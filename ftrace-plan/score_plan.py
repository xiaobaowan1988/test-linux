#!/usr/bin/env python3
"""
对 15 族 (~40%) 内核函数全量打分 + trace 方案规划
"""
import re, json
from collections import defaultdict

with open('/tmp/all_text_funcs.txt') as f:
    ALL = [l.strip() for l in f if l.strip()]

# ── 族分类规则 (first-match) ────────────────────────────────────────────────
FAM_RULES = [
    ('F01','网络',      r'^(tcp_|udp_|ip_|ipv6_|inet_|net_|sock_|skb_|netdev_|xdp_|pkt_|arp_|icmp_|l2tp_|nf_|xt_|bridge_|llc_|802|atm_|can_|dccp_|sctp_|tipc_|rxrpc_|caif_|phonet_|rose_|x25_|ax25_|nr_)'),
    ('F02','tracing',   r'^(__traceiter_|__probestub_|trace_|ring_buffer_|tracing_|ftrace_|perf_trace_|event_|bpf_perf_event_)'),
    ('F03','BPF',       r'^(bpf_|btf_|__bpf_|prog_array_|sock_map_|sock_hash_|devmap_|cpumap_|xskmap_|reuseport_)'),
    ('F04','文件系统',  r'^(vfs_|ext4_|proc_|dentry_|dcache_|inode_|file_|kernfs_|sysfs_|tmpfs_|ramfs_|btrfs_|nfs_|fat_|exfat_|jbd2_|mnt_|path_|fs_|fscache_|afs_|cifs_|gfs2_|hfs_|iso9660_|jfs_|minix_|nilfs_|ntfs_|ocfs2_|qnx4_|reiserfs_|udf_|ufs_|xfs_|zonefs_)'),
    ('F05','驱动/of_',  r'^(of_|platform_|pci_|usb_|i2c_|spi_|gpio_|pinctrl_|clk_|regulator_|dma_|iommu_|driver_|device_|bus_|acpi_|firmware_|module_|virtio_|nvme_|mmc_|scsi_|ata_|ahci_|ide_|md_|dm_)'),
    ('F06','内存管理',  r'^(__alloc_pages|alloc_pages|free_pages|alloc_page|page_|mm_|vmalloc|kvmalloc|__vmalloc|kmalloc|kzalloc|krealloc|kfree|slab_|slub_|folio_|__folio_|vm_|vma_|pgd_|pud_|pmd_|pte_|tlb_|swap_|oom_|compaction_|migrate_|mlock_|hugetlb_|thp_|zsmalloc_|zram_|memblock_)'),
    ('F07','RCU',       r'^(rcu_|call_rcu|synchronize_rcu|rcupdate_|srcutree_|srcu_|rcu_tasks_)'),
    ('F08','ARM64',     r'^(__arm64_|arm64_|el[0-9]_|do_el[0-9]|cpu_|cpufreq_|cpuidle_|perf_event_arm|hw_breakpoint_|kvm_arm_|hyp_|__hyp_)'),
    ('F09','IRQ/GIC',   r'^(gic_|irq_|handle_|irqchip_|__irq_|irqdomain_|irqdesc_|generic_handle_)'),
    ('F10','TTY',       r'^(tty_|pty_|uart_|serial_|pl011_|n_tty_|vt_|con_|hvc_)'),
    ('F11','cgroup',    r'^(cgroup_|css_|blkcg_|memcg_|cpuacct_|cgroupv2_|pids_cgroup_)'),
    ('F12','输入设备',  r'^(input_|evdev_|keyboard_|mouse_|touchscreen_|joystick_|gamepad_)'),
    ('F13','调度器',    r'^(task_|sched_|fair_|rt_sched_|dl_|cfs_|load_balance|wake_up_|pick_next_|update_curr|enqueue_task|dequeue_task|prio_changed|switched_to|set_next_task|select_task_rq|finish_task_switch|context_switch|__schedule|schedule_)'),
    ('F14','加密',      r'^(sha256_|sha224_|sha512_|sha384_|sha1_|sha3_|aes_|des_|hmac_|md5_|crypto_|chacha_|poly1305_|blake2|ghash_|cmac_|xcbc_|crng_|random_|get_random|prng_|drbg_|ecdh_|rsa_|curve25519_)'),
    ('F15','KUnit',     r'^(__?kunit_)'),
]

compiled = [(fid, fname, re.compile(pat)) for fid, fname, pat in FAM_RULES]

def classify(fn):
    for fid, fname, rx in compiled:
        if rx.match(fn):
            return fid, fname
    return None, None

# ── 子族提取（取 _ 分割后的前 1-2 个有意义部分）─────────────────────────────
def sub_family(fn):
    # 去掉前导 __
    s = fn.lstrip('_')
    parts = s.split('_')
    # 第一个有意义的词即为子族
    if not parts: return fn[:8]
    root = parts[0]
    # 对于 arm64_sys 这类双词子族保留两个
    if len(parts) >= 2 and len(root) <= 4 and parts[1]:
        return root + '_' + parts[1]
    return root

# ── 打分规则：(sub_family_prefix → (score, trigger_type, trigger_desc)) ─────
# score: 1=仅启动期/硬件专属  2=需复杂触发  3=需多步骤  4=需特定操作  5=trivial
SCORE_RULES = [
    # F01 网络
    (r'^tcp',           5, 'TCP_SOCKET',    'socket→connect→send'),
    (r'^udp',           5, 'UDP_SOCKET',    'socket→bind→sendto'),
    (r'^ip[_v]',        5, 'ANY_SOCKET',    '任意 socket 操作经过 IP 层'),
    (r'^inet',          5, 'ANY_SOCKET',    'inet_sendmsg / inet_recvmsg'),
    (r'^sock',          5, 'ANY_SOCKET',    'open/use any socket'),
    (r'^skb',           5, 'ANY_SOCKET',    '任意网络包分配/释放 skb'),
    (r'^net',           4, 'ANY_SOCKET',    'generic net ops'),
    (r'^netdev',        4, 'NET_DEVICE',    'any packet send/recv via netdev'),
    (r'^xdp',           2, 'XDP',           '需 attach XDP program 到接口'),
    (r'^nf_|^xt_',      4, 'IPTABLES',      '任意经过 iptables 的包'),
    (r'^arp',           3, 'ARP',           'ip neigh show / new ARP entry'),
    (r'^icmp',          3, 'ICMP',          'ping 127.0.0.1'),
    # F02 tracing
    (r'^__traceiter',   3, 'TRACEPOINT',    'echo 1 > events/X/enable; trigger event'),
    (r'^__probestub',   3, 'TRACEPOINT',    '同 __traceiter，轻量 stub'),
    (r'^trace_|^tracing', 3, 'FTRACE',     'ftrace function tracer 自身活动'),
    (r'^ring_buffer',   3, 'FTRACE',        'ftrace ring buffer 写入时'),
    (r'^ftrace',        3, 'FTRACE',        'write to set_ftrace_filter'),
    (r'^perf_trace',    3, 'PERF_EVENT',    'perf record + tracepoint'),
    # F03 BPF
    (r'^bpf_prog',      3, 'BPF_LOAD',      'syscall(BPF_PROG_LOAD, ...)'),
    (r'^bpf_map',       3, 'BPF_MAP',       'syscall(BPF_MAP_CREATE, ...)'),
    (r'^bpf_sk|^sock_map|^sock_hash', 3, 'BPF_SOCKET', 'BPF socket map ops'),
    (r'^btf',           3, 'BPF_BTF',       'syscall(BPF_BTF_LOAD, ...)'),
    (r'^bpf',           3, 'BPF_MISC',      'bpf() syscall'),
    # F04 文件系统
    (r'^vfs',           5, 'FILE_IO',       'open/read/write any file'),
    (r'^ext4',          4, 'EXT4_IO',       'read/write ext4 文件 (需挂载 ext4)'),
    (r'^proc',          5, 'PROC_READ',     'read /proc/... 任意文件'),
    (r'^dentry|^dcache', 4, 'FILE_OPEN',   'open() → dentry lookup'),
    (r'^inode',         4, 'FILE_OPEN',     'open() → inode ops'),
    (r'^file_|^filp',   5, 'FILE_IO',       'open/read/write file'),
    (r'^kernfs|^sysfs', 4, 'SYSFS_READ',    'read /sys/... 任意文件'),
    (r'^btrfs|^nfs|^fat|^xfs', 2, 'FS_SPECIFIC', '需挂载对应 FS 类型'),
    # F05 驱动
    (r'^of_',           1, 'BOOT_ONLY',     'DT 驱动探测期专属，运行期不可触发'),
    (r'^platform_',     2, 'DRIVER_PROBE',  '驱动 probe 时调用，热插拔可触发'),
    (r'^pci_',          2, 'PCI_HOTPLUG',   'PCI 设备热插拔 (QEMU 支持但需操作)'),
    (r'^usb_',          2, 'USB_EVENT',     'USB 插拔事件'),
    (r'^i2c_|^spi_',    2, 'BUS_XFER',     'I2C/SPI 总线传输'),
    (r'^gpio_|^pinctrl', 2, 'GPIO_OP',     'GPIO set/get (需硬件)'),
    (r'^clk_|^regulator', 2, 'PM_EVENT',   'clock/regulator 电源管理'),
    (r'^dma_',          3, 'DMA_OP',        'DMA 传输 (网络/存储 IO)'),
    (r'^virtio_',       3, 'VIRTIO',        'virtio 设备 IO (QEMU 有 virtio)'),
    (r'^nvme_',         2, 'BLOCK_IO',      'NVMe 块设备 IO'),
    (r'^driver_|^device_|^bus_', 2, 'DRIVER_CORE', '驱动核心 (probe/remove)'),
    # F06 内存管理
    (r'^__alloc_pages|^alloc_pages', 5, 'PAGE_FAULT', 'mmap anon + touch pages'),
    (r'^free_pages',    5, 'PAGE_FREE',     'munmap / process exit'),
    (r'^folio_|^__folio', 5, 'PAGE_FAULT',  'folio-based page alloc'),
    (r'^slab_|^slub_',  4, 'KMALLOC',       'any kmalloc → slab allocator'),
    (r'^kmalloc|^kzalloc|^krealloc|^kfree', 5, 'KMALLOC', 'any kernel alloc/free'),
    (r'^vmalloc|^kvmalloc', 4, 'VMALLOC',  'large vmalloc allocation'),
    (r'^vma_|^vm_area', 4, 'MMAP',          'mmap() or brk()'),
    (r'^tlb_',          5, 'TLB_FLUSH',     'munmap → TLB shootdown'),
    (r'^page_',         4, 'PAGE_OPS',      'page reference counting ops'),
    (r'^swap_',         2, 'SWAP',          '需内存压力触发 swap'),
    (r'^oom_',          1, 'OOM',           '需 OOM 条件 (内存耗尽)'),
    (r'^compaction_|^migrate_', 2, 'DEFRAG', '内存碎片整理 (压力触发)'),
    # F07 RCU
    (r'^call_rcu',      4, 'RCU_CALLBACK',  'close socket/inode free → call_rcu'),
    (r'^rcu_',          4, 'RCU_OPS',       'quiescent state / callback'),
    (r'^srcu_|^srcutree', 3, 'SRCU',        'SRCU read lock/unlock'),
    # F08 ARM64
    (r'^__arm64_sys',   5, 'SYSCALL',       'getpid() / write() / 任意 syscall'),
    (r'^arm64_|^el[0-9]_|^do_el', 4, 'EXCEPTION', '异常/中断入口 (IRQ/fault)'),
    (r'^cpu_',          3, 'CPU_OPS',       'CPU hotplug / cpufreq'),
    (r'^kvm_|^hyp_|^__hyp', 2, 'KVM',      'KVM 虚拟机操作 (需 KVM guest)'),
    # F09 IRQ/GIC
    (r'^gic_',          4, 'TIMER_IRQ',     'nanosleep → timer IRQ → GIC'),
    (r'^irq_',          4, 'ANY_IRQ',       '任意硬件中断'),
    (r'^handle_',       4, 'IRQ_HANDLE',    'IRQ handler dispatch'),
    (r'^irqdomain_|^irqdesc', 3, 'IRQ_SETUP', '中断描述符查找 (IRQ 路由)'),
    # F10 TTY
    (r'^tty_',          4, 'TTY_WRITE',     'write to /dev/ttyAMA0'),
    (r'^uart_|^pl011_|^serial_', 4, 'UART_IO', 'write to serial/UART device'),
    (r'^n_tty_',        4, 'TTY_LDISC',    'tty line discipline ops'),
    (r'^pty_',          3, 'PTY',           '需 PTY pair (openpty)'),
    # F11 cgroup
    (r'^cgroup_',       4, 'FORK',          'fork() → cgroup_fork/post_fork'),
    (r'^css_',          4, 'FORK',          'cgroup subsystem state ops'),
    (r'^memcg_',        4, 'PAGE_FAULT',    'page alloc → memcg charge'),
    (r'^blkcg_',        3, 'BLOCK_IO',      '需块设备 IO'),
    # F12 输入设备
    (r'^input_|^evdev_', 1, 'HW_INPUT',    'QEMU -nographic: 无键鼠硬件，0命中'),
    (r'^keyboard_|^mouse_', 1, 'HW_INPUT', '需物理输入设备'),
    # F13 调度器
    (r'^task_fork|^sched_cgroup_fork', 4, 'FORK', 'fork() → task_fork_fair'),
    (r'^task_',         4, 'FORK_SCHED',    'fork/exec/exit task lifecycle'),
    (r'^sched_',        4, 'SLEEP',         'nanosleep → scheduler'),
    (r'^fair_|^cfs_|^update_curr|^enqueue_task|^dequeue_task|^pick_next', 4, 'SLEEP', 'scheduler tick / sleep'),
    (r'^load_balance|^wake_up', 4, 'SLEEP', 'sleep/wake → load balancer'),
    # F14 加密
    (r'^crng_|^random_|^get_random', 4, 'URANDOM', 'read /dev/urandom'),
    (r'^sha256_ce|^sha256_block|^sha256_blocks', 3, 'CRYPTO_SHA256', 'AF_ALG sha256 (需 CONFIG_CRYPTO_USER_API_HASH)'),
    (r'^sha256_',       3, 'CRYPTO_SHA256', 'SHA-256 hash computation'),
    (r'^sha512_|^sha384_', 3, 'CRYPTO_SHA512', 'SHA-512 hash'),
    (r'^sha1_',         3, 'CRYPTO_SHA1',   'SHA-1 hash'),
    (r'^aes_',          3, 'CRYPTO_AES',    'AES encrypt/decrypt'),
    (r'^hmac_',         3, 'CRYPTO_HMAC',   'HMAC computation'),
    (r'^chacha_|^poly1305_', 4, 'URANDOM', 'ChaCha20/Poly1305 for CSPRNG'),
    (r'^blake2',        4, 'URANDOM',       'BLAKE2 for CSPRNG'),
    (r'^crypto_',       3, 'CRYPTO_API',    'kernel crypto API call'),
    # F15 KUnit
    (r'^kunit_|^__kunit', 1, 'BOOT_ONLY',  'late_initcall 启动期一次性，运行期 0 命中'),
]

score_compiled = [(re.compile('^' + r.lstrip('^')), sc, tt, td) for r, sc, tt, td in SCORE_RULES]

def get_score(fn):
    s = fn.lstrip('_')  # normalize
    for rx, sc, tt, td in score_compiled:
        if rx.match(s) or rx.match(fn):
            return sc, tt, td
    return 3, 'MISC', '未分类，需具体分析'

# ── 主处理 ──────────────────────────────────────────────────────────────────
records = []
for fn in sorted(ALL):
    fid, fname = classify(fn)
    if fid is None:
        continue
    sf = sub_family(fn)
    sc, tt, td = get_score(fn)
    records.append({
        'fn': fn,
        'fid': fid,
        'fname': fname,
        'sub': sf,
        'score': sc,
        'trigger_type': tt,
        'trigger_desc': td,
    })

print(f"Total classified: {len(records)}")

# Per-family stats
from collections import Counter
fam_counts = Counter(r['fid'] for r in records)
for fid in ['F01','F02','F03','F04','F05','F06','F07','F08','F09','F10','F11','F12','F13','F14','F15']:
    sub_counts = Counter(r['sub'] for r in records if r['fid'] == fid)
    score_counts = Counter(r['score'] for r in records if r['fid'] == fid)
    print(f"  {fid}: {fam_counts[fid]:5d}  top-subs: {dict(sub_counts.most_common(5))}  scores: {dict(sorted(score_counts.items()))}")

# Save JSON
with open('/tmp/func_plan.json', 'w') as f:
    json.dump(records, f)
print("Saved /tmp/func_plan.json")
