#!/usr/bin/env python3
"""
对 15 族 (~40%) 内核函数全量打分 + trace 方案规划
v2: 修复 (1) 分类≠分数 (F02/F03/F11 内部评分细化)
        (2) 覆盖率补丁 (br_/netif_/ip6_/sk_/ovl_/devm_/percpu_/preempt_/kunit_/...)
        (3) F07 __rcu_/__srcu_ regex 漏洞修复
        (4) F15 kunit_（无前置下划线）regex 修复
        (5) 去重（nm 输出含重复符号）
"""
import re, json
from collections import defaultdict

with open('/tmp/all_text_funcs.txt') as f:
    raw = [l.strip() for l in f if l.strip()]
# 去重，保序
seen = set()
ALL = []
for fn in raw:
    if fn not in seen:
        seen.add(fn)
        ALL.append(fn)

# ── 族分类规则 (first-match) ────────────────────────────────────────────────
# v2 修改:
#   F01: 补 br_/netif_/neigh_/ip6_/unix_/ethtool_/ethnl_/rtnl_/fib_/sk_
#   F04: 补 ovl_ (overlayfs)
#   F05: 补 devm_
#   F06: 补 percpu_/pcpu_
#   F07: 补 __rcu_/__srcu_ (双下划线漏洞)
#   F13: 补 preempt_
#   F15: 修正 regex 支持 kunit_（无前置下划线）
FAM_RULES = [
    ('F01','网络',
     r'^(tcp_|udp_|ip_|ip6_|ipv6_|inet_|net_|sock_|skb_|netdev_|netif_|'
     r'xdp_|pkt_|arp_|icmp_|l2tp_|nf_|xt_|bridge_|br_|llc_|802|atm_|'
     r'can_|dccp_|sctp_|tipc_|rxrpc_|caif_|phonet_|rose_|x25_|ax25_|nr_|'
     r'neigh_|unix_|ethtool_|ethnl_|rtnl_|fib_|sk_)'),
    ('F02','tracing',
     r'^(__traceiter_|__probestub_|trace_|ring_buffer_|tracing_|ftrace_|perf_trace_|event_|bpf_perf_event_)'),
    ('F03','BPF',
     r'^(bpf_|btf_|__bpf_|prog_array_|sock_map_|sock_hash_|devmap_|cpumap_|xskmap_|reuseport_)'),
    ('F04','文件系统',
     r'^(vfs_|ext4_|proc_|dentry_|dcache_|inode_|file_|kernfs_|sysfs_|tmpfs_|ramfs_|'
     r'btrfs_|nfs_|fat_|exfat_|jbd2_|mnt_|path_|fs_|fscache_|afs_|cifs_|gfs2_|hfs_|'
     r'iso9660_|jfs_|minix_|nilfs_|ntfs_|ocfs2_|qnx4_|reiserfs_|udf_|ufs_|xfs_|zonefs_|'
     r'ovl_)'),
    ('F05','驱动/of_',
     r'^(of_|platform_|pci_|usb_|i2c_|spi_|gpio_|pinctrl_|clk_|regulator_|dma_|iommu_|'
     r'driver_|device_|bus_|acpi_|firmware_|module_|virtio_|nvme_|mmc_|scsi_|ata_|ahci_|'
     r'ide_|md_|dm_|devm_)'),
    ('F06','内存管理',
     r'^(__alloc_pages|alloc_pages|free_pages|alloc_page|page_|mm_|vmalloc|kvmalloc|'
     r'__vmalloc|kmalloc|kzalloc|krealloc|kfree|slab_|slub_|folio_|__folio_|vm_|vma_|'
     r'pgd_|pud_|pmd_|pte_|tlb_|swap_|oom_|compaction_|migrate_|mlock_|hugetlb_|thp_|'
     r'zsmalloc_|zram_|memblock_|percpu_|pcpu_)'),
    ('F07','RCU',
     r'^(rcu_|__rcu_|call_rcu|synchronize_rcu|rcupdate_|srcutree_|srcu_|__srcu_|rcu_tasks_)'),
    ('F08','ARM64',
     r'^(__arm64_|arm64_|el[0-9]_|do_el[0-9]|cpu_|cpufreq_|cpuidle_|'
     r'perf_event_arm|hw_breakpoint_|kvm_arm_|hyp_|__hyp_)'),
    ('F09','IRQ/GIC',
     r'^(gic_|irq_|handle_|irqchip_|__irq_|irqdomain_|irqdesc_|generic_handle_)'),
    ('F10','TTY',
     r'^(tty_|pty_|uart_|serial_|pl011_|n_tty_|vt_|con_|hvc_)'),
    ('F11','cgroup',
     r'^(cgroup_|css_|blkcg_|memcg_|cpuacct_|cgroupv2_|pids_cgroup_)'),
    ('F12','输入设备',
     r'^(input_|evdev_|keyboard_|mouse_|touchscreen_|joystick_|gamepad_)'),
    ('F13','调度器',
     r'^(task_|sched_|fair_|rt_sched_|dl_|cfs_|load_balance|wake_up_|pick_next_|'
     r'update_curr|enqueue_task|dequeue_task|prio_changed|switched_to|set_next_task|'
     r'select_task_rq|finish_task_switch|context_switch|__schedule|schedule_|preempt_)'),
    ('F14','加密',
     r'^(sha256_|sha224_|sha512_|sha384_|sha1_|sha3_|aes_|des_|hmac_|md5_|crypto_|'
     r'chacha_|poly1305_|blake2|ghash_|cmac_|xcbc_|crng_|random_|get_random|prng_|'
     r'drbg_|ecdh_|rsa_|curve25519_)'),
    ('F15','KUnit',
     r'^(_*kunit_)'),   # 修正：匹配 kunit_xxx / _kunit_xxx / __kunit_xxx
]

compiled = [(fid, fname, re.compile(pat)) for fid, fname, pat in FAM_RULES]

def classify(fn):
    for fid, fname, rx in compiled:
        if rx.match(fn):
            return fid, fname
    return None, None

# ── 子族提取（取 _ 分割后的前 1-2 个有意义部分）─────────────────────────────
def sub_family(fn):
    s = fn.lstrip('_')
    parts = s.split('_')
    if not parts: return fn[:8]
    root = parts[0]
    if len(parts) >= 2 and len(root) <= 4 and parts[1]:
        return root + '_' + parts[1]
    return root

# ── 打分规则：(regex → (score, trigger_type, trigger_desc)) ─────────────────
# score: 1=仅启动/硬件  2=复杂触发  3=多步骤  4=特定操作  5=随时可触发
# v2 改动：
#   F02: trace_hardirq_*/trace_softirq_* → 5；ring_buffer_read*/event_* → 4
#   F03: bpf_prog_alloc*/bpf_map_alloc* → 4；btf_/bpf_check* → 3；xskmap_/sock_map_ → 2
#   F11: cgroup_fork/cgroup_exit → 5；memcg_ → 4；css_ → 3；blkcg_ → 2
SCORE_RULES = [
    # ── F01 网络 ──────────────────────────────────────────────────────────────
    (r'^tcp',           5, 'TCP_SOCKET',    'socket→connect→send'),
    (r'^udp',           5, 'UDP_SOCKET',    'socket→bind→sendto'),
    (r'^ip[_v6]',       5, 'ANY_SOCKET',    '任意 socket 操作经过 IP 层'),
    (r'^inet',          5, 'ANY_SOCKET',    'inet_sendmsg / inet_recvmsg'),
    (r'^sock',          5, 'ANY_SOCKET',    'open/use any socket'),
    (r'^skb',           5, 'ANY_SOCKET',    '任意网络包分配/释放 skb'),
    (r'^sk_',           5, 'ANY_SOCKET',    'sock 内部 sk_* 操作'),
    (r'^unix_',         4, 'UNIX_SOCKET',   'socket(AF_UNIX,SOCK_STREAM,0)→connect→send'),
    (r'^net',           4, 'ANY_SOCKET',    'generic net ops'),
    (r'^netdev',        4, 'NET_DEVICE',    'any packet send/recv via netdev'),
    (r'^netif_',        4, 'NET_DEVICE',    'netif_start_xmit / netif_rx'),
    (r'^xdp',           2, 'XDP',           '需 attach XDP program 到接口'),
    (r'^nf_|^xt_',      4, 'IPTABLES',      '任意经过 iptables 的包'),
    (r'^br_',           4, 'BRIDGE',        'socket + brctl → 经过 bridge 转发'),
    (r'^arp',           3, 'ARP',           'ip neigh show / 首次 connect 新 IP'),
    (r'^icmp',          3, 'ICMP',          'SOCK_RAW+IPPROTO_ICMP sendto 127.0.0.1'),
    (r'^neigh_',        3, 'ARP',           'ip neigh → neigh lookup/update'),
    (r'^ethtool_|^ethnl_', 3, 'ETHTOOL',   'ioctl(SIOCETHTOOL) / ethtool syscall'),
    (r'^rtnl_',         4, 'RTNETLINK',     'ip link/route → rtnetlink'),
    (r'^fib_',          4, 'ROUTING',       'ip route → FIB lookup'),
    # ── F02 tracing ──────────────────────────────────────────────────────────
    # score 5: 只要内核运行就持续命中（IRQ/preempt flag 追踪）
    (r'^trace_hardirq_|^trace_softirq_|^trace_preempt_',
                        5, 'IRQFLAG',       '任意 IRQ 使能/关闭路径自动触发'),
    # score 4: 启用对应 tracepoint 后轻松触发
    (r'^__traceiter_',  4, 'TRACEPOINT',    'echo 1>events/X/enable; 触发对应事件'),
    (r'^__probestub_',  4, 'TRACEPOINT',    '同 __traceiter，更轻量的 stub'),
    (r'^ring_buffer_read|^ring_buffer_consume|^ring_buffer_peek',
                        4, 'FTRACE_READ',   'cat trace / read(trace_pipe_fd,...)'),
    (r'^event_',        4, 'TRACEPOINT',    'echo 1 > events/.../enable'),
    # score 3: 需多步操作（设置 filter / perf_event_open）
    (r'^ring_buffer_',  3, 'FTRACE',        'ftrace ring buffer 管理'),
    (r'^tracing_',      3, 'FTRACE',        'write to tracing_on / set_ftrace_filter'),
    (r'^ftrace_',       3, 'FTRACE',        'write to set_ftrace_filter'),
    (r'^perf_trace_',   3, 'PERF_EVENT',    'syscall(__NR_perf_event_open, &attr, ...)'),
    (r'^trace_',        3, 'FTRACE',        'ftrace 内部路径'),
    # ── F03 BPF ──────────────────────────────────────────────────────────────
    # score 4: BPF_PROG_LOAD / BPF_MAP_CREATE 即触发
    (r'^bpf_prog_alloc|^bpf_prog_load|^bpf_prog_select|^bpf_prog_put',
                        4, 'BPF_LOAD',      'syscall(280,BPF_PROG_LOAD,&attr,sz)'),
    (r'^bpf_map_alloc|^bpf_map_create|^bpf_map_get|^bpf_map_put|^bpf_map_update|^bpf_map_delete',
                        4, 'BPF_MAP',       'syscall(280,BPF_MAP_CREATE,&attr,sz)'),
    # score 3: BPF 加载流程中调用，但多步骤
    (r'^btf_',          3, 'BPF_BTF',       'BPF_BTF_LOAD / BTF 类型解析'),
    (r'^bpf_check|^bpf_verif',
                        3, 'BPF_VERIF',     'BPF 校验器（prog load 过程中）'),
    (r'^bpf_ringbuf',   3, 'BPF_RINGBUF',   'BPF ring buffer ops（需已加载 prog）'),
    (r'^bpf_sk_',       2, 'BPF_SOCKET',    'BPF sk_skb / sk_msg（需复杂设置）'),
    # score 2: 需 XDP attach 或 socket map 配置
    (r'^sock_map_|^sock_hash_',
                        2, 'BPF_SOCKET',    'BPF socket map（需 BPF_MAP_TYPE_SOCKMAP）'),
    (r'^devmap_|^cpumap_|^xskmap_',
                        2, 'XDP',           'XDP redirect map（需 attach XDP prog）'),
    (r'^reuseport_',    3, 'BPF_REUSEPORT', 'SO_REUSEPORT + BPF prog'),
    (r'^bpf_',          3, 'BPF_MISC',      'bpf() syscall 通用路径'),
    # ── F04 文件系统 ──────────────────────────────────────────────────────────
    (r'^vfs',           5, 'FILE_IO',       'open/read/write any file'),
    (r'^ext4',          4, 'EXT4_IO',       'read/write ext4 文件（需挂载 ext4）'),
    (r'^proc',          5, 'PROC_READ',     'read /proc/... 任意文件'),
    (r'^dentry|^dcache', 4, 'FILE_OPEN',   'open() → dentry lookup'),
    (r'^inode',         4, 'FILE_OPEN',     'open() → inode ops'),
    (r'^file_|^filp',   5, 'FILE_IO',       'open/read/write file'),
    (r'^kernfs|^sysfs', 4, 'SYSFS_READ',    'read /sys/... 任意文件'),
    (r'^ovl_',          4, 'FILE_IO',       'read/write on overlayfs'),
    (r'^btrfs|^nfs|^fat|^xfs', 2, 'FS_SPECIFIC', '需挂载对应 FS 类型'),
    # ── F05 驱动 ──────────────────────────────────────────────────────────────
    (r'^of_',           1, 'BOOT_ONLY',     'DT 驱动探测期专属，运行期不可触发'),
    (r'^platform_',     2, 'DRIVER_PROBE',  '驱动 probe 时调用，热插拔可触发'),
    (r'^pci_',          2, 'PCI_HOTPLUG',   'PCI 设备热插拔（QEMU device_add）'),
    (r'^usb_',          2, 'USB_EVENT',     'USB 插拔事件'),
    (r'^i2c_|^spi_',    2, 'BUS_XFER',     'I2C/SPI 总线传输'),
    (r'^gpio_|^pinctrl', 2, 'GPIO_OP',     'GPIO set/get（需硬件）'),
    (r'^clk_|^regulator', 2, 'PM_EVENT',   'clock/regulator 电源管理'),
    (r'^dma_',          3, 'DMA_OP',        'DMA 传输（网络/存储 IO）'),
    (r'^devm_',         3, 'DRIVER_PROBE',  'devm 资源管理（驱动 probe/remove）'),
    (r'^virtio_',       3, 'VIRTIO',        'virtio 设备 IO（QEMU 有 virtio）'),
    (r'^nvme_',         2, 'BLOCK_IO',      'NVMe 块设备 IO'),
    (r'^driver_|^device_|^bus_', 2, 'DRIVER_CORE', '驱动核心（probe/remove）'),
    # ── F06 内存管理 ──────────────────────────────────────────────────────────
    (r'^__alloc_pages|^alloc_pages', 5, 'PAGE_FAULT', 'mmap anon + touch pages'),
    (r'^free_pages',    5, 'PAGE_FREE',     'munmap / 进程退出'),
    (r'^folio_|^__folio', 5, 'PAGE_FAULT', 'folio-based page alloc'),
    (r'^slab_|^slub_',  4, 'KMALLOC',       'any kmalloc → slab allocator'),
    (r'^kmalloc|^kzalloc|^krealloc|^kfree', 5, 'KMALLOC', 'any kernel alloc/free'),
    (r'^vmalloc|^kvmalloc', 4, 'VMALLOC',  '大块 vmalloc 分配'),
    (r'^vma_|^vm_area', 4, 'MMAP',          'mmap() 或 brk()'),
    (r'^tlb_',          5, 'TLB_FLUSH',     'munmap 多页 → TLB shootdown'),
    (r'^page_',         4, 'PAGE_OPS',      'page 引用计数 ops'),
    (r'^percpu_|^pcpu_', 4, 'KMALLOC',     'alloc_percpu → per-CPU 分配'),
    (r'^swap_',         2, 'SWAP',          '需内存压力触发 swap'),
    (r'^oom_',          1, 'OOM',           '需 OOM 条件（内存耗尽）'),
    (r'^compaction_|^migrate_', 2, 'DEFRAG', '内存碎片整理（压力触发）'),
    # ── F07 RCU ──────────────────────────────────────────────────────────────
    (r'^call_rcu',      4, 'RCU_CALLBACK',  '12x open/close socket → call_rcu'),
    (r'^__rcu_',        5, 'RCU_READ',      '__rcu_read_lock/unlock：任意 rcu 读临界区'),
    (r'^rcu_',          4, 'RCU_OPS',       'quiescent state / callback'),
    (r'^__srcu_|^srcu_|^srcutree', 3, 'SRCU', 'SRCU read lock/unlock'),
    # ── F08 ARM64 ──────────────────────────────────────────────────────────────
    (r'^__arm64_sys',   5, 'SYSCALL',       'getpid() / write() / 任意 syscall'),
    (r'^arm64_|^el[0-9]_|^do_el', 4, 'EXCEPTION', '异常/中断入口（IRQ/fault）'),
    (r'^cpu_',          3, 'CPU_OPS',       'CPU hotplug / cpufreq'),
    (r'^kvm_|^hyp_|^__hyp', 2, 'KVM',      '需在 KVM host 运行 guest VM'),
    # ── F09 IRQ/GIC ──────────────────────────────────────────────────────────
    (r'^gic_handle|^gic_irq', 5, 'TIMER_IRQ', 'nanosleep(10ms) → timer IRQ → GIC'),
    (r'^gic_',          4, 'TIMER_IRQ',     'GIC 内部路径，timer/外设 IRQ 触发'),
    (r'^irq_',          4, 'ANY_IRQ',       '任意硬件中断'),
    (r'^handle_',       4, 'IRQ_HANDLE',    'IRQ handler dispatch'),
    (r'^irqdomain_|^irqdesc', 3, 'IRQ_SETUP', '中断描述符查找（IRQ 路由）'),
    (r'^generic_handle_', 4, 'ANY_IRQ',     '通用 IRQ 处理入口'),
    # ── F10 TTY ──────────────────────────────────────────────────────────────
    (r'^tty_',          4, 'TTY_WRITE',     'open("/dev/ttyAMA0",O_WRONLY); write'),
    (r'^uart_|^pl011_|^serial_', 4, 'UART_IO', 'write to /dev/ttyAMA0'),
    (r'^n_tty_',        4, 'TTY_LDISC',    'tty 读写经 n_tty'),
    (r'^pty_',          3, 'PTY',           '需 PTY pair（openpty）'),
    # ── F11 cgroup ──────────────────────────────────────────────────────────
    # score 5: fork/exit 自动触发
    (r'^cgroup_fork|^cgroup_post_fork|^cgroup_exit|^cgroup_release',
                        5, 'FORK',          'fork()→cgroup_fork; exit→cgroup_exit'),
    # score 4: 一般 cgroup 操作，fork/exit 均触发
    (r'^cgroup_',       4, 'FORK',          'fork() / exit → cgroup 路径'),
    (r'^cpuacct_',      4, 'FORK',          'fork/exit → cpuacct accounting'),
    (r'^memcg_',        4, 'PAGE_FAULT',    'page alloc → memcg charge'),
    # score 3: 需读写 cgroup 文件系统
    (r'^css_',          3, 'CGROUP_FS',     'read/write /sys/fs/cgroup/...'),
    # score 2: 需块设备 IO
    (r'^blkcg_',        2, 'BLOCK_IO',      '需块设备 IO'),
    # ── F12 输入设备 ──────────────────────────────────────────────────────────
    (r'^input_|^evdev_', 1, 'HW_INPUT',    'QEMU -nographic: 无键鼠硬件，0命中'),
    (r'^keyboard_|^mouse_', 1, 'HW_INPUT', '需物理输入设备'),
    # ── F13 调度器 ──────────────────────────────────────────────────────────
    (r'^task_fork|^sched_cgroup_fork', 4, 'FORK', 'fork() → task_fork_fair'),
    (r'^task_',         4, 'FORK_SCHED',    'fork/exec/exit task lifecycle'),
    (r'^sched_',        4, 'SLEEP',         'nanosleep → scheduler'),
    (r'^preempt_',      5, 'PREEMPT',       '调度器抢占路径，任意 syscall return 触发'),
    (r'^fair_|^cfs_|^update_curr|^enqueue_task|^dequeue_task|^pick_next',
                        4, 'SLEEP',         'scheduler tick / sleep'),
    (r'^load_balance|^wake_up', 4, 'SLEEP', 'sleep/wake → load balancer'),
    # ── F14 加密 ──────────────────────────────────────────────────────────────
    (r'^crng_|^random_|^get_random', 4, 'URANDOM', 'read /dev/urandom x4'),
    (r'^sha256_ce|^sha256_block', 3, 'CRYPTO_SHA256',
     'AF_ALG sha256（需 CONFIG_CRYPTO_USER_API_HASH）'),
    (r'^sha256_',       3, 'CRYPTO_SHA256', 'SHA-256 hash'),
    (r'^sha512_|^sha384_', 3, 'CRYPTO_SHA512', 'SHA-512 hash'),
    (r'^sha1_',         3, 'CRYPTO_SHA1',   'SHA-1 hash'),
    (r'^aes_',          3, 'CRYPTO_AES',    'AES encrypt/decrypt'),
    (r'^hmac_',         3, 'CRYPTO_HMAC',   'HMAC computation'),
    (r'^chacha_|^poly1305_', 4, 'URANDOM', 'ChaCha20/Poly1305 for CSPRNG'),
    (r'^blake2',        4, 'URANDOM',       'BLAKE2 for CSPRNG'),
    (r'^crypto_',       3, 'CRYPTO_API',    'kernel crypto API call'),
    # ── F15 KUnit ──────────────────────────────────────────────────────────
    (r'^_*kunit_|^__kunit', 1, 'BOOT_ONLY', 'late_initcall 启动期一次性，运行期 0 命中'),
]

score_compiled = [(re.compile('^' + r.lstrip('^')), sc, tt, td) for r, sc, tt, td in SCORE_RULES]

def get_score(fn):
    s = fn.lstrip('_')
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

print(f"Total classified: {len(records)} / {len(ALL)} unique = {len(records)/len(ALL)*100:.1f}%")

from collections import Counter
fam_counts = Counter(r['fid'] for r in records)
for fid in ['F01','F02','F03','F04','F05','F06','F07','F08','F09','F10','F11','F12','F13','F14','F15']:
    sub_counts = Counter(r['sub'] for r in records if r['fid'] == fid)
    score_counts = Counter(r['score'] for r in records if r['fid'] == fid)
    print(f"  {fid}: {fam_counts[fid]:5d}  scores={dict(sorted(score_counts.items()))}  top-subs: {dict(sub_counts.most_common(3))}")

with open('/tmp/func_plan.json', 'w') as f:
    json.dump(records, f)
print("Saved /tmp/func_plan.json")
