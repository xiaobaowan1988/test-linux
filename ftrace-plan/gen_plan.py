#!/usr/bin/env python3
import json
from collections import Counter, defaultdict
import html as _html

with open('/tmp/func_plan.json') as f:
    records = json.load(f)

TRIGGER_PLANS = {
    'TCP_SOCKET':   ('TCP loopback send',        'socket(AF_INET,SOCK_STREAM,0) → connect → send'),
    'UDP_SOCKET':   ('UDP loopback sendto',       'socket(AF_INET,SOCK_DGRAM,0) → bind → sendto'),
    'ANY_SOCKET':   ('任意 socket 操作',          'socket(AF_INET,SOCK_STREAM,0) → connect/send'),
    'NET_DEVICE':   ('网络包收发',                '任意 send/recv 经过 netdev 层'),
    'XDP':          ('XDP program attach',        '需 attach XDP prog + 发包'),
    'IPTABLES':     ('iptables 规则匹配',          '任意经 OUTPUT/INPUT 链的包'),
    'ARP':          ('ARP 解析',                  '首次 connect 新 IP 触发 ARP'),
    'ICMP':         ('ICMP ping',                 'SOCK_RAW + IPPROTO_ICMP sendto'),
    'TRACEPOINT':   ('启用 tracepoint',           'echo 1 > events/X/enable; 触发对应事件'),
    'FTRACE':       ('ftrace 控制路径',            'write to set_ftrace_filter / tracing_on'),
    'PERF_EVENT':   ('perf_event_open',           'syscall(__NR_perf_event_open, &attr, ...)'),
    'BPF_LOAD':     ('BPF_PROG_LOAD',             'syscall(280, 5, &attr, sizeof(attr))'),
    'BPF_MAP':      ('BPF_MAP_CREATE',            'syscall(280, 0, &attr, sizeof(attr))'),
    'BPF_SOCKET':   ('BPF socket map',            'BPF_MAP_CREATE with BPF_MAP_TYPE_SOCKMAP'),
    'BPF_BTF':      ('BPF_BTF_LOAD',              'syscall(280, 18, &attr, sizeof(attr))'),
    'BPF_MISC':     ('bpf() syscall',             '任意 bpf() 系统调用'),
    'FILE_IO':      ('read/write file',           'open("/proc/version",O_RDONLY); read(fd,buf,n)'),
    'EXT4_IO':      ('ext4 文件 IO',              '需挂载 ext4; read/write ext4 文件'),
    'PROC_READ':    ('read /proc/*',              'open("/proc/version",O_RDONLY); read(fd,buf,n)'),
    'FILE_OPEN':    ('open() syscall',            'open("/proc/version",O_RDONLY)'),
    'SYSFS_READ':   ('read /sys/*',               'open("/sys/firmware/devicetree/...",O_RDONLY)'),
    'FS_SPECIFIC':  ('特定 FS 类型',               '需挂载对应 FS (btrfs/nfs/fat 等)'),
    'BOOT_ONLY':    ('仅启动期 ⚠',               '运行时 ftrace 命中 0 — 仅 kernel boot 期调用'),
    'HW_INPUT':     ('硬件输入事件 ⚠',            'QEMU -nographic 命中 0; 需物理键鼠设备'),
    'DRIVER_PROBE': ('驱动 probe',                '驱动模块加载 / 设备热插拔'),
    'PCI_HOTPLUG':  ('PCI 热插拔',                'QEMU: device_add e1000'),
    'USB_EVENT':    ('USB 插拔',                  'USB 设备连接/断开'),
    'BUS_XFER':     ('I2C/SPI 传输',              '需 I2C/SPI 硬件'),
    'GPIO_OP':      ('GPIO 操作',                 '需 GPIO 控制器'),
    'PM_EVENT':     ('电源管理',                   'cpufreq change / clock gate'),
    'DMA_OP':       ('DMA 传输',                  '网络/块 IO 触发 DMA'),
    'VIRTIO':       ('virtio 设备 IO',            'QEMU virtio-net/blk IO'),
    'BLOCK_IO':     ('块设备 IO',                 '需挂载块设备; read/write'),
    'DRIVER_CORE':  ('驱动核心',                  '设备 probe/remove/bind'),
    'PAGE_FAULT':   ('缺页中断',                   'mmap(NULL,65536,MAP_ANON,-1,0); *ptr=1'),
    'PAGE_FREE':    ('页面释放',                   'munmap(p,len) / 进程退出'),
    'KMALLOC':      ('kmalloc/kfree',             '任意内核 kmalloc/kfree'),
    'VMALLOC':      ('vmalloc',                    '大块 vmalloc_to_page'),
    'MMAP':         ('mmap/brk',                  'mmap() 或 malloc() → brk()'),
    'TLB_FLUSH':    ('TLB shootdown',             'munmap 多页'),
    'PAGE_OPS':     ('页面引用计数',               'page fault → get_page/put_page'),
    'SWAP':         ('swap IO',                   '需内存压力触发 swap'),
    'OOM':          ('OOM killer ⚠',             '需耗尽内存，危险'),
    'DEFRAG':       ('内存碎片整理',               '持续分配/释放触发 compaction'),
    'RCU_CALLBACK': ('RCU callback',              '12x open/close socket → call_rcu'),
    'RCU_OPS':      ('RCU 静止状态',              'nanosleep → quiescent state'),
    'SRCU':         ('SRCU read lock',             '持有 SRCU read lock'),
    'SYSCALL':      ('任意 syscall',              'getpid() x5 → __arm64_sys_getpid'),
    'EXCEPTION':    ('CPU 异常/中断',              'page fault / IRQ / SVC 入口'),
    'CPU_OPS':      ('CPU 操作',                  'cpufreq change / CPU hotplug'),
    'KVM':          ('KVM ⚠',                    '需在 KVM host 运行 guest VM'),
    'TIMER_IRQ':    ('定时器 IRQ',                'nanosleep(10ms) → GIC timer IRQ'),
    'ANY_IRQ':      ('任意硬件中断',               'nanosleep → timer; net recv → NIC IRQ'),
    'IRQ_HANDLE':   ('IRQ handler dispatch',      '任意 IRQ 到来'),
    'IRQ_SETUP':    ('中断描述符',                  'IRQ 注册/路由 (驱动 probe 期)'),
    'TTY_WRITE':    ('写 TTY',                    'open("/dev/ttyAMA0",O_WRONLY); write(fd,"\\n",1)'),
    'UART_IO':      ('UART IO',                   'write to /dev/ttyAMA0'),
    'TTY_LDISC':    ('TTY 线路规程',               'tty 读写经 n_tty'),
    'PTY':          ('PTY 伪终端',                 'openpty() 创建 PTY pair'),
    'FORK':         ('fork()',                     'pid_t p=fork(); if(p==0)_exit(0); waitpid'),
    'FORK_SCHED':   ('fork + CFS',                'fork() → task_fork_fair → enqueue'),
    'SLEEP':        ('nanosleep',                  'nanosleep(&ts,NULL) 1ms+'),
    'URANDOM':      ('read /dev/urandom',          'open("/dev/urandom",O_RDONLY); read x4'),
    'CRYPTO_SHA256':('SHA-256 AF_ALG',             'socket(AF_ALG)+bind("sha256")+accept+send'),
    'CRYPTO_SHA512':('SHA-512 AF_ALG',             'socket(AF_ALG)+bind("sha512")+accept+send'),
    'CRYPTO_SHA1':  ('SHA-1 AF_ALG',               'socket(AF_ALG)+bind("sha1")+accept+send'),
    'CRYPTO_AES':   ('AES AF_ALG',                 'socket(AF_ALG)+bind("cbc(aes)")+accept+send'),
    'CRYPTO_HMAC':  ('HMAC AF_ALG',                'socket(AF_ALG)+bind("hmac(sha256)")+accept'),
    'CRYPTO_API':   ('kernel crypto API',          'AF_ALG socket 或内核内部 hash'),
    'MISC':         ('待人工分析',                 '需具体分析触发条件'),
}

FAM_META = {
    'F01':('网络',     '#2563eb'),
    'F02':('tracing',  '#7c3aed'),
    'F03':('BPF',      '#0891b2'),
    'F04':('文件系统', '#059669'),
    'F05':('驱动/of_', '#dc2626'),
    'F06':('内存管理', '#d97706'),
    'F07':('RCU',      '#65a30d'),
    'F08':('ARM64',    '#0284c7'),
    'F09':('IRQ/GIC',  '#c2410c'),
    'F10':('TTY',      '#6d28d9'),
    'F11':('cgroup',   '#15803d'),
    'F12':('输入设备', '#b45309'),
    'F13':('调度器',   '#1d4ed8'),
    'F14':('加密',     '#6b21a8'),
    'F15':('KUnit',    '#475569'),
}

by_fam_sub = defaultdict(lambda: defaultdict(list))
for r in records:
    by_fam_sub[r['fid']][r['sub']].append(r)

sc_counts = Counter(r['score'] for r in records)
tt_set = sorted(set(r['trigger_type'] for r in records))
fids = ['F01','F02','F03','F04','F05','F06','F07','F08','F09','F10','F11','F12','F13','F14','F15']

def signal_html(score):
    colors = {5:'#10b981',4:'#34d399',3:'#f59e0b',2:'#f97316',1:'#f43f5e'}
    heights = [4,6,9,12,16]
    bars = ''
    for i, h in enumerate(heights, 1):
        fill = colors[score] if i <= score else '#1e2a38'
        bars += '<span style="display:inline-block;width:3px;height:%dpx;background:%s;border-radius:1px;vertical-align:bottom;margin-right:2px"></span>' % (h, fill)
    return bars

def fam_score_bar(fid):
    recs = [r for r in records if r['fid']==fid]
    n = len(recs)
    if not n: return ''
    sc = Counter(r['score'] for r in recs)
    colors = {5:'#10b981',4:'#34d399',3:'#f59e0b',2:'#f97316',1:'#f43f5e'}
    segs = ''.join('<div style="flex:%d;background:%s"></div>' % (sc.get(i,0), colors[i]) for i in range(1,6))
    return '<div style="display:flex;height:3px;border-radius:2px;overflow:hidden;margin:8px 0;gap:1px">%s</div>' % segs

def sub_rows(fid):
    subs = sorted(by_fam_sub[fid].items(), key=lambda x: -len(x[1]))[:6]
    rows = ''
    colors = {5:'#10b981',4:'#34d399',3:'#f59e0b',2:'#f97316',1:'#f43f5e'}
    for sub, recs in subs:
        avg = sum(r['score'] for r in recs)/len(recs)
        tt = Counter(r['trigger_type'] for r in recs).most_common(1)[0][0]
        col = colors.get(round(avg), '#64748b')
        plan = TRIGGER_PLANS.get(tt, ('?',))[0]
        rows += '<tr><td class="mono" style="color:#93c5fd">%s_*</td><td class="num muted" style="text-align:right">%d</td><td class="num"><span style="color:%s;font-weight:600">%.1f</span></td><td class="mono" style="color:#7dd3fc;font-size:10px">%s</td><td class="muted" style="font-size:11px">%s</td></tr>' % (sub, len(recs), col, avg, tt, _html.escape(plan))
    return rows

def cards_html():
    out = ''
    for fid in fids:
        fname, fcolor = FAM_META[fid]
        recs_f = [r for r in records if r['fid']==fid]
        n = len(recs_f)
        sc = Counter(r['score'] for r in recs_f)
        out += '''<div class="fcard" style="border-left:3px solid %(fc)s">
<div class="fcard-head">
  <span class="mono" style="color:%(fc)s;font-size:10px;font-weight:700">%(fid)s</span>
  <span class="fcard-name">%(fname)s</span>
  <span class="num muted" style="margin-left:auto;font-size:11px">%(n)s</span>
</div>
%(bar)s
<div class="score-legend">
  <span style="color:#10b981">■5:%(s5)d</span>
  <span style="color:#34d399">■4:%(s4)d</span>
  <span style="color:#f59e0b">■3:%(s3)d</span>
  <span style="color:#f97316">■2:%(s2)d</span>
  <span style="color:#f43f5e">■1:%(s1)d</span>
</div>
<table class="sub-tbl">
  <tr><th>子族</th><th>数量</th><th>均分</th><th>触发类型</th><th>方案</th></tr>
  %(rows)s
</table>
</div>''' % dict(fc=fcolor, fid=fid, fname=fname, n='%s' % f'{n:,}',
                  bar=fam_score_bar(fid),
                  s5=sc.get(5,0), s4=sc.get(4,0), s3=sc.get(3,0),
                  s2=sc.get(2,0), s1=sc.get(1,0),
                  rows=sub_rows(fid))
    return out

def tt_grid_html():
    out = ''
    for t in sorted(TRIGGER_PLANS.keys()):
        plan, code = TRIGGER_PLANS[t]
        out += '<div class="tt-card"><div class="tt-name">%s</div><div class="tt-plan">%s</div><div class="tt-code">%s</div></div>' % (t, _html.escape(plan), _html.escape(code))
    return out

def fam_options():
    return ''.join('<option value="%s">%s %s</option>' % (fid, fid, FAM_META[fid][0]) for fid in fids)

def tt_options():
    return ''.join('<option value="%s">%s</option>' % (t, t) for t in tt_set)

def score_key_html():
    labels = {5:'轻松触发',4:'特定操作',3:'多步骤',2:'复杂触发',1:'启动/硬件'}
    parts = ''
    for s in [5,4,3,2,1]:
        parts += '<span class="sk-item">%s<span>%d · %s</span></span>' % (signal_html(s), s, labels[s])
    return parts

js_data = [[r['fn'],r['fid'],r['sub'],r['score'],r['trigger_type']] for r in records]
jd = json.dumps(js_data, ensure_ascii=False, separators=(',',':'))
tp_js = json.dumps({k:v[0] for k,v in TRIGGER_PLANS.items()}, ensure_ascii=False)
tf_js = json.dumps({k:v[1] for k,v in TRIGGER_PLANS.items()}, ensure_ascii=False)
fm_js = json.dumps({k:v[0] for k,v in FAM_META.items()}, ensure_ascii=False)
fc_js = json.dumps({k:v[1] for k,v in FAM_META.items()}, ensure_ascii=False)
easy = sc_counts.get(5,0)+sc_counts.get(4,0)

CSS = """<style>
:root{
  --bg:#070b11;--s0:#0d1520;--s1:#111c2b;--s2:#172133;
  --border:#1a2840;--text:#c9d8ec;--muted:#4d6480;--accent:#3b82f6;
  --mono:ui-monospace,'Cascadia Code','JetBrains Mono',Menlo,monospace;
  --sans:system-ui,-apple-system,'Segoe UI',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13px;line-height:1.5}
.mono{font-family:var(--mono)}
.num{font-variant-numeric:tabular-nums}
.muted{color:var(--muted)}
header{padding:24px 28px 20px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:24px;flex-wrap:wrap}
.hdr-left{flex:1;min-width:260px}
.hdr-eyebrow{font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);margin-bottom:6px}
.hdr-title{font-size:1.35rem;font-weight:600;color:#e8f0fc;line-height:1.2}
.hdr-sub{margin-top:6px;color:var(--muted);font-size:12px;max-width:520px}
.hdr-stats{display:flex;gap:1px;flex-wrap:wrap}
.hstat{background:var(--s1);border:1px solid var(--border);padding:10px 18px;min-width:110px}
.hstat:first-child{border-radius:6px 0 0 6px}
.hstat:last-child{border-radius:0 6px 6px 0}
.hstat-n{font-family:var(--mono);font-size:1.5rem;font-weight:700;font-variant-numeric:tabular-nums}
.hstat-l{font-size:10px;color:var(--muted);margin-top:1px;text-transform:uppercase;letter-spacing:.06em}
.score-key{display:flex;align-items:center;gap:16px;padding:10px 28px;background:var(--s0);border-bottom:1px solid var(--border);flex-wrap:wrap}
.score-key-lbl{font-size:11px;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;flex-shrink:0}
.sk-item{display:inline-flex;align-items:center;gap:6px;font-size:11px}
.section-head{padding:16px 28px 10px;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}
.section-head::before{content:'';display:block;width:3px;height:14px;background:var(--accent);border-radius:2px}
.fam-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:10px;padding:16px 28px}
.fcard{background:var(--s1);border:1px solid var(--border);border-radius:2px;padding:12px 14px}
.fcard-head{display:flex;align-items:center;gap:8px;margin-bottom:0}
.fcard-name{font-weight:600;color:#d0e4f8;font-size:13px}
.score-legend{display:flex;gap:10px;font-size:10px;font-family:var(--mono);margin-bottom:8px}
.sub-tbl{width:100%;border-collapse:collapse;font-size:11px}
.sub-tbl th{color:var(--muted);font-weight:400;padding:2px 5px;text-align:left;border-bottom:1px solid var(--border)}
.sub-tbl td{padding:3px 5px;border-bottom:1px solid #0d1520}
.sub-tbl tr:last-child td{border-bottom:none}
.sub-tbl tr:hover td{background:var(--s2)}
.tt-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px;padding:12px 28px}
.tt-card{background:var(--s1);border:1px solid var(--border);border-radius:2px;padding:10px 12px}
.tt-name{font-family:var(--mono);font-size:11px;color:#7dd3fc;font-weight:600;margin-bottom:3px}
.tt-plan{font-size:11px;font-weight:500;color:#c9d8ec;margin-bottom:3px}
.tt-code{font-family:var(--mono);font-size:10px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.filter-bar{position:sticky;top:0;z-index:20;background:var(--s0);border-bottom:1px solid var(--border);padding:8px 28px;display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.filter-bar input{background:var(--s1);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:3px;font-family:var(--mono);font-size:12px;width:200px;outline:none}
.filter-bar input:focus{border-color:var(--accent)}
.filter-bar select{background:var(--s1);border:1px solid var(--border);color:var(--text);padding:5px 8px;border-radius:3px;font-size:12px;outline:none;cursor:pointer}
.filter-bar select:focus{border-color:var(--accent)}
.filter-label{font-size:11px;color:var(--muted);flex-shrink:0}
#count-display{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)}
.tbl-outer{overflow-x:auto;padding:0 0 24px}
#ftbl{width:100%;border-collapse:collapse;font-size:12px}
#ftbl thead tr{background:var(--s0)}
#ftbl th{padding:6px 10px;color:var(--muted);font-weight:500;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none;font-size:11px;letter-spacing:.04em}
#ftbl th:hover{color:var(--text)}
#ftbl th.sort-asc::after{content:" ↑"}
#ftbl th.sort-desc::after{content:" ↓"}
#ftbl td{padding:5px 10px;border-bottom:1px solid #0d1520;vertical-align:middle}
#ftbl tr:hover td{background:var(--s1)}
.fn-name{font-family:var(--mono);font-size:11px;color:#93c5fd}
.fam-badge{display:inline-block;font-family:var(--mono);font-size:10px;padding:1px 5px;border-radius:2px;font-weight:700;color:#fff}
.plan-txt{font-size:11px;color:var(--muted);max-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cmd-txt{font-family:var(--mono);font-size:10px;color:#4d6480;max-width:240px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.more-row td{text-align:center;padding:10px;color:var(--muted);font-size:11px;background:var(--s0)}
</style>"""

JS = """<script>
const D=__DATA__;
const TP=__TP__;
const TF=__TF__;
const FM=__FM__;
const FC=__FC__;
const SC={1:'#f43f5e',2:'#f97316',3:'#f59e0b',4:'#34d399',5:'#10b981'};
function SIG(s){
  const c=SC[s]||'#64748b';
  const hs=[4,6,9,12,16];
  return hs.map((h,i)=>'<span style="display:inline-block;width:3px;height:'+h+'px;background:'+(i+1<=s?c:'#1e2a38')+';border-radius:1px;vertical-align:bottom;margin-right:2px"></span>').join('');
}
let sortCol=3,sortDir=-1;
function hdr(n){return document.getElementById('h'+n);}
function clearSort(){[0,1,2,3,4].forEach(function(i){const h=hdr(i);if(h)h.className='';});}
function render(){
  const q=document.getElementById('q').value.toLowerCase();
  const ff=document.getElementById('ff').value;
  const sf=parseInt(document.getElementById('sf').value)||0;
  const tf=document.getElementById('tf').value;
  const rows=D.filter(function(d){
    if(ff&&d[1]!==ff)return false;
    if(d[3]<sf)return false;
    if(tf&&d[4]!==tf)return false;
    if(q&&d[0].indexOf(q)<0&&d[2].indexOf(q)<0&&d[4].toLowerCase().indexOf(q)<0)return false;
    return true;
  });
  rows.sort(function(a,b){
    const va=a[sortCol],vb=b[sortCol];
    if(typeof va==='string')return sortDir*va.localeCompare(vb);
    return sortDir*(va-vb);
  });
  document.getElementById('count-display').textContent=rows.length.toLocaleString()+' / '+D.length.toLocaleString();
  const LIMIT=400;
  const tb=document.getElementById('tb');
  const shown=rows.slice(0,LIMIT);
  tb.innerHTML=shown.map(function(d){
    const plan=TP[d[4]]||'?';
    const cmd='echo "'+d[0]+'" > set_ftrace_filter  # '+(TF[d[4]]||'');
    return '<tr>'
      +'<td class="fn-name">'+d[0]+'</td>'
      +'<td><span class="fam-badge" style="background:'+(FC[d[1]]||'#333')+'">'+d[1]+'</span>&nbsp;<span class="muted" style="font-size:11px">'+(FM[d[1]]||'')+'</span></td>'
      +'<td class="mono" style="color:#60a5fa;font-size:11px">'+d[2]+'_*</td>'
      +'<td class="num">'+SIG(d[3])+'</td>'
      +'<td class="mono" style="color:#7dd3fc;font-size:11px">'+d[4]+'</td>'
      +'<td class="plan-txt" title="'+plan+'">'+plan+'</td>'
      +'<td class="cmd-txt" title="'+cmd+'">'+cmd+'</td>'
      +'</tr>';
  }).join('')+(rows.length>LIMIT?'<tr class="more-row"><td colspan="7">另有 '+(rows.length-LIMIT)+' 行 — 缩小过滤范围</td></tr>':'');
}
[0,1,2,3,4].forEach(function(i){
  const h=hdr(i); if(!h)return;
  h.addEventListener('click',function(){
    if(sortCol===i)sortDir*=-1;else{sortCol=i;sortDir=1;}
    clearSort();
    h.className=sortDir===1?'sort-asc':'sort-desc';
    render();
  });
});
['q','ff','sf','tf'].forEach(function(id){
  document.getElementById(id).addEventListener('input',render);
});
clearSort();hdr(3).className='sort-desc';
render();
</script>"""

JS = JS.replace('__DATA__', jd).replace('__TP__', tp_js).replace('__TF__', tf_js).replace('__FM__', fm_js).replace('__FC__', fc_js)

HEADER = """<title>Linux .text 函数 · 15族全量 Trace 方案</title>
<meta name="description" content="Linux arm64 7.1-rc7 内核 ~40% 命名子系统函数全量分类评分与 ftrace 触发方案">"""

BODY = """
<header>
  <div class="hdr-left">
    <div class="hdr-eyebrow">Linux arm64 7.1-rc7 · .text 内核函数分析</div>
    <h1 class="hdr-title">15族全量 Trace 方案</h1>
    <p class="hdr-sub">~40%% 命名子系统函数完整分类 · 运行时可触发性评分（1–5）· 每函数 ftrace 触发方案</p>
  </div>
  <div class="hdr-stats">
    <div class="hstat"><div class="hstat-n" style="color:#3b82f6">10,810</div><div class="hstat-l">函数总量</div></div>
    <div class="hstat"><div class="hstat-n" style="color:#10b981">%(easy)s</div><div class="hstat-l">分值 4-5（易触发）</div></div>
    <div class="hstat"><div class="hstat-n" style="color:#f59e0b">%(mid)s</div><div class="hstat-l">分值 3（多步骤）</div></div>
    <div class="hstat"><div class="hstat-n" style="color:#f43f5e">%(hard)s</div><div class="hstat-l">分值 1-2（启动/硬件）</div></div>
    <div class="hstat"><div class="hstat-n" style="color:#7dd3fc">15</div><div class="hstat-l">子系统族</div></div>
  </div>
</header>
<div class="score-key">
  <span class="score-key-lbl">评分说明</span>
  %(score_key)s
</div>
<div class="section-head">子系统族概览</div>
<div class="fam-grid">%(cards)s</div>
<div class="section-head">Trace 触发方案速查</div>
<div class="tt-grid">%(tt_grid)s</div>
<div class="section-head">全量函数表（可搜索 · 可排序 · 可过滤）</div>
<div class="filter-bar">
  <span class="mono muted">❯</span>
  <input id="q" type="text" placeholder="函数名 / 子族 / 触发类型...">
  <span class="filter-label">族</span>
  <select id="ff"><option value="">全部</option>%(fam_opts)s</select>
  <span class="filter-label">分值 ≥</span>
  <select id="sf"><option value="0">全部</option><option value="3">3</option><option value="4">4</option><option value="5">5</option></select>
  <span class="filter-label">触发类型</span>
  <select id="tf"><option value="">全部</option>%(tt_opts)s</select>
  <span id="count-display">0 / 0</span>
</div>
<div class="tbl-outer">
<table id="ftbl">
<thead><tr>
  <th id="h0">函数名</th><th id="h1">族</th><th id="h2">子族前缀</th>
  <th id="h3">分值</th><th id="h4">触发类型</th>
  <th>方案说明</th><th>ftrace filter 命令</th>
</tr></thead>
<tbody id="tb"></tbody>
</table>
</div>
""" % dict(
    easy='%s' % f'{easy:,}',
    mid='%s' % f'{sc_counts.get(3,0):,}',
    hard='%s' % f'{sc_counts.get(1,0)+sc_counts.get(2,0):,}',
    score_key=score_key_html(),
    cards=cards_html(),
    tt_grid=tt_grid_html(),
    fam_opts=fam_options(),
    tt_opts=tt_options(),
)

page = HEADER + CSS + BODY + JS

SCRATCHPAD='/tmp/claude-0/-home-user-test-linux/7618e386-9b7a-5da4-9f39-fa7cd766ebe3/scratchpad/func-plan.html'
with open(SCRATCHPAD,'w') as f:
    f.write(page)
print('Written %dKB' % (len(page)//1024))
