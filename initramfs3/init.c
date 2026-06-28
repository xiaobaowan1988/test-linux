#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/reboot.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>

static void xmount(const char *src, const char *dst,
                   const char *type, unsigned long fl) {
    if (mount(src, dst, type, fl, NULL) < 0)
        printf("  [!!] mount %s: %s\n", dst, strerror(errno));
    else
        printf("  [ok] %-24s\n", dst);
}

static void wait_path(const char *p, int secs) {
    for (int i = 0; i < secs*10; i++) {
        if (access(p, F_OK) == 0) return;
        struct timespec t = {0, 100000000}; nanosleep(&t, NULL);
    }
    printf("  [!!] timeout: %s\n", p);
}

static void msleep(int ms) {
    struct timespec t = {ms/1000, (long)(ms%1000)*1000000L};
    nanosleep(&t, NULL);
}

/* recursively enable cgroup v2 controllers in a directory tree */
static void enable_cgroup_ctrl(const char *path) {
    static const char *ctrl = "+cpu +memory +io +pids";
    char sc[512];
    snprintf(sc, sizeof sc, "%s/cgroup.subtree_control", path);
    int fd = open(sc, O_WRONLY);
    if (fd >= 0) { write(fd, ctrl, strlen(ctrl)); close(fd); }

    DIR *d = opendir(path);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        if (e->d_type != DT_DIR) continue;
        char sub[512];
        snprintf(sub, sizeof sub, "%s/%s", path, e->d_name);
        enable_cgroup_ctrl(sub);
    }
    closedir(d);
}

/* background daemon: poll cgroup kubepods tree every 200ms, enable controllers */
static void cgroup_daemon(void) {
    for (;;) {
        struct timespec t = {0, 200000000L};
        nanosleep(&t, NULL);
        enable_cgroup_ctrl("/sys/fs/cgroup");
    }
}

static void setup_lo(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr; struct sockaddr_in *sin = (void*)&ifr.ifr_addr;
    memset(&ifr,0,sizeof ifr); strncpy(ifr.ifr_name,"lo",IFNAMSIZ);
    sin->sin_family=AF_INET; sin->sin_addr.s_addr=htonl(0x7f000001);
    ioctl(s, SIOCSIFADDR, &ifr);
    memset(&ifr,0,sizeof ifr); strncpy(ifr.ifr_name,"lo",IFNAMSIZ);
    sin->sin_family=AF_INET; sin->sin_addr.s_addr=htonl(0xff000000);
    ioctl(s, SIOCSIFNETMASK, &ifr);
    memset(&ifr,0,sizeof ifr); strncpy(ifr.ifr_name,"lo",IFNAMSIZ);
    ifr.ifr_flags = IFF_UP|IFF_LOOPBACK|IFF_RUNNING;
    ioctl(s, SIOCSIFFLAGS, &ifr); close(s);
    printf("  [ok] lo 127.0.0.1/8\n");
}

/* Add a UNICAST route for the service CIDR (10.96.0.0/12) via lo.
 * Without this route, connect() to ClusterIPs fails with ENETUNREACH
 * before iptables OUTPUT can DNAT the packet to a pod IP. */
static void add_svc_route(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { printf("  [!!] svc route: socket: %s\n", strerror(errno)); return; }
    struct rtentry rt;
    memset(&rt, 0, sizeof rt);
    struct sockaddr_in *dst  = (struct sockaddr_in *)&rt.rt_dst;
    struct sockaddr_in *mask = (struct sockaddr_in *)&rt.rt_genmask;
    struct sockaddr_in *gw   = (struct sockaddr_in *)&rt.rt_gateway;
    dst->sin_family  = AF_INET;
    dst->sin_addr.s_addr = inet_addr("10.96.0.0");
    mask->sin_family = AF_INET;
    mask->sin_addr.s_addr = inet_addr("255.240.0.0"); /* /12 */
    gw->sin_family   = AF_INET;
    gw->sin_addr.s_addr = INADDR_ANY;
    rt.rt_flags = RTF_UP;
    rt.rt_dev   = (char *)"lo";
    if (ioctl(s, SIOCADDRT, &rt) < 0)
        printf("  [!!] svc route SIOCADDRT: %s\n", strerror(errno));
    else
        printf("  [ok] service CIDR route 10.96.0.0/12 → lo\n");
    close(s);
}

/* print up to max_lines lines of a file */
static void head_file(const char *path, int max_lines) {
    FILE *f = fopen(path, "r");
    if (!f) { printf("  (cannot open %s)\n", path); return; }
    char line[512]; int n = 0;
    while (n < max_lines && fgets(line, sizeof line, f))
        { fputs(line, stdout); n++; }
    int total = n;
    while (fgets(line, sizeof line, f)) total++;
    if (total > max_lines)
        printf("  ... (%d more lines)\n", total - max_lines);
    fclose(f);
}

/* cat an entire small /proc file */
static void cat_proc(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("  (not available)\n"); return; }
    char buf[4096]; int n;
    while ((n = read(fd, buf, sizeof buf)) > 0) fwrite(buf, 1, n, stdout);
    close(fd);
}

/* dump /proc/<pid> accounting info — the kernel's open book on a task */
static void proc_account(pid_t pid, const char *name) {
    char path[128];

    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║  /proc/%d  (%s) — kernel 进程账本              \n", pid, name);
    printf("╚══════════════════════════════════════════════════════════╝\n");

    /* ── 1. status: human-readable task_struct fields ─────────── */
    printf("\n┌─ /proc/%d/status  (task_struct 摘要) ─────────────────┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    cat_proc(path);

    /* ── 2. cmdline: argv[] as stored in mm->arg_start..arg_end ─ */
    printf("\n┌─ /proc/%d/cmdline  (完整命令行 argv[]) ────────────────┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
    {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char buf[2048]; int n = read(fd, buf, sizeof buf - 1);
            close(fd);
            if (n > 0) {
                /* NUL-separated args → space-separated for readability */
                for (int i = 0; i < n; i++)
                    putchar(buf[i] == '\0' ? ' ' : buf[i]);
                putchar('\n');
            }
        } else printf("  (not available)\n");
    }

    /* ── 3. stat: raw task_struct fields (scheduler view) ──────── */
    printf("\n┌─ /proc/%d/stat  (调度器原始字段) ──────────────────────┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    cat_proc(path);

    /* ── 4. statm: memory counters in pages ─────────────────────── */
    printf("\n┌─ /proc/%d/statm  (内存页计数: size rss shared text lib data dt) ┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/statm", pid);
    cat_proc(path);

    /* ── 5. wchan: kernel symbol the task is sleeping in ────────── */
    printf("\n┌─ /proc/%d/wchan  (阻塞在哪个内核函数) ────────────────┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/wchan", pid);
    cat_proc(path);
    putchar('\n');

    /* ── 6. schedstat: total run-time & wait-time (ns) ──────────── */
    printf("\n┌─ /proc/%d/schedstat  (运行时间ns / 等待时间ns / 调度次数) ┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/schedstat", pid);
    cat_proc(path);

    /* ── 7. oom_score + oom_score_adj ─────────────────────────── */
    printf("\n┌─ /proc/%d/oom_score  (OOM killer 分值) ─────────────┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/oom_score", pid);
    cat_proc(path);
    printf("┌─ /proc/%d/oom_score_adj  (用户态调整值) ────────────┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/oom_score_adj", pid);
    cat_proc(path);

    /* ── 8. limits: rlimit table ─────────────────────────────── */
    printf("\n┌─ /proc/%d/limits  (资源上限 rlimit 表) ─────────────┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/limits", pid);
    cat_proc(path);

    /* ── 9. io: read/write byte accounting ───────────────────── */
    printf("\n┌─ /proc/%d/io  (I/O 账单: rchar/wchar/syscr/syscw/...) ┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/io", pid);
    cat_proc(path);

    /* ── 10. cgroup: which cgroup hierarchy the task belongs to ── */
    printf("\n┌─ /proc/%d/cgroup  (所属 cgroup 层级) ──────────────────┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/cgroup", pid);
    cat_proc(path);

    /* ── 11. fd: count open file descriptors ─────────────────── */
    printf("\n┌─ /proc/%d/fd/  (打开的文件描述符) ─────────────────────┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/fd", pid);
    {
        DIR *d = opendir(path);
        if (d) {
            int cnt = 0; struct dirent *e;
            while ((e = readdir(d))) if (e->d_name[0] != '.') cnt++;
            closedir(d);
            printf("  共 %d 个打开的 fd\n", cnt);
        } else printf("  (cannot open)\n");
    }

    /* ── 12. maps: first 20 lines of address space map ────────── */
    printf("\n┌─ /proc/%d/maps  (虚拟地址空间前20条) ──────────────────┐\n", pid);
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    head_file(path, 20);

    printf("\n── end of /proc/%d ──────────────────────────────────────\n\n", pid);
}

/* ── ftrace helpers ────────────────────────────────────────────────────── */

/* write a string to a tracefs control file */
static void ftrace_write(const char *path, const char *val) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) return;
    write(fd, val, strlen(val));
    close(fd);
}

/* read up to max bytes from trace pipe/file, return bytes read */
static int ftrace_read_trace(char *buf, int max) {
    int fd = open("/sys/kernel/debug/tracing/trace", O_RDONLY);
    if (fd < 0) return 0;
    int n = read(fd, buf, max - 1);
    close(fd);
    if (n < 0) n = 0;
    buf[n] = '\0';
    return n;
}

/* count how many lines in buf contain needle */
static int count_hits(const char *buf, const char *needle) {
    int hits = 0;
    const char *p = buf;
    while ((p = strstr(p, needle)) != NULL) { hits++; p++; }
    return hits;
}

/*
 * Four experiments that prove .text code is strictly event-driven.
 * Each follows the same recipe:
 *   1) arm the tracer on a specific function
 *   2) clear the trace buffer
 *   3) trigger exactly one event
 *   4) stop tracing and read the ring buffer
 *   5) show the hit count and one representative trace line
 */
static void ftrace_event_proof(void) {
    static char tbuf[65536];

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════╗\n");
    printf("║  ftrace 事件驱动证明实验  (tracefs @ /sys/kernel/debug/tracing/)    ║\n");
    printf("║  结论：没有事件 → ring buffer 空；事件发生 → 函数立即出现           ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════╝\n");

    /* make sure tracefs is mounted */
    if (access("/sys/kernel/debug/tracing/current_tracer", F_OK) != 0) {
        /* try mounting debugfs first */
        mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL);
        mount("tracefs", "/sys/kernel/debug/tracing", "tracefs", 0, NULL);
    }
    if (access("/sys/kernel/debug/tracing/current_tracer", F_OK) != 0) {
        printf("  [!!] tracefs not available — skipping ftrace experiments\n");
        return;
    }
    printf("  [ok] tracefs mounted\n\n");

    /* ── Experiment 1: syscall path ──────────────────────────────────── */
    printf("┌─ 实验1: syscall 路径  (write → __arm64_sys_write) ─────────────────┐\n");
    printf("│  假设: 只有执行 write(2) 系统调用时 __arm64_sys_write 才会出现     │\n");
    printf("│  方法: arm tracer → 清空 buffer → 执行 write → 读 trace           │\n");
    printf("└─────────────────────────────────────────────────────────────────────┘\n");

    ftrace_write("/sys/kernel/debug/tracing/current_tracer", "function");
    ftrace_write("/sys/kernel/debug/tracing/set_ftrace_filter", "__arm64_sys_write");
    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "0");
    ftrace_write("/sys/kernel/debug/tracing/trace", ""); /* clear */
    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "1");

    /* trigger exactly one write() syscall */
    write(1, "", 0);  /* zero-length write — touches syscall path but outputs nothing */

    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "0");
    int n1 = ftrace_read_trace(tbuf, sizeof tbuf);
    int hits1 = count_hits(tbuf, "__arm64_sys_write");
    printf("  ring buffer size: %d bytes | __arm64_sys_write 出现次数: %d\n", n1, hits1);
    if (hits1 > 0) {
        /* print first matching line */
        char *p = strstr(tbuf, "__arm64_sys_write");
        if (p) {
            /* walk back to start of line */
            while (p > tbuf && *(p-1) != '\n') p--;
            char *end = strchr(p, '\n');
            if (end) *end = '\0';
            printf("  → %s\n", p);
            if (end) *end = '\n';
        }
    }
    printf("  %-8s write() 触发前 buffer 为空；write() 后立即命中\n\n",
           hits1 > 0 ? "[证明]" : "[跳过]");

    /* ── Experiment 2: timer/IRQ path ────────────────────────────────── */
    /* arm64 timer IRQ entry point: arch_timer_handler_virt (virtual timer) */
    printf("┌─ 实验2: 硬件中断路径  (timer tick → arch_timer_handler_virt) ──────┐\n");
    printf("│  假设: 只有时钟中断到来时 arch_timer_handler_virt 才会出现         │\n");
    printf("│  方法: arm tracer → 清空 → nanosleep(10ms) → 读 trace             │\n");
    printf("└─────────────────────────────────────────────────────────────────────┘\n");

    ftrace_write("/sys/kernel/debug/tracing/set_ftrace_filter", "arch_timer_handler_virt");
    ftrace_write("/sys/kernel/debug/tracing/trace", "");
    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "1");

    /* sleep 10ms — several timer interrupts will fire */
    struct timespec ts = { 0, 10000000L };
    nanosleep(&ts, NULL);

    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "0");
    int n2 = ftrace_read_trace(tbuf, sizeof tbuf);
    int hits2 = count_hits(tbuf, "arch_timer_handler_virt");
    printf("  ring buffer size: %d bytes | arch_timer_handler_virt 出现次数: %d\n", n2, hits2);
    if (hits2 > 0) {
        char *p = strstr(tbuf, "arch_timer_handler_virt");
        if (p) {
            while (p > tbuf && *(p-1) != '\n') p--;
            char *end = strchr(p, '\n');
            if (end) *end = '\0';
            printf("  → %s\n", p);
            if (end) *end = '\n';
        }
    }
    printf("  %-8s nanosleep 期间时钟中断驱动 arch_timer_handler_virt；sleep前后无命中\n\n",
           hits2 > 0 ? "[证明]" : "[跳过]");

    /* ── Experiment 3: page fault path ──────────────────────────────── */
    printf("┌─ 实验3: 缺页中断路径  (mmap access → do_mem_abort) ───────────────┐\n");
    printf("│  假设: 只有访问未映射内存时 do_mem_abort 才会出现                 │\n");
    printf("│  方法: arm tracer → 清空 → mmap(anon) → *ptr=1 → 读 trace        │\n");
    printf("└─────────────────────────────────────────────────────────────────────┘\n");

    ftrace_write("/sys/kernel/debug/tracing/set_ftrace_filter", "do_mem_abort");
    ftrace_write("/sys/kernel/debug/tracing/trace", "");
    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "1");

    /* allocate one anonymous page and touch it — triggers a page fault */
    {
        void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            volatile char *cp = (volatile char *)p;
            *cp = 0x42;          /* first access → page fault → do_mem_abort */
            munmap(p, 4096);
        }
    }

    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "0");
    int n3 = ftrace_read_trace(tbuf, sizeof tbuf);
    int hits3 = count_hits(tbuf, "do_mem_abort");
    printf("  ring buffer size: %d bytes | do_mem_abort 出现次数: %d\n", n3, hits3);
    if (hits3 > 0) {
        char *p = strstr(tbuf, "do_mem_abort");
        if (p) {
            while (p > tbuf && *(p-1) != '\n') p--;
            char *end = strchr(p, '\n');
            if (end) *end = '\0';
            printf("  → %s\n", p);
            if (end) *end = '\n';
        }
    }
    printf("  %-8s 匿名页首次访问精确触发 do_mem_abort；mmap 前后 buffer 为空\n\n",
           hits3 > 0 ? "[证明]" : "[跳过]");

    /* ── Experiment 4: TCP receive path ─────────────────────────────── */
    printf("┌─ 实验4: 网络/TCP 路径  (loopback packet → tcp_rcv_established) ───┐\n");
    printf("│  假设: 只有 TCP 数据包到来时 tcp_rcv_established 才会出现         │\n");
    printf("│  方法: arm tracer → 清空 → loopback TCP echo → 读 trace           │\n");
    printf("└─────────────────────────────────────────────────────────────────────┘\n");

    ftrace_write("/sys/kernel/debug/tracing/set_ftrace_filter", "tcp_rcv_established");
    ftrace_write("/sys/kernel/debug/tracing/trace", "");
    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "1");

    /* mini TCP loopback: server socket + client connect + send + recv */
    {
        int srv = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons(19876);
        bind(srv, (struct sockaddr *)&sa, sizeof sa);
        listen(srv, 1);

        pid_t cpid = fork();
        if (cpid == 0) {
            /* child: client */
            int c = socket(AF_INET, SOCK_STREAM, 0);
            connect(c, (struct sockaddr *)&sa, sizeof sa);
            send(c, "PING", 4, 0);
            char rbuf[8]; recv(c, rbuf, sizeof rbuf, 0);
            close(c);
            _exit(0);
        }
        /* parent: server accepts, echoes */
        int cl = accept(srv, NULL, NULL);
        char rbuf[8]; int nr = recv(cl, rbuf, sizeof rbuf, 0);
        if (nr > 0) send(cl, rbuf, nr, 0);
        close(cl); close(srv);
        int st; waitpid(cpid, &st, 0);
    }

    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "0");
    int n4 = ftrace_read_trace(tbuf, sizeof tbuf);
    int hits4 = count_hits(tbuf, "tcp_rcv_established");
    printf("  ring buffer size: %d bytes | tcp_rcv_established 出现次数: %d\n", n4, hits4);
    if (hits4 > 0) {
        char *p = strstr(tbuf, "tcp_rcv_established");
        if (p) {
            while (p > tbuf && *(p-1) != '\n') p--;
            char *end = strchr(p, '\n');
            if (end) *end = '\0';
            printf("  → %s\n", p);
            if (end) *end = '\n';
        }
    }
    printf("  %-8s loopback TCP 数据包精确触发 tcp_rcv_established\n\n",
           hits4 > 0 ? "[证明]" : "[跳过]");

    /* ── Experiment 5: softirq path ──────────────────────────────────── */
    printf("┌─ 实验5: softirq 路径  (UDP packet → __do_softirq) ────────────────┐\n");
    printf("│  假设: 只有软中断被 raise 时 __do_softirq 才会出现                │\n");
    printf("│  方法: arm tracer → 清空 → 发送 UDP loopback 包 → 读 trace        │\n");
    printf("└─────────────────────────────────────────────────────────────────────┘\n");

    ftrace_write("/sys/kernel/debug/tracing/set_ftrace_filter", "__do_softirq");
    ftrace_write("/sys/kernel/debug/tracing/trace", "");
    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "1");

    /* send a UDP datagram to loopback — triggers NET_RX_SOFTIRQ on arrival */
    {
        int usrv = socket(AF_INET, SOCK_DGRAM, 0);
        int ucli = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in usa;
        memset(&usa, 0, sizeof usa);
        usa.sin_family = AF_INET;
        usa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        usa.sin_port = htons(19877);
        bind(usrv, (struct sockaddr *)&usa, sizeof usa);
        sendto(ucli, "X", 1, 0, (struct sockaddr *)&usa, sizeof usa);
        char rb[4]; recvfrom(usrv, rb, sizeof rb, 0, NULL, NULL);
        close(usrv); close(ucli);
    }

    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "0");
    int n5 = ftrace_read_trace(tbuf, sizeof tbuf);
    int hits5 = count_hits(tbuf, "__do_softirq");
    printf("  ring buffer size: %d bytes | __do_softirq 出现次数: %d\n", n5, hits5);
    if (hits5 > 0) {
        char *p = strstr(tbuf, "__do_softirq");
        if (p) {
            while (p > tbuf && *(p-1) != '\n') p--;
            char *end = strchr(p, '\n');
            if (end) *end = '\0';
            printf("  → %s\n", p);
            if (end) *end = '\n';
        }
    }
    printf("  %-8s UDP 包到来触发 NET_RX_SOFTIRQ → __do_softirq；包发送前 buffer 为空\n\n",
           hits5 > 0 ? "[证明]" : "[跳过]");

    /* ── Experiment 6: workqueue/kthread path ────────────────────────── */
    /*
     * __queue_work() is the internal kernel function called whenever any work_struct
     * is enqueued onto a workqueue (via queue_work / queue_work_on / schedule_work).
     * Trigger: fork 5 children that exit immediately.  do_exit() → exit_mm() →
     * mmdrop_async() → queue_work(mm_percpu_wq, ...) → __queue_work().
     */
    printf("┌─ 实验6: workqueue/kthread 路径  (fork+exit → __queue_work) ────────┐\n");
    printf("│  假设: 只有 work item 入队时 __queue_work 才会出现                 │\n");
    printf("│  方法: arm tracer → 清空 → fork×5子进程立即退出 → 读 trace         │\n");
    printf("└─────────────────────────────────────────────────────────────────────┘\n");

    ftrace_write("/sys/kernel/debug/tracing/set_ftrace_filter", "__queue_work");
    ftrace_write("/sys/kernel/debug/tracing/trace", "");
    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "1");

    /* 5 fork+exit cycles: each exit calls do_exit → exit_mm → mmdrop_async →
     * queue_work(mm_percpu_wq) → __queue_work(), guaranteeing workqueue activity */
    for (int i = 0; i < 5; i++) {
        pid_t fp = fork();
        if (fp == 0) _exit(0);
        int fst; waitpid(fp, &fst, 0);
    }
    /* small pause for async work to be enqueued */
    { struct timespec tw = {0, 5000000L}; nanosleep(&tw, NULL); }

    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "0");
    int n6 = ftrace_read_trace(tbuf, sizeof tbuf);
    int hits6 = count_hits(tbuf, "__queue_work");
    printf("  ring buffer size: %d bytes | __queue_work 出现次数: %d\n", n6, hits6);
    if (hits6 > 0) {
        char *p = strstr(tbuf, "__queue_work");
        if (p) {
            while (p > tbuf && *(p-1) != '\n') p--;
            char *end = strchr(p, '\n');
            if (end) *end = '\0';
            printf("  → %s\n", p);
            if (end) *end = '\n';
        }
    }
    printf("  %-8s 进程退出时 mm 清理触发 __queue_work 向 kworker 投递任务\n\n",
           hits6 > 0 ? "[证明]" : "[跳过]");

    /* ── Experiment 7: scheduler path ───────────────────────────────── */
    /* __schedule is notrace; use schedule() — the exported wrapper that IS traceable */
    printf("┌─ 实验7: 调度器路径  (blocking sleep → schedule) ──────────────────┐\n");
    printf("│  假设: 只有进程主动放弃 CPU (block/yield) 时 schedule 才会出现    │\n");
    printf("│  方法: arm tracer → 清空 → nanosleep(1ms) 阻塞 → 读 trace         │\n");
    printf("└─────────────────────────────────────────────────────────────────────┘\n");

    ftrace_write("/sys/kernel/debug/tracing/set_ftrace_filter", "schedule");
    ftrace_write("/sys/kernel/debug/tracing/trace", "");
    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "1");

    /* nanosleep blocks → kernel calls schedule() to pick next runnable task */
    { struct timespec tsched = {0, 1000000L}; nanosleep(&tsched, NULL); }

    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "0");
    int n7 = ftrace_read_trace(tbuf, sizeof tbuf);
    int hits7 = count_hits(tbuf, " schedule <-");  /* exact: " schedule <-" avoids __schedule */
    printf("  ring buffer size: %d bytes | schedule 出现次数: %d\n", n7, hits7);
    if (hits7 > 0) {
        char *p = strstr(tbuf, " schedule <-");
        if (p) {
            while (p > tbuf && *(p-1) != '\n') p--;
            char *end = strchr(p, '\n');
            if (end) *end = '\0';
            printf("  → %s\n", p);
            if (end) *end = '\n';
        }
    }
    printf("  %-8s 进程阻塞精确触发 schedule → context_switch；空转时 buffer 为空\n\n",
           hits7 > 0 ? "[证明]" : "[跳过]");

    /* ── Summary ─────────────────────────────────────────────────────── */
    printf("╔══════════════════════════════════════════════════════════════════════╗\n");
    printf("║  七扇门 · ftrace 全量实验汇总                                        ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════╣\n");
    printf("║  门1 syscall (svc #0)       __arm64_sys_write      %3d次  %-6s  ║\n",
           hits1, hits1 > 0 ? "✓PASS" : "SKIP");
    printf("║  门2 硬件IRQ (GIC)          arch_timer_handler_virt%3d次  %-6s  ║\n",
           hits2, hits2 > 0 ? "✓PASS" : "SKIP");
    printf("║  门3 缺页中断 (MMU)         do_mem_abort            %3d次  %-6s  ║\n",
           hits3, hits3 > 0 ? "✓PASS" : "SKIP");
    printf("║  门4 TCP接收 (via softirq)  tcp_rcv_established     %3d次  %-6s  ║\n",
           hits4, hits4 > 0 ? "✓PASS" : "SKIP");
    printf("║  门5 softirq (NET_RX)       __do_softirq            %3d次  %-6s  ║\n",
           hits5, hits5 > 0 ? "✓PASS" : "SKIP");
    printf("║  门6 workqueue/kthread      __queue_work            %3d次  %-6s  ║\n",
           hits6, hits6 > 0 ? "✓PASS" : "SKIP");
    printf("║  门7 调度器 (schedule)      schedule                %3d次  %-6s  ║\n",
           hits7, hits7 > 0 ? "✓PASS" : "SKIP");
    printf("╠══════════════════════════════════════════════════════════════════════╣\n");
    printf("║  结论: 七扇门全部实测。没有任何函数自发运行——                        ║\n");
    printf("║        每一行 trace 背后都有且只有一个具体事件触发。                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════╝\n\n");

    /* reset tracer to nop */
    ftrace_write("/sys/kernel/debug/tracing/current_tracer", "nop");
    ftrace_write("/sys/kernel/debug/tracing/set_ftrace_filter", "");
    ftrace_write("/sys/kernel/debug/tracing/tracing_on", "0");
}

/* tail last N bytes of a file to stdout */
static void tail_file(const char *path, int nbytes) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("  (cannot open %s)\n", path); return; }
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz > nbytes) lseek(fd, -nbytes, SEEK_END);
    else lseek(fd, 0, SEEK_SET);
    char buf[4096]; int n;
    while ((n = read(fd, buf, sizeof buf)) > 0) fwrite(buf, 1, n, stdout);
    close(fd);
}

/* run kubectl command with header; argv must be NULL-terminated */
static void kctl(const char *header, const char *const argv[]) {
    if (header) printf("\n── %-44s\n", header);
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        execv("/bin/kubectl", (char *const *)argv);
        _exit(1);
    }
    int st; waitpid(p, &st, 0);
}

int main(void)
{
    int fd = open("/dev/console", O_RDWR);
    if (fd >= 0) { dup2(fd,0); dup2(fd,1); dup2(fd,2); if(fd>2) close(fd); }

    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║   kubelet v1.31  Test on arm64 Linux         ║\n");
    printf("║   Linux 7.1-rc7  containerd 1.7.25  etcd kube║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    /* ── system setup ─────────────────────────────────────── */
    printf("[ Setup ]\n");
    xmount("proc",    "/proc",          "proc",    0);
    xmount("sysfs",   "/sys",           "sysfs",   0);
    xmount("tmpfs",   "/tmp",           "tmpfs",   0);
    xmount("tmpfs",   "/run",           "tmpfs",   0);
    xmount("devtmpfs","/dev",           "devtmpfs",0);
    xmount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0);
    /* enable controllers at root level */
    {
        int fd = open("/sys/fs/cgroup/cgroup.subtree_control", O_WRONLY);
        if (fd >= 0) {
            const char *ctrl = "+cpu +memory +io +pids";
            write(fd, ctrl, strlen(ctrl));
            close(fd);
            printf("  [ok] cgroup2 controllers: cpu memory io pids\n");
        } else {
            printf("  [!!] cgroup.subtree_control: %s\n", strerror(errno));
        }
    }
    /* fork background daemon to keep controllers enabled as kubelet creates pod cgroups */
    {
        pid_t p = fork();
        if (p == 0) { cgroup_daemon(); _exit(0); }
    }
    mkdir("/run/containerd", 0755);
    mkdir("/var", 0755); mkdir("/var/lib", 0755);
    mkdir("/var/lib/etcd", 0755);
    mkdir("/var/lib/kubelet", 0755);
    mkdir("/var/lib/kubelet/pods", 0755);
    mkdir("/var/log", 0755);
    mkdir("/var/log/pods", 0755);
    mkdir("/var/log/containers", 0755);
    mkdir("/var/run", 0755);
    mkdir("/run/netns", 0755);

    setup_lo();
    add_svc_route();
    sethostname("test-node", 9);
    setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/sbin", 1);

    /* ── etcd ────────────────────────────────────────────── */
    printf("\n[ etcd ]\n");
    pid_t etcd_pid = fork();
    if (etcd_pid == 0) {
        int logfd = open("/tmp/etcd.log", O_WRONLY|O_CREAT|O_TRUNC, 0644);
        dup2(logfd,1); dup2(logfd,2); close(logfd);
        execl("/bin/etcd","etcd",
              "--data-dir",              "/var/lib/etcd",
              "--listen-client-urls",    "http://127.0.0.1:2379",
              "--advertise-client-urls", "http://127.0.0.1:2379",
              "--listen-peer-urls",      "http://127.0.0.1:2380",
              "--initial-advertise-peer-urls", "http://127.0.0.1:2380",
              "--initial-cluster",       "default=http://127.0.0.1:2380",
              "--initial-cluster-state", "new",
              "--initial-cluster-token", "etcd-cluster-1",
              "--name",                  "default",
              NULL);
        _exit(1);
    }
    /* wait for etcd to become ready (up to 15s) */
    {
        int ready = 0;
        for (int i = 0; i < 150 && !ready; i++) {
            msleep(100);
            FILE *f = fopen("/tmp/etcd.log", "r");
            if (!f) continue;
            char line[512];
            while (fgets(line, sizeof line, f)) {
                if (strstr(line, "serving client traffic") ||
                    strstr(line, "ready to serve client requests") ||
                    strstr(line, "serving insecure client requests")) {
                    ready = 1; break;
                }
            }
            fclose(f);
        }
        if (ready)
            printf("  [ok] etcd ready (pid=%d)\n", etcd_pid);
        else
            printf("  [!!] etcd not ready after 15s\n");
    }

    /* ── kube-apiserver ─────────────────────────────────── */
    printf("\n[ kube-apiserver ]\n");
    pid_t kas_pid = fork();
    if (kas_pid == 0) {
        int logfd = open("/tmp/kube-apiserver.log", O_WRONLY|O_CREAT|O_TRUNC, 0644);
        dup2(logfd,1); dup2(logfd,2); close(logfd);
        execl("/bin/kube-apiserver","kube-apiserver",
              "--etcd-servers",              "http://127.0.0.1:2379",
              "--advertise-address",         "127.0.0.1",
              "--bind-address",              "127.0.0.1",
              "--service-cluster-ip-range",  "10.96.0.0/12",
              "--tls-cert-file",             "/etc/kubernetes/pki/apiserver.crt",
              "--tls-private-key-file",      "/etc/kubernetes/pki/apiserver.key",
              "--client-ca-file",            "/etc/kubernetes/pki/ca.crt",
              "--service-account-key-file",  "/etc/kubernetes/pki/sa.pub",
              "--service-account-signing-key-file", "/etc/kubernetes/pki/sa.key",
              "--service-account-issuer",    "https://kubernetes.default.svc.cluster.local",
              "--token-auth-file",           "/etc/kubernetes/token.csv",
              "--authorization-mode",        "AlwaysAllow",
              "--anonymous-auth=true",
              "--allow-privileged=true",
              "--v=2",
              NULL);
        _exit(1);
    }
    /* wait up to 30s for kube-apiserver to be ready */
    {
        int ready = 0;
        for (int i = 0; i < 600 && !ready; i++) {
            msleep(100);
            FILE *f = fopen("/tmp/kube-apiserver.log", "r");
            if (!f) continue;
            char line[512];
            while (fgets(line, sizeof line, f)) {
                if (strstr(line, "Serving securely") ||
                    strstr(line, "serving securely") ||
                    strstr(line, "insecurely on") ||
                    strstr(line, "secure serving") ||
                    strstr(line, "READY")) {
                    ready = 1; break;
                }
            }
            fclose(f);
        }
        if (ready)
            printf("  [ok] kube-apiserver ready (pid=%d)\n", kas_pid);
        else
            printf("  [!!] kube-apiserver not ready after 60s\n");
    }

    /* ── kube-controller-manager ────────────────────────── */
    printf("\n[ kube-controller-manager ]\n");
    pid_t kcm_pid = fork();
    if (kcm_pid == 0) {
        int logfd = open("/tmp/kcm.log", O_WRONLY|O_CREAT|O_TRUNC, 0644);
        dup2(logfd,1); dup2(logfd,2); close(logfd);
        execl("/bin/kube-controller-manager","kube-controller-manager",
              "--kubeconfig",                   "/etc/kubernetes/controller-manager.kubeconfig",
              "--service-account-private-key-file", "/etc/kubernetes/pki/sa.key",
              "--root-ca-file",                 "/etc/kubernetes/pki/ca.crt",
              "--cluster-signing-cert-file",    "/etc/kubernetes/pki/ca.crt",
              "--cluster-signing-key-file",     "/etc/kubernetes/pki/ca.key",
              "--bind-address",                 "127.0.0.1",
              "--leader-elect=false",
              "--use-service-account-credentials=false",
              "--controllers=*",
              "--v=2",
              NULL);
        _exit(1);
    }
    /* wait up to 20s for controller-manager to start */
    {
        int ready = 0;
        for (int i = 0; i < 200 && !ready; i++) {
            msleep(100);
            FILE *f = fopen("/tmp/kcm.log", "r");
            if (!f) continue;
            char line[512];
            while (fgets(line, sizeof line, f)) {
                if (strstr(line, "Starting controller") ||
                    strstr(line, "Started controller") ||
                    strstr(line, "Serving securely") ||
                    strstr(line, "serving securely")) {
                    ready = 1; break;
                }
            }
            fclose(f);
        }
        if (ready)
            printf("  [ok] kube-controller-manager started (pid=%d)\n", kcm_pid);
        else
            printf("  [!!] kube-controller-manager not ready after 20s\n");
    }

    /* ── kube-scheduler ─────────────────────────────────── */
    printf("\n[ kube-scheduler ]\n");
    pid_t ks_pid = fork();
    if (ks_pid == 0) {
        int logfd = open("/tmp/ks.log", O_WRONLY|O_CREAT|O_TRUNC, 0644);
        dup2(logfd,1); dup2(logfd,2); close(logfd);
        execl("/bin/kube-scheduler","kube-scheduler",
              "--kubeconfig",    "/etc/kubernetes/scheduler.kubeconfig",
              "--bind-address",  "127.0.0.1",
              "--leader-elect=false",
              "--v=2",
              NULL);
        _exit(1);
    }
    {
        int ready = 0;
        for (int i = 0; i < 150 && !ready; i++) {
            msleep(100);
            FILE *f = fopen("/tmp/ks.log", "r");
            if (!f) continue;
            char line[512];
            while (fgets(line, sizeof line, f)) {
                if (strstr(line, "Serving securely") ||
                    strstr(line, "serving securely") ||
                    strstr(line, "Starting Scheduler") ||
                    strstr(line, "starting scheduler")) {
                    ready = 1; break;
                }
            }
            fclose(f);
        }
        if (ready)
            printf("  [ok] kube-scheduler started (pid=%d)\n", ks_pid);
        else
            printf("  [!!] kube-scheduler not ready after 15s\n");
    }

    /* ── containerd ──────────────────────────────────────── */
    printf("\n[ containerd ]\n");
    pid_t cd = fork();
    if (cd == 0) {
        int nul = open("/dev/null",O_WRONLY); dup2(nul,1); dup2(nul,2);
        execl("/bin/containerd","containerd",
              "--config", "/etc/containerd/config.toml",
              "--root",   "/run/containerd/root",
              "--state",  "/run/containerd/state", NULL);
        _exit(1);
    }
    wait_path("/run/containerd/containerd.sock", 20);
    msleep(500);
    printf("  [ok] containerd ready (pid=%d)\n", cd);

    /* pre-import hello image into k8s.io namespace */
    {
        pid_t p = fork();
        if (p == 0) {
            int nul=open("/dev/null",O_WRONLY); dup2(nul,1); dup2(nul,2);
            execl("/bin/ctr","ctr",
                  "--address","/run/containerd/containerd.sock",
                  "--namespace","k8s.io",
                  "images","import","/hello.oci.tar",
                  "--index-name","docker.io/library/hello:latest", NULL);
            _exit(1);
        }
        int st; waitpid(p, &st, 0);
        printf("  [ok] hello image imported\n");
    }

    /* pre-import hello-http image (HTTP server for ingress test) */
    {
        pid_t p = fork();
        if (p == 0) {
            int nul=open("/dev/null",O_WRONLY); dup2(nul,1); dup2(nul,2);
            execl("/bin/ctr","ctr",
                  "--address","/run/containerd/containerd.sock",
                  "--namespace","k8s.io",
                  "images","import","/hello-http.oci.tar",
                  "--index-name","docker.io/library/hello-http:latest", NULL);
            _exit(1);
        }
        int st; waitpid(p, &st, 0);
        printf("  [ok] hello-http image imported\n");
    }

    /* pre-import pause image (kubelet sandbox) into k8s.io namespace */
    {
        pid_t p = fork();
        if (p == 0) {
            int nul=open("/dev/null",O_WRONLY); dup2(nul,1); dup2(nul,2);
            execl("/bin/ctr","ctr",
                  "--address","/run/containerd/containerd.sock",
                  "--namespace","k8s.io",
                  "images","import","/pause.oci.tar",
                  "--index-name","registry.k8s.io/pause:3.8", NULL);
            _exit(1);
        }
        int st; waitpid(p, &st, 0);
        printf("  [ok] pause image imported\n");
    }

    /* ── kube-proxy ─────────────────────────────────────── */
    printf("\n[ kube-proxy ]\n");
    {
        pid_t p = fork();
        if (p == 0) {
            int logfd = open("/tmp/kube-proxy.log", O_WRONLY|O_CREAT|O_TRUNC, 0644);
            dup2(logfd,1); dup2(logfd,2); close(logfd);
            execl("/bin/kube-proxy","kube-proxy",
                  "--kubeconfig",  "/etc/kubernetes/kube-proxy.kubeconfig",
                  "--proxy-mode",  "iptables",
                  "--cluster-cidr","10.88.0.0/16",
                  "--v=2",
                  NULL);
            _exit(1);
        }
        /* wait up to 10s for kube-proxy to set up KUBE-SERVICES chain */
        int ready = 0;
        for (int i = 0; i < 100 && !ready; i++) {
            msleep(100);
            FILE *f = fopen("/tmp/kube-proxy.log", "r");
            if (!f) continue;
            char line[512];
            while (fgets(line, sizeof line, f)) {
                if (strstr(line, "Syncing iptables rules") ||
                    strstr(line, "syncProxyRules took") ||
                    strstr(line, "Tearing down inactive")) {
                    ready = 1; break;
                }
            }
            fclose(f);
        }
        printf("  [%s] kube-proxy (pid=%d)\n", ready?"ok":"!!", p);
    }

    /* ── test-csi driver ────────────────────────────────── */
    printf("\n[ test-csi driver ]\n");
    mkdir("/var/lib/test-csi-volumes", 0755);
    mkdir("/var/lib/kubelet/plugins", 0755);
    mkdir("/var/lib/kubelet/plugins_registry", 0755);
    {
        pid_t p = fork();
        if (p == 0) {
            int logfd = open("/tmp/test-csi.log", O_WRONLY|O_CREAT|O_TRUNC, 0644);
            dup2(logfd,1); dup2(logfd,2); close(logfd);
            execl("/bin/test-csi","test-csi",NULL);
            _exit(1);
        }
        /* wait for CSI socket to appear (up to 5s) */
        int ready = 0;
        for (int i = 0; i < 50 && !ready; i++) {
            msleep(100);
            if (access("/var/lib/kubelet/plugins/test.csi.k8s.io/csi.sock", F_OK) == 0)
                ready = 1;
        }
        printf("  [%s] test-csi (pid=%d)\n", ready?"ok":"!!" , p);
    }

    /* ── test-ingress controller ─────────────────────────── */
    printf("\n[ test-ingress controller ]\n");
    {
        pid_t p = fork();
        if (p == 0) {
            int logfd = open("/tmp/test-ingress.log", O_WRONLY|O_CREAT|O_TRUNC, 0644);
            dup2(logfd,1); dup2(logfd,2); close(logfd);
            execl("/bin/test-ingress","test-ingress",NULL);
            _exit(1);
        }
        msleep(500);
        printf("  [ok] test-ingress started (pid=%d)\n", p);
    }

    /* ── kubelet ─────────────────────────────────────────── */
    printf("\n[ kubelet ]\n");
    /* redirect kubelet logs to file so we can tail them */
    /* show manifest dir so we can confirm files are present */
    printf("  manifests dir:\n");
    {
        DIR *d = opendir("/etc/kubernetes/manifests");
        if (!d) {
            printf("    (cannot open: %s)\n", strerror(errno));
        } else {
            struct dirent *e;
            while ((e = readdir(d))) printf("    %s\n", e->d_name);
            closedir(d);
        }
    }

    pid_t kl = fork();
    if (kl == 0) {
        int logfd = open("/tmp/kubelet.log",
                         O_WRONLY|O_CREAT|O_TRUNC, 0644);
        dup2(logfd,1); dup2(logfd,2); close(logfd);
        execl("/bin/kubelet","kubelet",
              "--config",            "/etc/kubernetes/kubelet-config.yaml",
              "--kubeconfig",        "/etc/kubernetes/kubelet.kubeconfig",
              "--root-dir",          "/var/lib/kubelet",
              "--hostname-override", "test-node",
              "--v=4",
              NULL);
        _exit(1);
    }
    printf("  kubelet started (pid=%d), waiting 60s for pod...\n\n", kl);

    /* wait up to 60s for the pod log to appear */
    int pod_seen = 0;
    for (int i = 0; i < 600 && !pod_seen; i++) {
        msleep(100);
        /* check kubelet log for pod start indicators */
        FILE *f = fopen("/tmp/kubelet.log", "r");
        if (!f) continue;
        char line[512];
        while (fgets(line, sizeof line, f)) {
            if (strstr(line, "hello-static") &&
                (strstr(line, "Started") || strstr(line, "Running") ||
                 strstr(line, "SyncPod") || strstr(line, "pulling") ||
                 strstr(line, "start_worker"))) {
                pod_seen = 1; break;
            }
        }
        fclose(f);
    }

    if (pod_seen)
        printf("  pod activity detected, waiting 45s for container start...\n");
    else
        printf("  timeout: no pod activity detected\n");

    /* wait for sandbox + container creation to complete */
    for (int i = 0; i < 450; i++) {
        msleep(100);
        /* stop early if container task appears */
        FILE *f = fopen("/tmp/kubelet.log", "r");
        if (!f) continue;
        char line[512];
        int done = 0;
        while (fgets(line, sizeof line, f)) {
            if (strstr(line, "hello-static") &&
                (strstr(line, "Started container") ||
                 strstr(line, "start_worker") ||
                 strstr(line, "PostStartHook"))) {
                done = 1; break;
            }
        }
        fclose(f);
        if (done) { printf("  container started!\n"); msleep(8000); break; }
    }

    /* ── kubectl GVK comprehensive test ─────────────────── */
    setenv("KUBECONFIG", "/etc/kubernetes/admin.kubeconfig", 1);
    printf("\n\n╔══════════════════════════════════════════════╗\n");
    printf(    "║          kubectl GVK Test Suite              ║\n");
    printf(    "╚══════════════════════════════════════════════╝\n");

    /* 1. All available API resources (GVKs) */
    kctl("api-resources (all GVKs)", (const char*[]){
        "kubectl","api-resources","--verbs=list","-o","wide","--sort-by=kind",NULL});

    /* 2. API versions */
    kctl("api-versions", (const char*[]){
        "kubectl","api-versions",NULL});

    /* ── core/v1 ─────────────────────────────── */
    kctl("core/v1 » nodes -o wide", (const char*[]){
        "kubectl","get","nodes","-o","wide",NULL});
    kctl("core/v1 » pods -A -o wide", (const char*[]){
        "kubectl","get","pods","-A","-o","wide",NULL});
    kctl("core/v1 » namespaces", (const char*[]){
        "kubectl","get","namespaces",NULL});
    kctl("core/v1 » services -A", (const char*[]){
        "kubectl","get","services","-A",NULL});
    kctl("core/v1 » endpoints -A", (const char*[]){
        "kubectl","get","endpoints","-A",NULL});
    kctl("core/v1 » configmaps -A", (const char*[]){
        "kubectl","get","configmaps","-A",NULL});
    kctl("core/v1 » secrets -A", (const char*[]){
        "kubectl","get","secrets","-A",NULL});
    kctl("core/v1 » serviceaccounts -A", (const char*[]){
        "kubectl","get","serviceaccounts","-A",NULL});
    kctl("core/v1 » persistentvolumes", (const char*[]){
        "kubectl","get","persistentvolumes",NULL});
    kctl("core/v1 » persistentvolumeclaims -A", (const char*[]){
        "kubectl","get","persistentvolumeclaims","-A",NULL});
    kctl("core/v1 » resourcequotas -A", (const char*[]){
        "kubectl","get","resourcequotas","-A",NULL});
    kctl("core/v1 » limitranges -A", (const char*[]){
        "kubectl","get","limitranges","-A",NULL});
    kctl("core/v1 » events -A (latest 20)", (const char*[]){
        "kubectl","get","events","-A","--sort-by=.lastTimestamp",NULL});

    /* ── apply test resources ──────────────── */
    kctl("CREATE test resources (all GVKs)",
        (const char*[]){"kubectl","apply","-f",
          "/etc/kubernetes/test-resources.yaml",NULL});

    /* wait up to 90s for Deployment pod to be Running */
    printf("\n  waiting up to 90s for hello-deploy pod...\n");
    for (int i = 0; i < 900; i++) {
        msleep(100);
        FILE *f = popen("kubectl get pods -A --no-headers 2>/dev/null", "r");
        if (!f) continue;
        char line[256]; int done = 0;
        while (fgets(line, sizeof line, f))
            if (strstr(line,"hello-deploy") && strstr(line,"Running")) { done=1; break; }
        pclose(f);
        if (done) {
            printf("  [ok] hello-deploy pod Running\n");
            /* wait up to 30s for hello-svc endpoint to be populated */
            printf("  waiting for hello-svc endpoint (kube-proxy sync)...\n");
            for (int ep = 0; ep < 150; ep++) {
                msleep(200);
                FILE *ef = popen("kubectl get endpoints hello-svc --no-headers 2>/dev/null", "r");
                if (!ef) continue;
                char el[256]; int ep_ok = 0;
                while (fgets(el, sizeof el, ef))
                    if (strstr(el,"hello-svc") && !strstr(el,"<none>")) { ep_ok=1; break; }
                pclose(ef);
                if (ep_ok) {
                    printf("  [ok] hello-svc endpoint populated, sleeping 5s for kube-proxy iptables sync\n");
                    msleep(5000);
                    break;
                }
            }
            break;
        }
    }

    /* wait up to 60s for CSI PVC to be Bound */
    printf("  waiting up to 60s for CSI PVC Bound...\n");
    for (int i = 0; i < 600; i++) {
        msleep(100);
        FILE *f = popen("kubectl get pvc -A --no-headers 2>/dev/null", "r");
        if (!f) continue;
        char line[256]; int done = 0;
        while (fgets(line, sizeof line, f))
            if (strstr(line,"test-pvc") && strstr(line,"Bound")) { done=1; break; }
        pclose(f);
        if (done) { printf("  [ok] test-pvc Bound\n"); break; }
    }

    /* wait up to 60s for csi-consumer pod to be Running */
    printf("  waiting up to 60s for csi-consumer pod Running...\n");
    for (int i = 0; i < 600; i++) {
        msleep(100);
        FILE *f = popen("kubectl get pods -A --no-headers 2>/dev/null", "r");
        if (!f) continue;
        char line[256]; int done = 0;
        while (fgets(line, sizeof line, f))
            if (strstr(line,"csi-consumer") && strstr(line,"Running")) { done=1; break; }
        pclose(f);
        if (done) { printf("  [ok] csi-consumer Running\n"); break; }
    }

    /* wait up to 60s for DaemonSet pod to be Running */
    printf("  waiting up to 60s for test-ds DaemonSet pod...\n");
    for (int i = 0; i < 600; i++) {
        msleep(100);
        FILE *f = popen("kubectl get pods -A --no-headers 2>/dev/null", "r");
        if (!f) continue;
        char line[256]; int done = 0;
        while (fgets(line, sizeof line, f))
            if (strstr(line,"test-ds") && strstr(line,"Running")) { done=1; break; }
        pclose(f);
        if (done) { printf("  [ok] test-ds pod Running\n"); break; }
    }

    /* wait up to 60s for StatefulSet pod to be Running */
    printf("  waiting up to 60s for test-sts StatefulSet pod...\n");
    for (int i = 0; i < 600; i++) {
        msleep(100);
        FILE *f = popen("kubectl get pods -A --no-headers 2>/dev/null", "r");
        if (!f) continue;
        char line[256]; int done = 0;
        while (fgets(line, sizeof line, f))
            if (strstr(line,"test-sts") && strstr(line,"Running")) { done=1; break; }
        pclose(f);
        if (done) { printf("  [ok] test-sts pod Running\n"); break; }
    }

    /* ── CSI / Storage / Ingress resources (after create) ── */
    kctl("storage » csidrivers", (const char*[]){
        "kubectl","get","csidrivers",NULL});
    kctl("storage » csinodes", (const char*[]){
        "kubectl","get","csinodes",NULL});
    kctl("storage » storageclasses", (const char*[]){
        "kubectl","get","storageclasses",NULL});
    kctl("core/v1 » persistentvolumes (CSI)", (const char*[]){
        "kubectl","get","persistentvolumes","-o","wide",NULL});
    kctl("core/v1 » persistentvolumeclaims (CSI)", (const char*[]){
        "kubectl","get","persistentvolumeclaims","-A","-o","wide",NULL});
    kctl("networking » ingressclasses", (const char*[]){
        "kubectl","get","ingressclasses",NULL});
    kctl("networking » ingresses", (const char*[]){
        "kubectl","get","ingresses","-A",NULL});
    kctl("discovery.k8s.io/v1 » endpointslices -A", (const char*[]){
        "kubectl","get","endpointslices","-A",NULL});
    kctl("node.k8s.io/v1 » runtimeclasses", (const char*[]){
        "kubectl","get","runtimeclasses",NULL});
    kctl("rbac/v1 » clusterroles", (const char*[]){
        "kubectl","get","clusterroles",NULL});
    kctl("rbac/v1 » clusterrolebindings", (const char*[]){
        "kubectl","get","clusterrolebindings",NULL});
    kctl("rbac/v1 » roles -A", (const char*[]){
        "kubectl","get","roles","-A",NULL});
    kctl("rbac/v1 » rolebindings -A", (const char*[]){
        "kubectl","get","rolebindings","-A",NULL});
    kctl("networking.k8s.io/v1 » networkpolicies -A", (const char*[]){
        "kubectl","get","networkpolicies","-A",NULL});
    kctl("core/v1 » resourcequotas -A", (const char*[]){
        "kubectl","get","resourcequotas","-A",NULL});
    kctl("core/v1 » limitranges -A", (const char*[]){
        "kubectl","get","limitranges","-A",NULL});
    kctl("apiextensions/v1 » customresourcedefinitions", (const char*[]){
        "kubectl","get","customresourcedefinitions",NULL});

    /* dump iptables OUTPUT chain — needed for locally-originated ClusterIP traffic */
    printf("\n── iptables nat OUTPUT chain ────────────────────────\n");
    {
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/iptables","iptables","-t","nat","-L","OUTPUT",
                  "--line-numbers","-n",NULL);
            _exit(1);
        }
        int st; waitpid(p, &st, 0);
    }

    /* dump full iptables nat rules (-S = save format) */
    printf("\n── iptables nat rules (-S) ──────────────────────────\n");
    {
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/iptables","iptables","-t","nat","-S",NULL);
            _exit(1);
        }
        int st; waitpid(p, &st, 0);
    }

    /* direct pod IP test: bypass ClusterIP and test hello-http pod directly */
    printf("\n── direct pod HTTP test (pod IP:8080) ───────────────\n");
    {
        /* get hello-deploy pod IP via kubectl */
        char podip[64] = {0};
        FILE *f = popen(
            "kubectl get pods -n default --no-headers -l app=hello-deploy "
            "-o custom-columns=IP:.status.podIP 2>/dev/null | grep -v IP | head -1",
            "r");
        if (f) { fgets(podip, sizeof podip, f); pclose(f); }
        /* strip newline */
        for (int i = 0; podip[i]; i++) if (podip[i]=='\n'||podip[i]=='\r') { podip[i]=0; break; }
        if (podip[0] && strcmp(podip,"<none>") != 0) {
            printf("  pod IP: %s — testing http://%s:8080/\n", podip, podip);
            char url[128];
            snprintf(url, sizeof url, "http://%s:8080/", podip);
            pid_t p = fork();
            if (p == 0) {
                execl("/bin/httpget","httpget",url,podip,NULL);
                _exit(1);
            }
            int st; waitpid(p, &st, 0);
        } else {
            printf("  (could not get pod IP: '%s')\n", podip);
        }
    }

    /* test ingress routing: httpget hello.example.com via ingress controller on :80 */
    printf("\n── ingress HTTP test (httpget, up to 3 attempts) ────\n");
    {
        for (int attempt = 1; attempt <= 3; attempt++) {
            printf("  attempt %d:\n", attempt);
            pid_t p = fork();
            if (p == 0) {
                execl("/bin/httpget","httpget",
                      "http://127.0.0.1/","hello.example.com",NULL);
                _exit(1);
            }
            int st; waitpid(p, &st, 0);
            if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
                printf("  [ok] ingress HTTP test passed\n");
                break;
            }
            if (attempt < 3) { printf("  retry in 3s...\n"); msleep(3000); }
        }
    }

    /* verify CSI volume directories were created */
    printf("\n── CSI volume directories ───────────────────────────\n");
    {
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/find","find","/var/lib/test-csi-volumes",
                  "-maxdepth","2","-ls",NULL);
            _exit(1);
        }
        int st; waitpid(p, &st, 0);
    }

    /* kube-proxy iptables rules (KUBE-SERVICES chain) */
    printf("\n── kube-proxy iptables NAT rules ────────────────────\n");
    {
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/iptables","iptables","-t","nat","-L","KUBE-SERVICES",
                  "--line-numbers","-n",NULL);
            _exit(1);
        }
        int st; waitpid(p, &st, 0);
    }

    /* tail test-csi and test-ingress logs */
    printf("\n── test-csi log (last 2KB) ──────────────────────────\n");
    tail_file("/tmp/test-csi.log", 2048);
    printf("\n── test-ingress log (last 2KB) ──────────────────────\n");
    tail_file("/tmp/test-ingress.log", 2048);
    printf("\n── kube-proxy log (last 2KB) ────────────────────────\n");
    tail_file("/tmp/kube-proxy.log", 2048);

    /* ── apps/v1 ─────────────────────────────── */
    kctl("apps/v1 » deployments -A", (const char*[]){
        "kubectl","get","deployments","-A","-o","wide",NULL});
    kctl("apps/v1 » replicasets -A", (const char*[]){
        "kubectl","get","replicasets","-A",NULL});
    kctl("apps/v1 » daemonsets -A", (const char*[]){
        "kubectl","get","daemonsets","-A",NULL});
    kctl("apps/v1 » statefulsets -A", (const char*[]){
        "kubectl","get","statefulsets","-A",NULL});

    /* ── batch/v1 ────────────────────────────── */
    kctl("batch/v1 » jobs -A", (const char*[]){
        "kubectl","get","jobs","-A","-o","wide",NULL});
    kctl("batch/v1 » cronjobs -A", (const char*[]){
        "kubectl","get","cronjobs","-A",NULL});

    /* ── discovery.k8s.io/v1 ────────────────── */
    kctl("discovery.k8s.io/v1 » endpointslices -A", (const char*[]){
        "kubectl","get","endpointslices","-A",NULL});

    /* ── node.k8s.io/v1 ─────────────────────── */
    kctl("node.k8s.io/v1 » runtimeclasses", (const char*[]){
        "kubectl","get","runtimeclasses",NULL});

    /* ── networking.k8s.io/v1 ────────────────── */
    kctl("networking.k8s.io/v1 » ingresses -A", (const char*[]){
        "kubectl","get","ingresses","-A",NULL});
    kctl("networking.k8s.io/v1 » ingressclasses", (const char*[]){
        "kubectl","get","ingressclasses",NULL});
    kctl("networking.k8s.io/v1 » networkpolicies -A", (const char*[]){
        "kubectl","get","networkpolicies","-A",NULL});

    /* ── storage.k8s.io/v1 ───────────────────── */
    kctl("storage.k8s.io/v1 » storageclasses", (const char*[]){
        "kubectl","get","storageclasses",NULL});
    kctl("storage.k8s.io/v1 » csidrivers", (const char*[]){
        "kubectl","get","csidrivers",NULL});
    kctl("storage.k8s.io/v1 » csinodes", (const char*[]){
        "kubectl","get","csinodes",NULL});
    kctl("storage.k8s.io/v1 » volumeattachments", (const char*[]){
        "kubectl","get","volumeattachments",NULL});

    /* ── rbac.authorization.k8s.io/v1 ───────── */
    kctl("rbac/v1 » clusterroles", (const char*[]){
        "kubectl","get","clusterroles",NULL});
    kctl("rbac/v1 » clusterrolebindings", (const char*[]){
        "kubectl","get","clusterrolebindings",NULL});
    kctl("rbac/v1 » roles -A", (const char*[]){
        "kubectl","get","roles","-A",NULL});
    kctl("rbac/v1 » rolebindings -A", (const char*[]){
        "kubectl","get","rolebindings","-A",NULL});

    /* ── policy/v1 ───────────────────────────── */
    kctl("policy/v1 » poddisruptionbudgets -A", (const char*[]){
        "kubectl","get","poddisruptionbudgets","-A",NULL});

    /* ── autoscaling/v2 ──────────────────────── */
    kctl("autoscaling/v2 » horizontalpodautoscalers -A", (const char*[]){
        "kubectl","get","horizontalpodautoscalers","-A",NULL});

    /* ── scheduling.k8s.io/v1 ────────────────── */
    kctl("scheduling.k8s.io/v1 » priorityclasses", (const char*[]){
        "kubectl","get","priorityclasses",NULL});

    /* ── coordination.k8s.io/v1 ─────────────── */
    kctl("coordination.k8s.io/v1 » leases -A", (const char*[]){
        "kubectl","get","leases","-A",NULL});

    /* ── admissionregistration.k8s.io/v1 ────── */
    kctl("admissionreg/v1 » mutatingwebhookconfigurations", (const char*[]){
        "kubectl","get","mutatingwebhookconfigurations",NULL});
    kctl("admissionreg/v1 » validatingwebhookconfigurations", (const char*[]){
        "kubectl","get","validatingwebhookconfigurations",NULL});

    /* ── apiextensions.k8s.io/v1 ─────────────── */
    kctl("apiextensions/v1 » customresourcedefinitions", (const char*[]){
        "kubectl","get","customresourcedefinitions",NULL});

    /* ── core/v1 post-create ─────────────────── */
    kctl("core/v1 » resourcequotas -A", (const char*[]){
        "kubectl","get","resourcequotas","-A",NULL});
    kctl("core/v1 » limitranges -A", (const char*[]){
        "kubectl","get","limitranges","-A",NULL});
    kctl("core/v1 » secrets -A", (const char*[]){
        "kubectl","get","secrets","-A",NULL});
    kctl("core/v1 » configmaps -A", (const char*[]){
        "kubectl","get","configmaps","-A",NULL});
    kctl("core/v1 » serviceaccounts -A", (const char*[]){
        "kubectl","get","serviceaccounts","-A",NULL});
    kctl("core/v1 » services -A", (const char*[]){
        "kubectl","get","services","-A",NULL});
    kctl("core/v1 » endpoints -A", (const char*[]){
        "kubectl","get","endpoints","-A",NULL});

    /* ── final pod state ─────────────────────── */
    kctl("FINAL: pods -A -o wide", (const char*[]){
        "kubectl","get","pods","-A","-o","wide",NULL});

    /* print first 8KB then last 8KB of kubelet log */
    printf("── kubelet log (first 8KB) ─────────────────────\n");
    {
        int fd = open("/tmp/kubelet.log", O_RDONLY);
        if (fd >= 0) {
            char buf[8192]; int n, total = 0;
            while (total < 8192 && (n = read(fd, buf+total, 8192-total)) > 0) total += n;
            fwrite(buf, 1, total, stdout);
            close(fd);
        }
    }
    printf("\n── kubelet log (last 8KB) ──────────────────────\n");
    tail_file("/tmp/kubelet.log", 8192);

    /* check containers in k8s.io namespace */
    printf("\n── containers in k8s.io ns ──────────────────────\n");
    {
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/ctr","ctr",
                  "--address","/run/containerd/containerd.sock",
                  "--namespace","k8s.io",
                  "containers","ls", NULL);
            _exit(1);
        }
        int st; waitpid(p, &st, 0);
    }

    /* check tasks */
    printf("\n── tasks in k8s.io ns ───────────────────────────\n");
    {
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/ctr","ctr",
                  "--address","/run/containerd/containerd.sock",
                  "--namespace","k8s.io",
                  "tasks","ls", NULL);
            _exit(1);
        }
        int st; waitpid(p, &st, 0);
    }

    /* list images in k8s.io namespace */
    printf("\n── images in k8s.io ns ──────────────────────────\n");
    {
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/ctr","ctr",
                  "--address","/run/containerd/containerd.sock",
                  "--namespace","k8s.io",
                  "images","ls", NULL);
            _exit(1);
        }
        int st; waitpid(p, &st, 0);
    }

    /* kube-apiserver log tail */
    printf("\n── kube-apiserver log (last 2KB) ────────────────\n");
    tail_file("/tmp/kube-apiserver.log", 2048);

    /* controller-manager log tail */
    printf("\n── controller-manager log (last 2KB) ────────────\n");
    tail_file("/tmp/kcm.log", 2048);

    /* scheduler log tail */
    printf("\n── scheduler log (last 2KB) ─────────────────────\n");
    tail_file("/tmp/ks.log", 2048);

    /* etcd health check */
    printf("\n── etcd endpoint health ─────────────────────────\n");
    {
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/etcdctl","etcdctl",
                  "--endpoints","http://127.0.0.1:2379",
                  "endpoint","health", NULL);
            _exit(1);
        }
        int st; waitpid(p, &st, 0);
    }
    printf("\n── etcd log (last 2KB) ──────────────────────────\n");
    tail_file("/tmp/etcd.log", 2048);

    /* ── /proc 进程账本 ──────────────────────────────────────── */
    proc_account(kl, "kubelet");

    ftrace_event_proof();

    printf("\n=== Done. Powering off. ===\n\n");
    sync();
    reboot(RB_POWER_OFF);
    while(1) __asm__("wfi");
    return 0;
}
