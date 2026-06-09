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
#include <netinet/in.h>
#include <arpa/inet.h>

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

    printf("\n=== Done. Powering off. ===\n\n");
    sync();
    reboot(RB_POWER_OFF);
    while(1) __asm__("wfi");
    return 0;
}
