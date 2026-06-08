#include <stdio.h>
#include <string.h>

/*
 * Minimal iptables stub for CNI bridge ipMasq support.
 *
 * CNI calls iptables to manage MASQUERADE rules. Since we have no
 * real libxtables/libmnl, we fake the calls so CNI's iptables
 * library thinks operations succeed.
 *
 * Key behaviors:
 *  --version / -V  → print version string and exit 0
 *  -C / --check    → exit 1  (rule not found → CNI will append it)
 *  -L <chain>      → exit 1  (chain not found → CNI will create it)
 *  everything else → exit 0  (success)
 *
 * No real netfilter rules are installed. Pods get CNI IPs and routes,
 * but cross-host masquerade is absent (fine for local QEMU testing).
 */
int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0 ||
            strcmp(argv[i], "-V") == 0) {
            puts("iptables v1.8.10 (stub)");
            return 0;
        }
        /* -C / --check: rule not found → return 1 */
        if (strcmp(argv[i], "-C") == 0 ||
            strcmp(argv[i], "--check") == 0) {
            return 1;
        }
        /* -L with a specific chain argument: chain not found → return 1 */
        if ((strcmp(argv[i], "-L") == 0 ||
             strcmp(argv[i], "--list") == 0) && i + 1 < argc) {
            /* check the next arg is a chain name, not a flag */
            if (argv[i+1][0] != '-') return 1;
        }
    }
    return 0;
}
