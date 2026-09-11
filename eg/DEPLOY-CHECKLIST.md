# Live-deploy verification checklist

`t/` proves only that the six modules **compile** — nothing about a deploy.
There is no integration test and no way to fake one honestly (a mocked SSH /
mocked Kubernetes API "pass" would be a lie about cluster safety). So a change
to install ordering, the `127.0.0.1` kubeconfig patch, the Cilium/`config.yaml`
agreement, ports, service names, or a `K8s.pm` API object is only trustworthy
after this checklist runs **green against a real node**.

Run it with `eg/hetzner-gpu.Rexfile` on a throwaway host. **Run it for both
distributions when your change touches a path that differs between them** — a
half-change ships a cluster that only comes up on one.

```
rex -f eg/hetzner-gpu.Rexfile -I ../rex-gpu/lib -I lib -H <IP> deploy
rex -f eg/hetzner-gpu.Rexfile -H <IP> status      # local kubeconfig, no kubectl on host
```

API checks below prefer `rex ... status` (or the local kubeconfig via
`Kubernetes::REST`) because that is what the pipeline itself does — no `kubectl`
on the remote host, no kubeconfig on the operator's disk beyond what we wrote.
Host-level checks use plain SSH `run`.

## Where RKE2 and K3s differ (verify both)

| | RKE2 | K3s |
|---|---|---|
| server service | `rke2-server` | `k3s` |
| agent service | `rke2-agent.service` | `k3s-agent.service` |
| config dir | `/etc/rancher/rke2/` | `/etc/rancher/k3s/` |
| kubeconfig (remote) | `/etc/rancher/rke2/rke2.yaml` | `/etc/rancher/k3s/k3s.yaml` |
| node token | `/var/lib/rancher/rke2/server/node-token` | `/var/lib/rancher/k3s/server/node-token` |
| install URL | `https://get.rke2.io` | `https://get.k3s.io` |
| agent join port (`server:` URL) | **9345** | **6443** |
| API port | 6443 | 6443 |
| on-host kubectl | `/var/lib/rancher/rke2/bin/kubectl` (+ `KUBECONFIG`, no PATH set) | `k3s kubectl` / on PATH |
| containerd socket | `/run/k3s/containerd/containerd.sock` | `/run/k3s/containerd/containerd.sock` (same — RKE2 runs K3s agent code) |

---

## (a) Pre-connect host-key scan / first verified connect

The `before 'ALL'` hook calls `rancher_scan_known_hosts($host)` on the **local**
machine before Rex opens the SSH connection (Rex::LibSSH >= 0.004 verifies the
host key against `known_hosts`; a fresh Hetzner box has no entry).

- **Check (local):** `ssh-keygen -F <IP>` after the first task run.
  **Expect:** the key is present (exit 0).
- **Check:** the first `deploy`/`prepare` run connects.
  **Expect:** no `host key is not in known_hosts and strict_hostkeycheck is on`.
- **Check (idempotency):** run a second task; `known_hosts` is unchanged and no
  duplicate key line is appended.
- **Degrade path:** with `ssh-keyscan` absent or the host unreachable, the hook
  logs a `warn` and continues — the verified connect then surfaces the real
  error. It must never hard-fail the run itself.

## (b) `prepare_node` — OS prep

Verified on **Debian, Ubuntu, RHEL/Rocky/Alma** only. **openSUSE Leap / SLES is
unverified** (base packages fall through to Rex's generic `pkg`/zypper path and
have never run on real SUSE hardware) — do not report a SUSE run as evidence.

- **Swap off (precondition for kubelet):** `swapon --show` → empty; `free -h`
  swap total `0`. `/etc/fstab` has no active `swap` line.
- **Kernel modules:** `lsmod | grep -E '^(br_netfilter|overlay)'` → both loaded;
  `/etc/modules-load.d/kubernetes.conf` lists them (survives reboot).
- **Sysctl:** `sysctl net.ipv4.ip_forward net.bridge.bridge-nf-call-iptables
  net.bridge.bridge-nf-call-ip6tables` → all `= 1`. (The bridge keys only exist
  once `br_netfilter` is loaded — check this *after* the module check.)
- **NTP:** `timedatectl` shows NTP active, or `chronyc tracking` returns; chrony
  enabled + running.
- **Base packages:** `command -v curl` resolves; `ca-certificates` present.
- **Fresh-boot trap (Debian/Ubuntu):** in the run log, `apt-get update` ran
  after `unattended-upgrades`/`apt-daily*` were stopped, with no apt frontend
  lock error. A cold Hetzner boot is where this bites (`DPkg::Lock::Timeout`
  covers only the dpkg lock, not the frontend lock).

## (c) Optional GPU setup + reboot (`gpu => 1` only)

Runs before cluster bring-up via `Rex::GPU`. On a first deploy where `nouveau`
was loaded, `reboot => 1` is required.

- **Driver present:** `nvidia-smi` enumerates the GPU(s) **and** `libcuda.so` is
  in the linker cache (`ldconfig -p | grep libcuda`). Do not judge by package
  state — vendor images install outside the package namespace.
- **nouveau gone (after reboot):** `lsmod | grep nouveau` → empty.
- **Container toolkit + runtime:** `nvidia-ctk --version` works; the `nvidia`
  containerd runtime is configured and the `nvidia` RuntimeClass will exist in
  the cluster (used by stage h). RKE2's unit sets **no PATH**, so the runtime
  must be found by absolute path or via `/etc/default/rke2-server`.
- **Missing `Rex::GPU`:** with `gpu => 1` and the dist absent, the pipeline
  **dies with an install hint** at step (c) — GPU is an optional peer dist, so
  this die is correct, not a regression.

## (d) `install_server` — control-plane install (check BOTH distributions)

- **Service active:** RKE2 `systemctl is-active rke2-server` → `active`;
  K3s `systemctl is-active k3s` → `active`.
- **`config.yaml` written correctly** (`cat <config dir>/config.yaml`):
  - With `cilium => 1` (default): `cni: none` and `disable-kube-proxy: true`
    serialised as **real YAML booleans** (not `1`/`0` strings — this is the
    `YAML::PP boolean => 'JSON::PP'` contract).
  - `token:` set; `tls-san:` lists your SANs; `disable:` present.
  - Note the `disable:` list currently carries only `rke2-ingress-nginx` for
    both distributions; on K3s that entry is inert (Traefik/ServiceLB are turned
    off via the install flags `--disable=traefik --disable=servicelb`, not
    `config.yaml`). See the drift note under (g).
- **kubeconfig file appeared on remote:** RKE2 `test -f /etc/rancher/rke2/rke2.yaml`;
  K3s `test -f /etc/rancher/k3s/k3s.yaml`. (`install_server` waits only for this
  file — **not** for API readiness; that is stage f.)
- **Ports listening:** `ss -tlnp | grep -E ':6443|:9345'` → API `:6443` on both;
  supervisor `:9345` on RKE2. A K3s agent joins `:6443`, an RKE2 agent `:9345`.
- **RKE2 installer noise is not a failure:** the install script runs with
  `auto_die => 0` (it prints GPG key-import noise to STDERR on e.g. Rocky 10);
  success is confirmed by `command -v rke2`. In the run log, a non-zero installer
  exit followed by a found `rke2` binary is the expected, healthy path.
- **Middle state is not a failure:** with `cni: none` the node is `NotReady` and
  CoreDNS `Pending` until stage (g). Do **not** restart the service to "fix" it.

## (e) Kubeconfig fetched + patched to the real address

Only when `kubeconfig_file` is given (its absence silently skips this **and**
the device-plugin step, even under `gpu => 1`).

- **Server address patched:** `grep 'server:' <kubeconfig_file>` → the first
  `tls_san` (or `kubeconfig_server`), **not** `https://127.0.0.1`.
- **Ticket-#2 warning must be SILENT on a good run:** with a routable `tls_san`,
  the log must **not** contain `still points at https://127.0.0.1` or
  `is a loopback address`. If it does, your `tls_san`/`kubeconfig_server` is
  missing, mis-ordered, or loopback — the saved file cannot reach the cluster.
- **File saved:** `kubeconfig_file` exists locally and is readable.

## (f) `wait_for_api` — from the LOCAL machine

The real readiness gate: polls `list(Node)` over the cluster API via
`Kubernetes::REST` from the operator's machine (this is why stage e must run
first — the patched address is what it dials).

- **Check:** run log shows `API server is up` within the timeout (60 × 5 s).
- **Confirm:** `rex ... status` lists the node (may still be `NotReady` before
  Cilium — that is fine here).
- **Failure:** `did not respond in time` means the patched address/credentials
  are wrong, or the server never came up — not a `wait_for_api` bug by itself.

## (g) `install_cilium` — CNI healthy (check BOTH distributions)

- **Cilium healthy:** `KUBECONFIG=<remote kubeconfig> cilium status --brief` →
  `OK` (or `rex ... status` Cilium section). Agents/operator all green.
- **RKE2 — kube-proxy replacement:** `cilium status` shows
  `KubeProxyReplacement: True`; Helm values carry `kubeProxyReplacement: true`,
  `k8sServiceHost: 127.0.0.1`, `k8sServicePort: "6443"`, `cni.exclusive: false`.
  This must agree with `disable-kube-proxy: true` in `config.yaml` — the two
  halves together are what give the cluster working Service routing.
- **K3s:** Helm values set `cni.exclusive: true`, `operator.replicas: 1`.
- **⚠ Known divergence to verify on K3s:** `config.yaml` sets
  `disable-kube-proxy: true` for **both** distributions, but the K3s Cilium Helm
  values do **not** set `kubeProxyReplacement` (only RKE2 does). So on K3s,
  kube-proxy is disabled at the distro level while Cilium is not told to replace
  it. **Explicitly verify Service routing on K3s**: CoreDNS pods `Running`, and a
  `ClusterIP` Service is reachable from a pod (e.g. `nslookup kubernetes.default`
  succeeds). If routing is broken, that is the divergence, not your change —
  see the follow-up note at the end.
- **Node becomes Ready:** after Cilium, the node flips to `Ready` and CoreDNS
  schedules. `rex ... status` → node `Ready`.
- **Idempotency:** re-running `deploy` re-invokes `cilium install`; the
  `cannot re-use a name` output is swallowed and logged as `Cilium already
  installed` — the run continues. A re-run must not hard-fail here.

## (h) NVIDIA device plugin → `nvidia.com/gpu` allocatable (`gpu => 1` + kubeconfig)

- **Capacity present:** `rex ... status` shows `nvidia.com/gpu=N` (N > 0), i.e.
  it appears in the node's `status.capacity`/`allocatable`.
- **DaemonSet running:** the `nvidia-device-plugin-daemonset` in `kube-system`
  has a `Running` pod with `runtimeClassName: nvidia` (this is the manifest that
  `t/nvidia-device-plugin-spec.t` guards offline).
- **End-to-end proof:** schedule a pod with `runtimeClassName: nvidia` and
  `limits: { nvidia.com/gpu: 1 }` running `nvidia-smi` — it lists the GPU.
- **Empty capacity** means the plugin never started or found no driver (stage c),
  not a scheduling problem.
- **Idempotency:** re-deploy → the DaemonSet already exists → the code fetches
  its `resourceVersion` and `update`s (no `already exist` hard failure).

## (i) `untaint_node` — single-node scheduling

- **Taints gone:** the node no longer carries
  `node-role.kubernetes.io/control-plane:NoSchedule` or `.../master:NoSchedule`.
  Via `rex ... status` / the API: `spec.taints` no longer lists them.
- **Workloads schedule:** a plain pod (no GPU, no tolerations) reaches `Running`
  on the single node.
- **Idempotency:** an already-untainted node is skipped silently — re-running is
  a no-op, not an error.

---

## Gate

A pipeline change is trusted only when stages (a)–(f), (g), and (i) pass on a
real node — and, for a GPU change, (c) and (h) as well. Where your change
touches a path that differs between RKE2 and K3s, **both** must pass. Record the
distribution(s), OS, and GPU/non-GPU shape you actually ran; a green `prove -lr
t/` is compilation only and is **not** evidence for any of the above.
