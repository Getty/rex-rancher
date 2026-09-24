# Rex::Rancher

[Rex](https://www.rexify.org/) automation for deploying [RKE2](https://docs.rke2.io/) and [K3s](https://k3s.io/) Kubernetes clusters — with optional GPU support and [Cilium](https://cilium.io/) CNI.

## What it does

Handles the full lifecycle of a Rancher-based Kubernetes deployment from a Rex task:

- **Node preparation** — hostname, timezone, swap off, kernel modules, sysctl
- **Control plane installation** — RKE2 or K3s via official install scripts
- **Agent/worker node joining** — joins nodes to an existing cluster
- **Cilium CNI** — installs Cilium by default (`cilium => 0` keeps the distribution's own CNI); kube-proxy replacement on RKE2
- **GPU support** — NVIDIA driver + Container Toolkit + CDI + device plugin (via [Rex::GPU](https://metacpan.org/pod/Rex::GPU))
- **Registry mirrors** — configures `registries.yaml` for private pull-through caches
- **Local kubeconfig management** — fetches and patches kubeconfig for external access

## Synopsis

```perl
use Rex -feature => ['1.4'];
use Rex::LibSSH;
use Rex::Rancher;

set connection => 'LibSSH';

# Deploy a single-node RKE2 cluster with GPU support
task 'deploy_server', 'gpu-node.example.com', sub {
    rancher_deploy_server(
        distribution  => 'rke2',
        token         => 'my-cluster-secret',
        tls_san       => ['lb.example.com', '10.0.0.1'],
        gpu           => 1,
        kubeconfig_file => "$ENV{HOME}/.kube/mycluster.yaml",
    );
};

# Join worker nodes
task 'deploy_agents', group => 'workers', sub {
    rancher_deploy_agent(
        distribution => 'rke2',
        token        => 'my-cluster-secret',
        server       => 'https://first-server:9345',
    );
};
```

## Modules

| Module | Purpose |
|--------|---------|
| `Rex::Rancher` | Top-level: `rancher_deploy_server`, `rancher_deploy_agent`, `rancher_scan_known_hosts` (re-exports `wait_for_api`, `untaint_node`, `deploy_nvidia_device_plugin`) |
| `Rex::Rancher::Server` | Control plane install, kubeconfig/token retrieval |
| `Rex::Rancher::Agent` | Worker node join |
| `Rex::Rancher::Node` | Node preparation (kernel, swap, modules) |
| `Rex::Rancher::Cilium` | Cilium CNI installation |
| `Rex::Rancher::K8s` | Local Kubernetes API ops (device plugin, readiness wait) |

## Requirements

`Rex::LibSSH` is required for Hetzner and other SFTP-less servers:

```perl
use Rex::LibSSH;
set connection => 'LibSSH';
```

`Rex::GPU` is required only when using `gpu => 1` with the default `gpu_setup => 1`; with `gpu_setup => 0` (e.g. the NVIDIA GPU Operator provides driver and toolkit) it is not needed, and `gpu_device_plugin => 0` skips the device plugin as well. With newer `Rex::GPU` versions, the GPU generation decides both whether a GPU gets a driver and which one: every Maxwell-or-newer GPU does, consumer and laptop cards (GeForce MX, GT 1030, GTX 9xx, laptop RTX) included, so a re-deploy with `gpu => 1` on such a node now installs the driver and, with `reboot => 1`, reboots it. Kepler and older GPUs are skipped with a warning; a Kepler-only node deploys without `nvidia.com/gpu`, and the device-plugin step ends with a warning. Conflicting GPU mixes such as V100 + B200 and a missing package source for the required driver make the deploy die after node preparation, before the driver or Kubernetes is installed; so does an NVIDIA vGPU guest (Azure NVadsA10 v5, AWS G6f, ...) without an already working licensed vGPU driver, even next to a passed-through GPU. HGX B200/B300 nodes get the driver plus a warning that the NVLink fabric (Fabric Manager, `nvlsm`, OFED, kernel >= 5.17) is not set up by `Rex::GPU`, GB200/GB300 an `nvidia-imex` hint — see "GPU hardware support" in the `Rex::Rancher` POD.

**Verifying a deploy:** `prove -lr t/` runs a compile check and offline unit tests only — there is no integration test. To trust a pipeline change, deploy a real node with [`eg/hetzner-gpu.Rexfile`](eg/hetzner-gpu.Rexfile).

### Supported / verified distributions

RKE2 is the verified, supported distribution. K3s is implemented but
**unverified** on real hosts (`install_server` warns about it).

Verified on Debian, Ubuntu, and RHEL/Rocky. openSUSE Leap / SLES is
**unverified and unsupported** — node preparation there relies on Rex's
generic `pkg` abstraction (zypper) and has never been exercised on real
SUSE hardware, so treat it as best-effort only.

### Host-key verification on fresh hosts

`Rex::LibSSH` >= 0.004 verifies the server host key against your `known_hosts`
(a CWE-322 fix; earlier versions never checked). A freshly-installed Hetzner
box has no entry, so the first connect fails with `host key is not in
known_hosts and strict_hostkeycheck is on`. Seed the key before connecting —
the exported `rancher_scan_known_hosts($host)` runs `ssh-keyscan` locally and
appends it, which **keeps** verification on instead of disabling it. Because
Rex opens the connection before the task body runs, wire it into a pre-connect
`before 'ALL'` hook (see `eg/hetzner-gpu.Rexfile`):

```perl
before 'ALL' => sub {
    my ($server) = @_;
    rancher_scan_known_hosts($server);
};
```

## Installation

```
cpanm Rex::Rancher
```

Or from this repository:

```
cpanm --installdeps .
dzil build
cpanm Rex-Rancher-*.tar.gz
```

## See Also

- [Rex::LibSSH](https://metacpan.org/pod/Rex::LibSSH)
- [Rex::GPU](https://metacpan.org/pod/Rex::GPU)
- [Rex](https://metacpan.org/pod/Rex)
- [RKE2 documentation](https://docs.rke2.io/)
- [K3s documentation](https://docs.k3s.io/)

## Author

Torsten Raudssus `<getty@cpan.org>`

## License

This software is copyright (c) 2026 by Torsten Raudssus. This is free software; you can redistribute it and/or modify it under the same terms as the Perl 5 programming language system itself.
