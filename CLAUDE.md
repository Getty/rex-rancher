# Rex::Rancher

Rancher Kubernetes (RKE2/K3s) deployment automation for Rex.

## Module Structure

```
Rex::Rancher              — Main: rancher_deploy_server/agent (gpu => 1 optional)
Rex::Rancher::Node        — Node preparation (hostname, NTP, sysctl, swap, kernel modules)
Rex::Rancher::Server      — Control plane install (RKE2 + K3s)
Rex::Rancher::Agent       — Worker node join (RKE2 + K3s)
Rex::Rancher::Cilium      — Cilium CNI installation and upgrades
```

## GPU Support

GPU is optional. Pass `gpu => 1` and install `Rex-GPU` separately.
Without it, Rex::Rancher works for non-GPU nodes.

## Testing

```bash
prove -l t/
```

## Build

Uses `[@Author::GETTY]` Dist::Zilla plugin bundle.
