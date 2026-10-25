# Rex::Rancher House Rules

The shared house rules come from skilletor — bundle `getty-cpan-dist@getty`: engineering
discipline, the delegation lock, the publish gate, karr coordination, CPAN release. They load
as `.claude/rules/.local.*.md`; if they are missing, run `skilletor sync` and publish nothing
until they load. This file adds what is true only here, and wins where it differs.

## What this repo is

Rancher Kubernetes (RKE2/K3s) deployment automation for Rex. Pipeline invariants: skill
`rex-rancher-core`.

## Agent team

| Task | Agent |
|---|---|
| Implement / refactor / debug anything under `lib/` | `rex-rancher-worker` (default) |
| Commits, `Changes`, card → done, pre-release audit | `rex-rancher-release-manager` |
| Read-only research, audit, gap analysis | `rex-rancher-worker` ("read-only, change nothing") |

Behavior-relevant = anything under `lib/`, the tests, and any change to the pipeline step
order, an install command, an `auto_die` decision, the kubeconfig patch, a `config.yaml` key,
or a `K8s.pm` API object. `README.md` and `Changes` wording are not.

## Release

`Kubernetes::REST`, `IO::K8s` and `Rex::LibSSH` are Getty-authored; if pinned, pin to the
latest *released* CPAN version, never to an unreleased `$VERSION` in a local `~/dev` checkout.

## Hazards

- **The blast radius is a remote root shell driving a cluster.** Every install function runs
  an OS installer, `modprobe`, `swapoff` and `systemctl` on a remote host as root, then
  drives its Kubernetes API: a wrong step order or a swallowed error leaves a
  half-provisioned node, not a red test. The `auto_die => 0` sites are deliberate — don't
  tighten one without naming the failure it re-opens. Details: skill `rex-rancher-core`.
- **A green suite proves the pure logic, not a deploy.** `t/` holds a compile check
  (`t/00-load.t`) and offline unit tests with `run` faked; there is no integration test, and
  most of this dist can't be unit-tested. Never report green as evidence for a pipeline
  change: install ordering, the `127.0.0.1` kubeconfig patch and a `K8s.pm` object are only
  trustworthy after a real deploy — in practice through `kubernetes-ocp` (GPU only on
  citilan). There is no Hetzner test host; `eg/hetzner-gpu.Rexfile` is an example, not a test
  rig. Flag "unverified live" once per change; don't nag for a run every turn.

## Perl / Rex specifics — reference, don't restate

Perl house style and cpanfile pinning: skills `getty-perl-core`,
`getty-perl-release-author-getty`. Rex idioms and connection types: skill `rex`. RKE2/K3s,
Cilium and GPU domain knowledge: skills `kubernetes-rke2`, `kubernetes-cilium-concepts`,
`kubernetes-gpu`. This distribution's pipeline invariants: skill `rex-rancher-core`. All are
force-loaded for `rex-rancher-*` agents.
