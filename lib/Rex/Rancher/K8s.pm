# ABSTRACT: Kubernetes API operations for Rex::Rancher (device plugin, readiness)

package Rex::Rancher::K8s;
our $VERSION = '0.005';
use v5.14.4;
use warnings;

use Kubernetes::REST::Kubeconfig;
use Rex::Logger;
use Rex::Rancher::Distribution;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  control_plane_version
  deploy_amd_device_plugin
  deploy_nvidia_device_plugin
  wait_for_api
  untaint_node
);

use constant DEVICE_PLUGIN_VERSION => 'v0.17.0';

# ROCm's Kubernetes device plugin, release v1.31.0.11 (2026-09-14):
# https://github.com/ROCm/k8s-device-plugin/releases/tag/v1.31.0.11
# The DaemonSets are built after the manifests at that tag:
# https://github.com/ROCm/k8s-device-plugin/blob/v1.31.0.11/k8s-ds-amdgpu-dp.yaml
# https://github.com/ROCm/k8s-device-plugin/blob/v1.31.0.11/k8s-ds-amdgpu-labeller.yaml
# the device plugin's securityContext after the Helm chart of the same repo,
# amd-gpu-helm 0.22.0 (values.yaml securityContext):
# https://github.com/ROCm/k8s-device-plugin/releases/tag/amd-gpu-helm-0.22.0
# Images on Docker Hub, amd64 only: rocm/k8s-device-plugin:<version> and
# rocm/k8s-device-plugin:labeller-<version> (the manifests use them untagged
# and as labeller-latest).
use constant AMD_DEVICE_PLUGIN_VERSION => '1.31.0.11';

=method wait_for_api(%opts)

Wait for the Kubernetes API server to become reachable by polling
C<list(Node)> via L<Kubernetes::REST>. Runs from the local machine — no
SSH connection to the cluster is needed.

Polls up to 60 times with a 5-second delay between attempts (5-minute
total timeout). Returns C<1> as soon as the API responds, or C<0> if it
does not respond within the timeout.

Required options:

=over

=item C<kubeconfig>

Path to the kubeconfig file saved locally. This file must have the
real server address (not C<127.0.0.1>) — L<Rex::Rancher/rancher_deploy_server>
patches the address automatically.

=back

  wait_for_api(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

=cut

sub wait_for_api {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";

  Rex::Logger::info("Waiting for Kubernetes API server...");

  for my $i (1..60) {
    my $up = eval {
      my $api = _api($kubeconfig);
      $api->list('Node');
      1;
    };
    if ($up) {
      Rex::Logger::info("  API server is up");
      return 1;
    }
    Rex::Logger::info("  Not responding yet, waiting... ($i/60)");
    sleep 5;
  }

  Rex::Logger::info("Kubernetes API server did not respond in time", "warn");
  return 0;
}

=method deploy_nvidia_device_plugin(%opts)

Deploy the NVIDIA Kubernetes device plugin DaemonSet to C<kube-system> and
wait for C<nvidia.com/gpu> capacity to appear on at least one node.

All operations run locally via L<Kubernetes::REST> — no C<kubectl> or SSH
to the cluster is needed.

The DaemonSet is created with:

=over

=item * C<runtimeClassName: nvidia> — uses the NVIDIA container runtime to
enumerate devices. With L<Rex::GPU>'s C<gpu_setup> it is registered by
L<Rex::GPU::NVIDIA/configure_containerd>; with C<gpu_setup =E<gt> 0> it must
come from the host (a preinstalled toolkit, see C<nvidia_runtime_path> in
L<Rex::Rancher/rancher_deploy_server>) or the GPU Operator's toolkit, which
RKE2/K3s pick up at service start along with the C<nvidia> RuntimeClass.

=item * C<priorityClassName: system-node-critical> — ensures the plugin
pod is scheduled even under resource pressure.

=item * A C<nvidia.com/gpu:NoSchedule> toleration — allows the pod to run
on nodes that still have the GPU taint.

=item * C<FAIL_ON_INIT_ERROR=false> — the plugin starts even if CDI or
driver initialisation fails, reporting partial GPU availability rather
than crash-looping.

=back

If the DaemonSet already exists it is updated (C<resourceVersion> is
fetched from the cluster before the update to satisfy the optimistic
concurrency requirement).

After applying, polls up to 24 times (2-minute timeout) for
C<nvidia.com/gpu> capacity to appear in any node's C<status.capacity>.
When it does not, a warning says so (no die), naming the API error of the
last attempt if that one failed (a 403, no connection).

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

Optional options:

=over

=item C<version>

NVIDIA device plugin image tag. Default: C<v0.17.0>.

=back

  deploy_nvidia_device_plugin(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

=cut

sub deploy_nvidia_device_plugin {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";
  my $version    = $opts{version} // DEVICE_PLUGIN_VERSION;

  Rex::Logger::info("Deploying NVIDIA device plugin $version...");

  my $api = _api($kubeconfig);

  _create_or_update($api, DaemonSet => _nvidia_device_plugin_daemonset_spec($version));

  Rex::Logger::info("  DaemonSet applied, waiting for GPU resources...");
  _wait_for_gpu_resource($api, 'nvidia.com/gpu');

  Rex::Logger::info("NVIDIA device plugin ready");
}

=method deploy_amd_device_plugin(%opts)

Deploy ROCm's Kubernetes device plugin for AMD GPUs
(L<https://github.com/ROCm/k8s-device-plugin>) as a DaemonSet to
C<kube-system> and wait for C<amd.com/gpu> capacity to appear on at least one
node. The counterpart of L</deploy_nvidia_device_plugin>, run the same way:
locally via L<Kubernetes::REST>, no C<kubectl> or SSH to the cluster.

The DaemonSet is upstream's C<k8s-ds-amdgpu-dp.yaml> of the pinned release,
with the image tag pinned instead of left out and the security context of
upstream's Helm chart (C<amd-gpu-helm> 0.22.0) instead of a privileged
container:

=over

=item * C<rocm/k8s-device-plugin:VERSION> with C<allowPrivilegeEscalation:
false> and all capabilities dropped, the kubelet's C<device-plugins>
directory and the host's C</sys> mounted.

=item * C<nodeSelector> C<kubernetes.io/arch: amd64>, as upstream ships it
(the images are amd64 only).

=item * C<priorityClassName: system-node-critical> and a
C<CriticalAddonsOnly> toleration.

=back

B<It runs on every amd64 node>, and on one without the C<amdgpu> driver
loaded the plugin exits, so its pod there stays in C<CrashLoopBackOff>. On a
cluster with such nodes pass C<affinity> (below).

No runtime class, CDI or containerd change is involved: the plugin hands the
kubelet C</dev/kfd> and the GPU's C</dev/dri/cardN> and C</dev/dri/renderDN>
for the pods that request C<amd.com/gpu> (one resource per GPU; ROCm's
C<single> naming), and the container images bring their own ROCm. The host
needs the C<amdgpu> kernel driver (L<Rex::GPU>'s C<gpu_setup>, when it sets
up AMD GPUs; see L<Rex::Rancher/GPU hardware support>). The device nodes keep
their host owner and group (C<video>, C<render>), so a pod that does not run
as root needs those groups as C<supplementalGroups>, or the nodes need K3s'
and RKE2's C<nonroot-devices> option, which Rex::Rancher does not set.

Every object already in the cluster is updated (C<resourceVersion> is
fetched before the update), as in L</deploy_nvidia_device_plugin>. Then it
polls up to 24 times (2-minute timeout) for C<amd.com/gpu> capacity in any
node's C<status.capacity>; when none appears, a warning says so (no die),
naming the API error of the last attempt if that one failed.

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

Optional options:

=over

=item C<version>

Image tag of the device plugin, and of the node labeller as
C<labeller-VERSION>. Default: C<1.31.0.11>.

=item C<node_labeller>

If true, also deploy upstream's node labeller (C<k8s-ds-amdgpu-labeller.yaml>
of the same release): the ClusterRole C<cr-node-labeller> (C<get>, C<list>,
C<watch>, C<update> on nodes), the ClusterRoleBinding C<labeller>, the
ServiceAccount C<node-labeller-sa> and the DaemonSet
C<amdgpu-labeller-daemonset> in C<kube-system>, which labels each node with
its AMD GPUs' VRAM, compute unit and SIMD count, device ID, family and
product name. It runs privileged with the host's C</dev> and C</sys>
(read-only) mounted, as upstream's manifest has it: it opens the GPU's
C</dev/dri> nodes. Default: C<0>; L<Rex::Rancher/rancher_deploy_server>
deploys the plugin without it.

=item C<affinity>

A pod C<affinity> (hashref, as in a pod spec) for the plugin's DaemonSet and
the labeller's, on top of the C<amd64> C<nodeSelector>. Default: none, which
is upstream's behaviour (every amd64 node, see above). With Node Feature
Discovery in the cluster, the AMD GPU nodes are those with one of its PCI
labels for vendor C<1002>; the terms of C<nodeSelectorTerms> are alternatives:

  # 0300 a Radeon, 0302 a 3D controller, 0380 an APU's GPU (e.g. gfx1151),
  # 1200 an Instinct MI355X (other Instinct models unverified)
  my @terms = map {
    +{ matchExpressions => [{
      key      => "feature.node.kubernetes.io/pci-${_}_1002.present",
      operator => 'In',
      values   => ['true'],
    }] }
  } qw( 0300 0302 0380 1200 );

  deploy_amd_device_plugin(
    kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml",
    affinity   => { nodeAffinity => {
      requiredDuringSchedulingIgnoredDuringExecution => { nodeSelectorTerms => \@terms },
    } },
  );

Anything but a hashref dies before the cluster is touched.

=back

  deploy_amd_device_plugin(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

=cut

sub deploy_amd_device_plugin {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";
  my $version    = $opts{version} // AMD_DEVICE_PLUGIN_VERSION;
  my $affinity   = $opts{affinity};
  die "affinity must be a hash reference (a pod spec's affinity)\n"
    if defined $affinity && ref $affinity ne 'HASH';

  Rex::Logger::info("Deploying AMD GPU device plugin $version...");

  my $api = _api($kubeconfig);

  _create_or_update($api, DaemonSet => _amd_device_plugin_daemonset_spec($version, $affinity));
  if ($opts{node_labeller}) {
    Rex::Logger::info("  Deploying the AMD GPU node labeller...");
    _create_or_update($api, @$_) for _amd_node_labeller_specs($version, $affinity);
  }

  Rex::Logger::info("  DaemonSet applied, waiting for GPU resources...");
  _wait_for_gpu_resource($api, 'amd.com/gpu');

  Rex::Logger::info("AMD GPU device plugin ready");
}

=method untaint_node(%opts)

Remove C<node-role.kubernetes.io/control-plane:NoSchedule> and
C<node-role.kubernetes.io/master:NoSchedule> taints from all nodes in the
cluster.

Kubernetes adds these taints to control-plane nodes to prevent general
workloads from being scheduled there. On single-node clusters (where the
control plane is also the only worker) these taints must be removed so that
pods can run.

Each node is fetched fresh before patching (to get the current
C<resourceVersion> for optimistic concurrency), and only patched if it
actually has one of the taints. Nodes that are already untainted are
skipped silently.

All operations run locally via L<Kubernetes::REST>.

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

  untaint_node(kubeconfig => "$ENV{HOME}/.kube/single-node.yaml");

=cut

sub untaint_node {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";

  Rex::Logger::info("Removing control-plane taints (single-node)...");

  my $api   = _api($kubeconfig);
  my $nodes = $api->list('Node');

  for my $node (@{ $nodes->items }) {
    my $name   = $node->metadata->name;
    my @taints = @{ $node->spec->taints // [] };
    my @keep   = grep {
      ($_->{key} // '') !~ /^node-role\.kubernetes\.io\/(control-plane|master)$/
    } @taints;

    next if @keep == @taints;  # nothing to remove

    my $fresh = $api->get('Node', $name);
    $fresh->spec->taints(\@keep);
    $api->update($fresh);
    Rex::Logger::info("  Untainted: $name");
  }
}

=method control_plane_version(%opts)

The Kubernetes version of the cluster's control plane, as the agent side of
the version skew policy needs it: the lowest C<kubeletVersion> among the
nodes labelled C<node-role.kubernetes.io/control-plane> (or C<master>) —
during a rolling server upgrade that is the server not yet upgraded — or,
without such nodes, the API server's C</version>. RKE2 and K3s report their
own release there (C<v1.30.4+rke2r1>). Nothing when neither gives a
version. Runs locally via L<Kubernetes::REST>; an API error dies.

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

  my $version = control_plane_version(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

=cut

sub control_plane_version {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";
  my $D = 'Rex::Rancher::Distribution';

  my $api = _api($kubeconfig);
  my @versions;
  for my $node (@{ $api->list('Node')->items }) {
    my $labels = $node->metadata->labels // {};
    next unless exists $labels->{'node-role.kubernetes.io/control-plane'}
      || exists $labels->{'node-role.kubernetes.io/master'};
    my $info = $node->status && $node->status->nodeInfo;
    my $version = $info && $info->kubeletVersion;
    my @parts = $D->parse_release($version);
    push @versions, $version if @parts;
  }
  my ($lowest) = sort { $D->compare_versions($a, $b) } @versions;
  return $lowest if defined $lowest;

  my $version = $api->cluster_version;
  my @parts = $D->parse_release($version);
  return @parts ? $version : ();
}

# ============================================================
#  Internal helpers
# ============================================================

sub _api {
  my ($kubeconfig) = @_;
  return Kubernetes::REST::Kubeconfig->new(
    kubeconfig_path => $kubeconfig,
  )->api;
}

# The nvidia-device-plugin DaemonSet as a plain hashref, split out verbatim
# from deploy_nvidia_device_plugin so its shape can be unit-tested offline —
# no cluster, no kubeconfig, no Kubernetes::REST client. $version is the only
# value that varies; the caller resolves the DEVICE_PLUGIN_VERSION default
# before calling. new_object(DaemonSet => %{ ... }) receives exactly the same
# named args as the previous inline literal.
sub _nvidia_device_plugin_daemonset_spec {
  my ($version) = @_;
  return {
    metadata => {
      name      => 'nvidia-device-plugin-daemonset',
      namespace => 'kube-system',
    },
    spec => {
      selector => {
        matchLabels => { name => 'nvidia-device-plugin-ds' },
      },
      updateStrategy => { type => 'RollingUpdate' },
      template => {
        metadata => {
          labels => { name => 'nvidia-device-plugin-ds' },
        },
        spec => {
          runtimeClassName  => 'nvidia',
          priorityClassName => 'system-node-critical',
          tolerations => [{
            key      => 'nvidia.com/gpu',
            operator => 'Exists',
            effect   => 'NoSchedule',
          }],
          containers => [{
            name  => 'nvidia-device-plugin-ctr',
            image => "nvcr.io/nvidia/k8s-device-plugin:$version",
            env   => [{
              name  => 'FAIL_ON_INIT_ERROR',
              value => 'false',
            }],
            securityContext => {
              allowPrivilegeEscalation => \0,
              capabilities            => { drop => ['ALL'] },
            },
            volumeMounts => [{
              name      => 'device-plugin',
              mountPath => '/var/lib/kubelet/device-plugins',
            }],
          }],
          volumes => [{
            name     => 'device-plugin',
            hostPath => { path => '/var/lib/kubelet/device-plugins' },
          }],
        },
      },
    },
  };
}

# ROCm's device plugin DaemonSet, upstream's k8s-ds-amdgpu-dp.yaml at the
# release AMD_DEVICE_PLUGIN_VERSION names, with three changes: the image
# carries the tag; the securityContext is the Helm chart's (amd-gpu-helm
# 0.22.0), not privileged: the plugin reads /sys, writes its socket to the
# kubelet's device-plugins directory and hands the kubelet the device nodes
# (/dev/kfd, /dev/dri/cardN, /dev/dri/renderDN) to put into the pods without
# opening them itself (the chart's extra /var/lib/amd-metrics-exporter mount
# is for its -pulse health checks, not used here); and $affinity, if given,
# is the pod affinity. A plain hashref like the NVIDIA one, so its shape is
# unit-tested offline. The caller resolves the version default.
sub _amd_device_plugin_daemonset_spec {
  my ($version, $affinity) = @_;
  return {
    metadata => {
      name      => 'amdgpu-device-plugin-daemonset',
      namespace => 'kube-system',
    },
    spec => {
      selector => {
        matchLabels => { name => 'amdgpu-dp-ds' },
      },
      template => {
        metadata => {
          labels => { name => 'amdgpu-dp-ds' },
        },
        spec => {
          restartPolicy     => 'Always',
          nodeSelector      => { 'kubernetes.io/arch' => 'amd64' },
          ( defined $affinity ? ( affinity => $affinity ) : () ),
          priorityClassName => 'system-node-critical',
          tolerations => [{
            key      => 'CriticalAddonsOnly',
            operator => 'Exists',
          }],
          containers => [{
            image => "rocm/k8s-device-plugin:$version",
            name  => 'amdgpu-dp-cntr',
            securityContext => {
              allowPrivilegeEscalation => \0,
              capabilities             => { drop => ['ALL'] },
            },
            volumeMounts => [
              { name => 'dp',  mountPath => '/var/lib/kubelet/device-plugins' },
              { name => 'sys', mountPath => '/sys' },
            ],
          }],
          volumes => [
            { name => 'dp',  hostPath => { path => '/var/lib/kubelet/device-plugins' } },
            { name => 'sys', hostPath => { path => '/sys' } },
          ],
        },
      },
    },
  };
}

# The node labeller, upstream's k8s-ds-amdgpu-labeller.yaml at the same
# release: [ kind => spec ] pairs in upstream's order. It stays privileged,
# as there ("Needed for /dev"): the chart's unprivileged variant may not open
# /dev/dri/* under runc's device cgroup, and the family and product-name
# labels go through libdrm. Changes: the image is labeller-$version, not
# labeller-latest, and so its imagePullPolicy Always is left out
# (Kubernetes' default for a tag other than latest is IfNotPresent; a pinned
# tag needs no pull on every pod start, which would tie each restart to
# Docker Hub); the ClusterRoleBinding loses upstream's namespace: default,
# which a cluster-scoped object does not have; $affinity, if given, is the
# pod affinity, as for the plugin.
sub _amd_node_labeller_specs {
  my ($version, $affinity) = @_;
  return (
    [ ClusterRole => {
      metadata => { name => 'cr-node-labeller' },
      rules    => [{
        apiGroups => [''],
        resources => ['nodes'],
        verbs     => [qw( watch get list update )],
      }],
    } ],
    [ ClusterRoleBinding => {
      metadata => { name => 'labeller' },
      roleRef  => {
        apiGroup => 'rbac.authorization.k8s.io',
        kind     => 'ClusterRole',
        name     => 'cr-node-labeller',
      },
      subjects => [{
        kind      => 'ServiceAccount',
        name      => 'node-labeller-sa',
        namespace => 'kube-system',
      }],
    } ],
    [ ServiceAccount => {
      metadata => { name => 'node-labeller-sa', namespace => 'kube-system' },
    } ],
    [ DaemonSet => {
      metadata => {
        name      => 'amdgpu-labeller-daemonset',
        namespace => 'kube-system',
      },
      spec => {
        selector => {
          matchLabels => { name => 'amdgpu-lr-ds' },
        },
        template => {
          metadata => {
            labels => { name => 'amdgpu-lr-ds' },
          },
          spec => {
            serviceAccountName => 'node-labeller-sa',
            nodeSelector       => { 'kubernetes.io/arch' => 'amd64' },
            ( defined $affinity ? ( affinity => $affinity ) : () ),
            priorityClassName  => 'system-node-critical',
            tolerations => [{
              key      => 'CriticalAddonsOnly',
              operator => 'Exists',
            }],
            containers => [{
              name       => 'amdgpu-lr-cntr',
              image      => "rocm/k8s-device-plugin:labeller-$version",
              workingDir => '/root',
              command    => ['./k8s-node-labeller'],
              args       => [qw( -vram -cu-count -simd-count -device-id -family -product-name )],
              env        => [{
                name      => 'DS_NODE_NAME',
                valueFrom => { fieldRef => { fieldPath => 'spec.nodeName' } },
              }],
              # Upstream: privileged is needed for /dev.
              securityContext => {
                privileged   => \1,
                capabilities => { drop => ['ALL'] },
              },
              volumeMounts => [
                { name => 'sys', mountPath => '/sys', readOnly => \1 },
                { name => 'dev', mountPath => '/dev' },
              ],
            }],
            volumes => [
              { name => 'sys', hostPath => { path => '/sys', type => 'Directory' } },
              { name => 'dev', hostPath => { path => '/dev', type => 'Directory' } },
            ],
          },
        },
      },
    } ],
  );
}

# Create the $kind object $spec describes or, where it already exists, update
# it with the cluster's resourceVersion (optimistic concurrency). Namespaced
# or cluster-scoped as $spec's metadata has it.
sub _create_or_update {
  my ($api, $kind, $spec) = @_;
  my $obj = $api->new_object($kind => %$spec);

  return $obj if eval { $api->create($obj); 1 };
  my $err = $@;
  die $err unless $err =~ /already exist/i;

  Rex::Logger::info("  $kind already exists, updating...");
  my $namespace = $spec->{metadata}{namespace};
  my $existing  = $api->get($kind, $spec->{metadata}{name},
    ( defined $namespace ? ( namespace => $namespace ) : () ));
  $obj->metadata->resourceVersion($existing->metadata->resourceVersion);
  $api->update($obj);
  return $obj;
}

# Poll for $resource (nvidia.com/gpu, amd.com/gpu) in any node's capacity.
sub _wait_for_gpu_resource {
  my ($api, $resource) = @_;

  # The error of the last attempt, if it failed: a 403 or a dead API reads
  # the same as a plugin that has not reported yet until the warning names it.
  my $last_error;
  for my $i (1..24) {
    my $found = eval {
      my $nodes = $api->list('Node');
      for my $node (@{ $nodes->items }) {
        my $cap = $node->status->capacity;
        if ($cap && $cap->{$resource} && $cap->{$resource} > 0) {
          Rex::Logger::info("  [ok] $resource: "
            . $cap->{$resource} . " on "
            . $node->metadata->name);
          return 1;  # returns 1 as value of the eval block
        }
      }
      0;
    };
    $last_error = $@ ? ( $@ =~ s/\s+\z//r ) : undef;
    return 1 if $found;  # exit the sub once GPU capacity is confirmed
    Rex::Logger::info("  No GPU capacity yet ($i/24), waiting...");
    sleep 5;
  }

  Rex::Logger::info("  $resource resource did not appear — check device plugin"
    . ( defined $last_error ? " (last API error: $last_error)" : '' ), "warn");
  return 0;
}

1;

=head1 SYNOPSIS

  use Rex::Rancher::K8s;

  # Wait for API to become available after cluster installation
  wait_for_api(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

  # Deploy NVIDIA device plugin and wait for gpu resource to appear
  deploy_nvidia_device_plugin(
    kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml",
    version    => 'v0.17.0',
  );

  # Deploy ROCm's device plugin for AMD GPUs, with its node labeller,
  # and wait for amd.com/gpu to appear
  deploy_amd_device_plugin(
    kubeconfig    => "$ENV{HOME}/.kube/mycluster.yaml",
    node_labeller => 1,
  );

  # Remove control-plane taints on a single-node cluster
  untaint_node(kubeconfig => "$ENV{HOME}/.kube/single.yaml");

=head1 DESCRIPTION

L<Rex::Rancher::K8s> provides Kubernetes API operations for L<Rex::Rancher>
using L<Kubernetes::REST> and L<IO::K8s>. All five public functions run
entirely on the B<local machine> against the cluster's HTTP API — no
C<kubectl> binary is required anywhere, and no SSH connection to the cluster
nodes is needed for these operations.

The module is used internally by L<Rex::Rancher/rancher_deploy_server> to:

=over

=item 1. Wait for the API server to respond after C<install_server> returns

=item 2. Deploy the NVIDIA device plugin, the AMD one, or both, when
C<gpu =E<gt> 1> (which one: L<Rex::Rancher/GPU hardware support>)

=back

L<Rex::Rancher::Agent/install_agent> uses L</control_plane_version> to keep
an agent from a newer minor version than the control plane.

It can also be used standalone for post-deploy operations such as removing
control-plane taints on single-node clusters.

=head2 No kubectl required

All Kubernetes API calls are made via L<Kubernetes::REST>, which implements
the Kubernetes REST API client in pure Perl using L<IO::K8s> for object
serialization. The kubeconfig file is parsed by
C<Kubernetes::REST::Kubeconfig> to extract the cluster address and
credentials.

=head1 SEE ALSO

L<Rex::Rancher>, L<Rex::GPU>, L<Kubernetes::REST>, L<IO::K8s>

=cut
