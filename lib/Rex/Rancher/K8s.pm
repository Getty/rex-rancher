# ABSTRACT: Kubernetes API operations for Rex::Rancher (device plugin, readiness)

package Rex::Rancher::K8s;

use v5.14.4;
use warnings;

use Kubernetes::REST::Kubeconfig;
use Rex::Logger;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  deploy_nvidia_device_plugin
  wait_for_api
  untaint_node
);

use constant DEVICE_PLUGIN_VERSION => 'v0.17.0';

=method wait_for_api(%opts)

Wait for the Kubernetes API server to become reachable. Returns 1 when the
API is up, 0 if it did not respond within the timeout.

  wait_for_api(kubeconfig => '/path/to/kubeconfig');

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

Deploy the NVIDIA Kubernetes device plugin DaemonSet and wait for
C<nvidia.com/gpu> resources to appear on GPU nodes.

The DaemonSet is created with C<runtimeClassName: nvidia> so it can
enumerate GPUs without needing a privileged container.

Options:

  deploy_nvidia_device_plugin(
    kubeconfig => '/path/to/kubeconfig',
    version    => 'v0.17.0',           # optional, default: DEVICE_PLUGIN_VERSION
  );

=cut

sub deploy_nvidia_device_plugin {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";
  my $version    = $opts{version} // DEVICE_PLUGIN_VERSION;

  Rex::Logger::info("Deploying NVIDIA device plugin $version...");

  my $api = _api($kubeconfig);

  my $ds = $api->new_object(DaemonSet =>
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
  );

  eval { $api->create($ds) };
  if ($@) {
    if ($@ =~ /already exist/i) {
      Rex::Logger::info("  DaemonSet already exists, updating...");
      my $existing = $api->get('DaemonSet', 'nvidia-device-plugin-daemonset',
        namespace => 'kube-system');
      $ds->metadata->resourceVersion($existing->metadata->resourceVersion);
      $api->update($ds);
    }
    else {
      die $@;
    }
  }

  Rex::Logger::info("  DaemonSet applied, waiting for GPU resources...");
  _wait_for_gpu_resource($api);

  Rex::Logger::info("NVIDIA device plugin ready");
}

=method untaint_node(%opts)

Remove C<node-role.kubernetes.io/control-plane> and
C<node-role.kubernetes.io/master> taints from all nodes. Use this on
single-node clusters so that workloads can be scheduled on the control
plane.

  untaint_node(kubeconfig => '/path/to/kubeconfig');

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

# ============================================================
#  Internal helpers
# ============================================================

sub _api {
  my ($kubeconfig) = @_;
  return Kubernetes::REST::Kubeconfig->new(
    kubeconfig_path => $kubeconfig,
  )->api;
}

sub _wait_for_gpu_resource {
  my ($api) = @_;

  for my $i (1..24) {
    my $found = eval {
      my $nodes = $api->list('Node');
      for my $node (@{ $nodes->items }) {
        my $cap = $node->status->capacity;
        if ($cap && $cap->{'nvidia.com/gpu'} && $cap->{'nvidia.com/gpu'} > 0) {
          Rex::Logger::info("  [ok] nvidia.com/gpu: "
            . $cap->{'nvidia.com/gpu'} . " on "
            . $node->metadata->name);
          return 1;  # returns 1 as value of the eval block
        }
      }
      0;
    };
    return 1 if $found;  # exit the sub once GPU capacity is confirmed
    Rex::Logger::info("  No GPU capacity yet ($i/24), waiting...");
    sleep 5;
  }

  Rex::Logger::info("  nvidia.com/gpu resource did not appear — check device plugin", "warn");
  return 0;
}

1;

=head1 SYNOPSIS

  use Rex::Rancher::K8s;

  # Wait for API after cluster start
  wait_for_api(kubeconfig => '/etc/rancher/rke2/rke2.yaml');

  # Deploy NVIDIA device plugin
  deploy_nvidia_device_plugin(kubeconfig => '~/.kube/rexdemo.yaml');

=head1 DESCRIPTION

L<Rex::Rancher::K8s> provides Kubernetes API operations for L<Rex::Rancher>
using L<Kubernetes::REST> and L<IO::K8s>. All operations run from the local
machine against the cluster API — no C<kubectl> binary required on the remote
host.

Used internally by L<Rex::Rancher> to deploy the NVIDIA device plugin after
cluster setup when C<gpu =E<gt> 1> is passed to C<rancher_deploy_server>.

=head1 SEE ALSO

L<Rex::Rancher>, L<Rex::GPU>, L<Kubernetes::REST>, L<IO::K8s>

=cut
