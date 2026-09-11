use strict;
use warnings;
use Test::More;

use Rex::Rancher::K8s;

# _nvidia_device_plugin_daemonset_spec is a pure function: it returns the
# NVIDIA device-plugin DaemonSet as a plain hashref, which
# deploy_nvidia_device_plugin then hands to $api->new_object(DaemonSet => %{...}).
# It builds no client and touches nothing remote, so it is testable offline —
# no cluster, no kubeconfig, no network, no Kubernetes::REST mock. This guards
# the manifest's load-bearing fields against silent drift; it is the only part
# of K8s.pm reachable without a live API server.

my $version = 'v0.17.0';
my $ds = Rex::Rancher::K8s::_nvidia_device_plugin_daemonset_spec($version);

is($ds->{metadata}{name}, 'nvidia-device-plugin-daemonset',
  'DaemonSet name');
is($ds->{metadata}{namespace}, 'kube-system',
  'deployed into kube-system');

my $pod = $ds->{spec}{template}{spec};

is($pod->{containers}[0]{image},
  "nvcr.io/nvidia/k8s-device-plugin:$version",
  'image tag interpolates the passed version');

is($pod->{runtimeClassName}, 'nvidia',
  'runtimeClassName nvidia — uses the NVIDIA container runtime to enumerate devices');
is($pod->{priorityClassName}, 'system-node-critical',
  'priorityClassName system-node-critical — scheduled under resource pressure');

is_deeply($pod->{tolerations},
  [{ key => 'nvidia.com/gpu', operator => 'Exists', effect => 'NoSchedule' }],
  'tolerates the nvidia.com/gpu:NoSchedule taint');

is_deeply($pod->{containers}[0]{env},
  [{ name => 'FAIL_ON_INIT_ERROR', value => 'false' }],
  'FAIL_ON_INIT_ERROR=false — starts even if CDI/driver init is incomplete');

my $sc = $pod->{containers}[0]{securityContext};
is(ref $sc->{allowPrivilegeEscalation}, 'SCALAR',
  'allowPrivilegeEscalation is a scalar ref (serialises as a YAML/JSON boolean)');
is(${ $sc->{allowPrivilegeEscalation} }, 0,
  'allowPrivilegeEscalation is false');
is_deeply($sc->{capabilities}, { drop => ['ALL'] },
  'all capabilities dropped');

is($pod->{containers}[0]{volumeMounts}[0]{mountPath},
  '/var/lib/kubelet/device-plugins',
  'device-plugin socket dir mounted');
is($pod->{volumes}[0]{hostPath}{path},
  '/var/lib/kubelet/device-plugins',
  'backed by the kubelet device-plugins hostPath');

# The version is the only thing that varies; a different tag must flow through.
my $pinned = Rex::Rancher::K8s::_nvidia_device_plugin_daemonset_spec('v9.9.9');
is($pinned->{spec}{template}{spec}{containers}[0]{image},
  'nvcr.io/nvidia/k8s-device-plugin:v9.9.9',
  'a custom version reaches the image tag');

done_testing;
