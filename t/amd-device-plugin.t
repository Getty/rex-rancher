use strict;
use warnings;
use Test::More;

# k95: deploy_amd_device_plugin puts ROCm's k8s-device-plugin (release
# v1.31.0.11) into kube-system the way deploy_nvidia_device_plugin puts
# NVIDIA's: typed objects through Kubernetes::REST, create or (already there)
# update with the cluster's resourceVersion, then the wait for amd.com/gpu.
# The node labeller and its RBAC only with node_labeller => 1.
#
# Offline: the specs are pure hashrefs, built through the real IO::K8s
# classes as the deploy does; the API client is a fake that records the
# calls. That the pinned images exist, that the plugin starts on an AMD node
# under this securityContext, and that amd.com/gpu shows up are only shown
# by a real deploy.

my $slept = 0;
BEGIN { *CORE::GLOBAL::sleep = sub { $slept++ } }

use IO::K8s;
use Rex::Rancher::K8s;

my ( @info, @warn );
{
  no warnings 'redefine';
  *Rex::Logger::info = sub { push @{ ( $_[1] // '' ) eq 'warn' ? \@warn : \@info }, $_[0] };
}

my $k8s     = IO::K8s->new;
my $version = '1.31.0.11';

is( Rex::Rancher::K8s::AMD_DEVICE_PLUGIN_VERSION(), $version, 'pinned release 1.31.0.11' );

# Builds through the typed classes and back, as Kubernetes::REST puts it on
# the wire: a field IO::K8s does not know, or a missing required one, dies here.
sub round_trip {
  my ( $kind, $spec, $label ) = @_;
  my $obj = eval { $k8s->new_object( $kind => %$spec ) };
  ok( $obj, "$label: new_object($kind) builds" ) or diag $@;
  my $struct = $obj && eval { $k8s->object_to_struct($obj) };
  ok( ref $struct eq 'HASH', "$label: object_to_struct round-trips" ) or diag $@;
  return $struct;
}

# --- the device plugin DaemonSet ---------------------------------------------

my $ds  = Rex::Rancher::K8s::_amd_device_plugin_daemonset_spec($version);
my $pod = $ds->{spec}{template}{spec};
my $ctr = $pod->{containers}[0];

is_deeply( $ds->{metadata}, { name => 'amdgpu-device-plugin-daemonset', namespace => 'kube-system' },
  'plugin: upstream name, kube-system' );
is_deeply( $ds->{spec}{selector}, { matchLabels => { name => 'amdgpu-dp-ds' } }, 'plugin: selector' );
is_deeply( $ds->{spec}{template}{metadata}, { labels => { name => 'amdgpu-dp-ds' } }, 'plugin: pod labels match' );
is( $ctr->{image}, 'rocm/k8s-device-plugin:1.31.0.11', 'plugin: image pinned to the release tag' );
is( $ctr->{name}, 'amdgpu-dp-cntr', 'plugin: container name' );
is( $pod->{restartPolicy}, 'Always', 'plugin: restartPolicy as upstream' );
is_deeply( $pod->{nodeSelector}, { 'kubernetes.io/arch' => 'amd64' }, 'plugin: amd64 only (images are amd64)' );
is( $pod->{priorityClassName}, 'system-node-critical', 'plugin: system-node-critical' );
is_deeply( $pod->{tolerations}, [ { key => 'CriticalAddonsOnly', operator => 'Exists' } ],
  'plugin: CriticalAddonsOnly toleration' );
ok( !exists $pod->{affinity}, 'plugin: no affinity unless given (upstream behaviour)' );
ok( !exists $pod->{runtimeClassName}, 'plugin: no runtime class (kubelet DeviceSpecs, no runtime)' );

# The Helm chart's (amd-gpu-helm 0.22.0) securityContext, not the raw
# manifest's privileged one.
my $sc = $ctr->{securityContext};
ok( !exists $sc->{privileged}, 'plugin: not privileged' );
is( ref $sc->{allowPrivilegeEscalation}, 'SCALAR', 'plugin: allowPrivilegeEscalation is a JSON boolean' );
is( ${ $sc->{allowPrivilegeEscalation} }, 0, 'plugin: allowPrivilegeEscalation false' );
is_deeply( $sc->{capabilities}, { drop => ['ALL'] }, 'plugin: all capabilities dropped' );

is_deeply( $ctr->{volumeMounts},
  [ { name => 'dp',  mountPath => '/var/lib/kubelet/device-plugins' },
    { name => 'sys', mountPath => '/sys' } ],
  'plugin: device-plugins socket dir and /sys mounted' );
is_deeply( $pod->{volumes},
  [ { name => 'dp',  hostPath => { path => '/var/lib/kubelet/device-plugins' } },
    { name => 'sys', hostPath => { path => '/sys' } } ],
  'plugin: hostPaths, no metrics-exporter health dir' );

is( Rex::Rancher::K8s::_amd_device_plugin_daemonset_spec('9.9.9')->{spec}{template}{spec}{containers}[0]{image},
  'rocm/k8s-device-plugin:9.9.9', 'plugin: a given version reaches the tag' );

my $ds_struct = round_trip( DaemonSet => $ds, 'plugin' );
is( $ds_struct->{spec}{template}{spec}{containers}[0]{securityContext}{allowPrivilegeEscalation} ? 1 : 0, 0,
  'plugin: allowPrivilegeEscalation serialises false' );

# --- the node labeller ---------------------------------------------------------

my @labeller = Rex::Rancher::K8s::_amd_node_labeller_specs($version);
is_deeply( [ map { $_->[0] } @labeller ], [qw( ClusterRole ClusterRoleBinding ServiceAccount DaemonSet )],
  'labeller: the four objects, upstream order' );
my %lab = map { $_->[0] => $_->[1] } @labeller;

is_deeply( $lab{ClusterRole},
  { metadata => { name => 'cr-node-labeller' },
    rules    => [ { apiGroups => [''], resources => ['nodes'], verbs => [qw( watch get list update )] } ] },
  'labeller: ClusterRole on nodes' );
is_deeply( $lab{ClusterRoleBinding},
  { metadata => { name => 'labeller' },
    roleRef  => { apiGroup => 'rbac.authorization.k8s.io', kind => 'ClusterRole', name => 'cr-node-labeller' },
    subjects => [ { kind => 'ServiceAccount', name => 'node-labeller-sa', namespace => 'kube-system' } ] },
  'labeller: ClusterRoleBinding, no namespace on the cluster-scoped object' );
is_deeply( $lab{ServiceAccount}, { metadata => { name => 'node-labeller-sa', namespace => 'kube-system' } },
  'labeller: ServiceAccount in kube-system' );

my $lds  = $lab{DaemonSet};
my $lpod = $lds->{spec}{template}{spec};
my $lctr = $lpod->{containers}[0];
is_deeply( $lds->{metadata}, { name => 'amdgpu-labeller-daemonset', namespace => 'kube-system' }, 'labeller: DaemonSet name' );
is_deeply( $lds->{spec}{selector}{matchLabels}, { name => 'amdgpu-lr-ds' }, 'labeller: selector' );
is( $lpod->{serviceAccountName}, 'node-labeller-sa', 'labeller: runs as its ServiceAccount' );
is_deeply( $lpod->{nodeSelector}, { 'kubernetes.io/arch' => 'amd64' }, 'labeller: amd64 only' );
is( $lctr->{image}, 'rocm/k8s-device-plugin:labeller-1.31.0.11', 'labeller: image pinned, not labeller-latest' );
ok( !exists $lctr->{imagePullPolicy}, 'labeller: no imagePullPolicy Always with a pinned tag' );
is( $lctr->{workingDir}, '/root', 'labeller: workingDir' );
is_deeply( $lctr->{command}, ['./k8s-node-labeller'], 'labeller: command' );
is_deeply( $lctr->{args}, [qw( -vram -cu-count -simd-count -device-id -family -product-name )], 'labeller: args' );
is_deeply( $lctr->{env},
  [ { name => 'DS_NODE_NAME', valueFrom => { fieldRef => { fieldPath => 'spec.nodeName' } } } ],
  'labeller: DS_NODE_NAME from the node name' );
is( ${ $lctr->{securityContext}{privileged} }, 1, 'labeller: privileged, as upstream ("Needed for /dev")' );
is_deeply( $lctr->{securityContext}{capabilities}, { drop => ['ALL'] }, 'labeller: capabilities dropped' );
is( ${ $lctr->{volumeMounts}[0]{readOnly} }, 1, 'labeller: /sys read-only' );
is_deeply( $lpod->{volumes},
  [ { name => 'sys', hostPath => { path => '/sys', type => 'Directory' } },
    { name => 'dev', hostPath => { path => '/dev', type => 'Directory' } } ],
  'labeller: /sys and /dev from the host' );

round_trip( @$_, 'labeller' ) for @labeller;

# --- affinity --------------------------------------------------------------------

# The example from the POD: Node Feature Discovery's PCI labels for AMD.
my @terms = map {
  +{ matchExpressions => [ {
    key      => "feature.node.kubernetes.io/pci-${_}_1002.present",
    operator => 'In',
    values   => ['true'],
  } ] }
} qw( 0300 0302 0380 1200 );
my $affinity = { nodeAffinity => {
  requiredDuringSchedulingIgnoredDuringExecution => { nodeSelectorTerms => \@terms },
} };

my $ads = Rex::Rancher::K8s::_amd_device_plugin_daemonset_spec( $version, $affinity );
is_deeply( $ads->{spec}{template}{spec}{affinity}, $affinity, 'affinity: on the plugin pods' );
is_deeply( $ads->{spec}{template}{spec}{nodeSelector}, { 'kubernetes.io/arch' => 'amd64' },
  'affinity: the amd64 nodeSelector stays' );
my $ads_struct = round_trip( DaemonSet => $ads, 'plugin with affinity' );
is( scalar @{ $ads_struct->{spec}{template}{spec}{affinity}{nodeAffinity}
  {requiredDuringSchedulingIgnoredDuringExecution}{nodeSelectorTerms} }, 4,
  'affinity: the four NFD terms survive the typed classes' );
my ($alds) = map { $_->[1] } grep { $_->[0] eq 'DaemonSet' }
  Rex::Rancher::K8s::_amd_node_labeller_specs( $version, $affinity );
is_deeply( $alds->{spec}{template}{spec}{affinity}, $affinity, 'affinity: on the labeller pods too' );
round_trip( DaemonSet => $alds, 'labeller with affinity' );

# --- deploy_amd_device_plugin against a fake API ----------------------------------

our ( @calls, %exists, $create_error );
{
  package FakeAPI;
  sub new        { bless {}, shift }
  sub _kind      { ( ref $_[0] ) =~ s/.*:://r }
  sub new_object { shift; IO::K8s->new->new_object(@_) }
  sub create {
    my ( $self, $obj ) = @_;
    my ( $kind, $name ) = ( _kind($obj), $obj->metadata->name );
    push @main::calls, "create $kind/$name";
    die $main::create_error if defined $main::create_error;
    die "create $kind failed: 409 Conflict: $name already exists\n" if $main::exists{$name};
    return $obj;
  }
  sub get {
    my ( $self, $kind, $name, %o ) = @_;
    push @main::calls, "get $kind/$name" . ( $o{namespace} ? " in $o{namespace}" : '' );
    return IO::K8s->new->new_object( ServiceAccount =>
      metadata => { name => $name, resourceVersion => "rv-$name" } );
  }
  sub update {
    my ( $self, $obj ) = @_;
    push @main::calls, 'update ' . _kind($obj) . '/' . $obj->metadata->name
      . ' at ' . $obj->metadata->resourceVersion;
    return $obj;
  }
  sub list {
    push @main::calls, 'list Node';
    return FakeList->new( IO::K8s->new->new_object( 'Node', metadata => { name => 'synapse' },
      status => { capacity => { 'amd.com/gpu' => 1 } } ) );
  }
  package FakeList;
  sub new   { my ( $c, @i ) = @_; bless { items => \@i }, $c }
  sub items { $_[0]{items} }
}

my @api_for;
{
  no warnings 'redefine';
  *Rex::Rancher::K8s::_api = sub { push @api_for, $_[0]; FakeAPI->new };
}

sub deploy {
  my (%o) = @_;
  ( @calls, @api_for, @info, @warn ) = ();
  return eval { Rex::Rancher::K8s::deploy_amd_device_plugin( kubeconfig => '/tmp/kc.yaml', %o ); 1 };
}

ok( deploy(), 'fresh cluster: deployed' ) or diag $@;
is_deeply( \@api_for, ['/tmp/kc.yaml'], '... through the given kubeconfig' );
is_deeply( \@calls, [ 'create DaemonSet/amdgpu-device-plugin-daemonset', 'list Node' ],
  '... the plugin only, then the wait' );
like( $info[0], qr/^Deploying AMD GPU device plugin 1\.31\.0\.11/, '... names the version' );
ok( grep( { /\[ok\] amd\.com\/gpu: 1 on synapse/ } @info ), '... and the node with amd.com/gpu' );
is_deeply( \@warn, [], '... no warning' );

ok( deploy( node_labeller => 1, version => '1.31.0.10' ), 'with node_labeller: deployed' ) or diag $@;
is_deeply( \@calls,
  [ 'create DaemonSet/amdgpu-device-plugin-daemonset',
    'create ClusterRole/cr-node-labeller',
    'create ClusterRoleBinding/labeller',
    'create ServiceAccount/node-labeller-sa',
    'create DaemonSet/amdgpu-labeller-daemonset',
    'list Node' ],
  '... plugin, then the labeller and its RBAC, then the wait' );
like( $info[0], qr/1\.31\.0\.10/, '... the given version' );

{
  local %exists = map { $_ => 1 }
    qw( amdgpu-device-plugin-daemonset cr-node-labeller labeller node-labeller-sa amdgpu-labeller-daemonset );
  ok( deploy( node_labeller => 1 ), 'all there already: deployed' ) or diag $@;
  is_deeply( \@calls,
    [ 'create DaemonSet/amdgpu-device-plugin-daemonset',
      'get DaemonSet/amdgpu-device-plugin-daemonset in kube-system',
      'update DaemonSet/amdgpu-device-plugin-daemonset at rv-amdgpu-device-plugin-daemonset',
      'create ClusterRole/cr-node-labeller',
      'get ClusterRole/cr-node-labeller',
      'update ClusterRole/cr-node-labeller at rv-cr-node-labeller',
      'create ClusterRoleBinding/labeller',
      'get ClusterRoleBinding/labeller',
      'update ClusterRoleBinding/labeller at rv-labeller',
      'create ServiceAccount/node-labeller-sa',
      'get ServiceAccount/node-labeller-sa in kube-system',
      'update ServiceAccount/node-labeller-sa at rv-node-labeller-sa',
      'create DaemonSet/amdgpu-labeller-daemonset',
      'get DaemonSet/amdgpu-labeller-daemonset in kube-system',
      'update DaemonSet/amdgpu-labeller-daemonset at rv-amdgpu-labeller-daemonset',
      'list Node' ],
    '... each updated at the resourceVersion the cluster has, cluster-scoped ones without namespace' );
}

{
  local $create_error = "create DaemonSet failed: 403 Forbidden\n";
  ok( !deploy(), 'any other create error: dies' );
  like( $@, qr/403 Forbidden/, '... with that error' );
  is_deeply( \@calls, ['create DaemonSet/amdgpu-device-plugin-daemonset'], '... nothing after it' );
}

ok( deploy( affinity => $affinity, node_labeller => 1 ), 'with affinity: deployed' ) or diag $@;
ok( !deploy( affinity => [] ), 'affinity not a hashref: dies' );
like( $@, qr/^affinity must be a hash reference/, '... saying so' );
is_deeply( \@api_for, [], '... before the cluster is touched' );

ok( !eval { Rex::Rancher::K8s::deploy_amd_device_plugin(); 1 }, 'no kubeconfig: dies' );
like( $@, qr/^kubeconfig required/, '... saying so' );

# Exported, and re-exported by Rex::Rancher like the NVIDIA one.
ok( grep( { $_ eq 'deploy_amd_device_plugin' } @Rex::Rancher::K8s::EXPORT ), 'exported by Rex::Rancher::K8s' );
require Rex::Rancher;
ok( grep( { $_ eq 'deploy_amd_device_plugin' } @Rex::Rancher::EXPORT ), 're-exported by Rex::Rancher' );

done_testing;
