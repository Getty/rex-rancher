#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# k95: deploy_amd_device_plugin puts ROCm's k8s-device-plugin (release
# v1.31.0.11) into kube-system the way deploy_nvidia_device_plugin puts
# NVIDIA's: typed objects through Kubernetes::REST, create or (already there)
# update with the cluster's resourceVersion, then the wait for amd.com/gpu.
# The node labeller and its RBAC only with node_labeller => 1.
#
# k101: the plugin's start command spelled out (the image has no
# Entrypoint), resource_naming single|mixed as -resource_naming_strategy,
# wait => 0, and deploy_amd_node_labeller: the labeller on its own, with an
# affinity of its own, through the same code as node_labeller => 1.
# Validation dies before the kubeconfig is opened.
#
# Offline: the specs are pure hashrefs, built through the real IO::K8s
# classes as the deploy does; the API client is a fake that records the
# calls. That the pinned images exist, that the plugin starts on an AMD node
# under this securityContext, and that amd.com/gpu shows up are only shown
# by a real deploy.
#
# k106: the wait reads the node's allocatable, not its capacity, which the
# kubelet keeps after the plugin is gone.

my $slept = 0;
BEGIN { *CORE::GLOBAL::sleep = sub { $slept++ } }

use IO::K8s;
use JSON::MaybeXS ();
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

my $ds  = Rex::Rancher::K8s::_amd_device_plugin_daemonset_spec( $version, 'single' );
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

is( Rex::Rancher::K8s::_amd_device_plugin_daemonset_spec( '9.9.9', 'single' )->{spec}{template}{spec}{containers}[0]{image},
  'rocm/k8s-device-plugin:9.9.9', 'plugin: a given version reaches the tag' );

# --- the plugin's start command (k101) -------------------------------------------
#
# The image config of rocm/k8s-device-plugin:1.31.0.11 (registry config blob
# sha256:c425a3af..., Dockerfile at the tag): no Entrypoint, only this Cmd,
# WorkingDir /root/. Setting args alone replaced that Cmd, and the container
# died with exec "-resource_naming_strategy=single": executable file not
# found (kubernetes-ocp, live on synapse, 2026-10-31).
my @IMAGE_CMD = qw( ./k8s-device-plugin -logtostderr=true -stderrthreshold=INFO -v=5 );
my @LOG_FLAGS = @IMAGE_CMD[ 1 .. 3 ];

# What the container runs, by Kubernetes' rule for command and args against
# an image without Entrypoint: command given, command + args; args alone,
# args (they take the place of the Cmd); neither, the Cmd.
sub argv_of {
  my ($ctr) = @_;
  return @{ $ctr->{command} }, @{ $ctr->{args} // [] } if $ctr->{command};
  return @{ $ctr->{args} } if $ctr->{args};
  return @IMAGE_CMD;
}

is_deeply( $ctr->{command}, ['./k8s-device-plugin'], 'plugin: command is the binary' );
is( $ctr->{workingDir}, '/root', 'plugin: workingDir /root, where ./k8s-device-plugin is' );
unlike( $ctr->{args}[0], qr/k8s-device-plugin/, 'plugin: args do not start with the binary' );
is_deeply( [ @{ $ctr->{args} }[ 0 .. 2 ] ], \@LOG_FLAGS, "plugin: args keep the image Cmd's log flags" );
is( $ctr->{args}[-1], '-resource_naming_strategy=single', 'plugin: then the naming strategy' );
is_deeply( [ argv_of($ctr) ], [ @IMAGE_CMD, '-resource_naming_strategy=single' ],
  'plugin: runs the image Cmd plus the naming strategy' );

# Counter-check of the rule above: args alone would run the first flag.
my @args_only = argv_of( { args => [ @LOG_FLAGS, '-resource_naming_strategy=single' ] } );
isnt( $args_only[0], './k8s-device-plugin', 'counter-check: args alone do not run the binary' );
is( $args_only[0], '-logtostderr=true', '... but the first flag as the program' );
is_deeply( [ argv_of( {} ) ], \@IMAGE_CMD, 'counter-check: neither runs the image Cmd' );

my $mixed = Rex::Rancher::K8s::_amd_device_plugin_daemonset_spec( $version, 'mixed' );
is_deeply( [ argv_of( $mixed->{spec}{template}{spec}{containers}[0] ) ],
  [ @IMAGE_CMD, '-resource_naming_strategy=mixed' ], 'plugin, mixed: the strategy reaches the flag' );
round_trip( DaemonSet => $mixed, 'plugin mixed' );

is_deeply( [ Rex::Rancher::K8s::AMD_RESOURCE_NAMINGS() ], [qw( single mixed )],
  'resource namings: what ParseStrategy knows at 1.31.0.11' );

my $ds_struct = round_trip( DaemonSet => $ds, 'plugin' );
is( $ds_struct->{spec}{template}{spec}{containers}[0]{securityContext}{allowPrivilegeEscalation} ? 1 : 0, 0,
  'plugin: allowPrivilegeEscalation serialises false' );
is_deeply( [ argv_of( $ds_struct->{spec}{template}{spec}{containers}[0] ) ],
  [ @IMAGE_CMD, '-resource_naming_strategy=single' ], 'plugin: command and args survive the typed classes' );
is( $ds_struct->{spec}{template}{spec}{containers}[0]{workingDir}, '/root', '... and workingDir' );

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

# --- the host's network ------------------------------------------------------------
#
# Both pods run in the host's network namespace: a hostNetwork pod gets no
# CNI ADD, so on a freshly joined node amd.com/gpu and the labels do not
# wait for the CNI's cold start (kubernetes-ocp on synapse, 2026-10-31: some
# 5.5 minutes after the Cilium agent was Ready no new pod sandbox came up).
# dnsPolicy Default, not ClusterFirstWithHostNet: neither resolves a name,
# and CoreDNS waits for the CNI itself. That the pods do start before the
# CNI on a fresh node only a real deploy shows.
my $lds_struct = round_trip( DaemonSet => $lds, 'labeller DaemonSet' );
for (
  [ plugin   => $ds,  $ds_struct ],
  [ labeller => $lds, $lds_struct ],
) {
  my ( $who, $spec, $struct ) = @$_;
  my $p = $spec->{spec}{template}{spec};
  is( ref $p->{hostNetwork}, 'SCALAR', "$who: hostNetwork is a JSON boolean" );
  is( ${ $p->{hostNetwork} }, 1, "$who: hostNetwork true" );
  is( $p->{dnsPolicy}, 'Default', "$who: dnsPolicy Default, the host's DNS" );

  my $sp = $struct->{spec}{template}{spec};
  ok( JSON::MaybeXS::is_bool( $sp->{hostNetwork} ) && $sp->{hostNetwork},
    "$who: hostNetwork survives the typed classes as boolean true" );
  is( $sp->{dnsPolicy}, 'Default', '... and dnsPolicy Default' );
  my $json = $k8s->object_to_json( $k8s->new_object( DaemonSet => %$spec ) );
  like( $json, qr/"hostNetwork":true[,}]/, '... sent as "hostNetwork":true' );
  like( $json, qr/"dnsPolicy":"Default"/, '... and "dnsPolicy":"Default"' );
}

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

my $ads = Rex::Rancher::K8s::_amd_device_plugin_daemonset_spec( $version, 'single', $affinity );
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

# %allocatable: what the one node offers; its capacity is the same, plus
# %capacity (the node of a plugin that is gone keeps its capacity, k106).
# @created: [ kind, struct ] of every object sent to create.
our ( @calls, @created, %exists, $create_error, %allocatable, %capacity );
%allocatable = ( 'amd.com/gpu' => 1 );
{
  package FakeAPI;
  sub new        { bless {}, shift }
  sub _kind      { ( ref $_[0] ) =~ s/.*:://r }
  sub new_object { shift; IO::K8s->new->new_object(@_) }
  sub create {
    my ( $self, $obj ) = @_;
    my ( $kind, $name ) = ( _kind($obj), $obj->metadata->name );
    push @main::calls, "create $kind/$name";
    push @main::created, [ $kind, IO::K8s->new->object_to_struct($obj) ];
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
      status => {
        capacity    => { %main::allocatable, %main::capacity },
        allocatable => { %main::allocatable },
      } ) );
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
  ( @calls, @created, @api_for, @info, @warn ) = ();
  $slept = 0;
  return eval { Rex::Rancher::K8s::deploy_amd_device_plugin( kubeconfig => '/tmp/kc.yaml', %o ); 1 };
}

sub deploy_labeller {
  my (%o) = @_;
  ( @calls, @created, @api_for, @info, @warn ) = ();
  return eval { Rex::Rancher::K8s::deploy_amd_node_labeller( kubeconfig => '/tmp/kc.yaml', %o ); 1 };
}

# The container args of the plugin DaemonSet the last deploy created.
sub plugin_args {
  my ($ds) = map { $_->[1] } grep { $_->[0] eq 'DaemonSet' && $_->[1]{metadata}{name} =~ /device-plugin/ } @created;
  return $ds->{spec}{template}{spec}{containers}[0]{args};
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
my @sent_ds = map { $_->[1] } grep { $_->[0] eq 'DaemonSet' } @created;
is( scalar @sent_ds, 2, '... two DaemonSets sent' );
for my $sent (@sent_ds) {
  my $p = $sent->{spec}{template}{spec};
  ok( JSON::MaybeXS::is_bool( $p->{hostNetwork} ) && $p->{hostNetwork}
      && ( $p->{dnsPolicy} // '' ) eq 'Default',
    "... $sent->{metadata}{name} sent with hostNetwork true, dnsPolicy Default" );
}

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

# --- resource_naming (k101) -----------------------------------------------------

ok( deploy(), 'resource_naming unset: deployed' ) or diag $@;
is( plugin_args()->[-1], '-resource_naming_strategy=single', '... single, always spelled out' );

ok( deploy( resource_naming => 'single' ), 'resource_naming single: deployed' ) or diag $@;
is( plugin_args()->[-1], '-resource_naming_strategy=single', '... single' );
ok( grep( { /\[ok\] amd\.com\/gpu: 1 on synapse/ } @info ), '... waits for amd.com/gpu' );

{
  # A partitioned Instinct under mixed: amd.com/<compute>_<memory>, no amd.com/gpu.
  local %allocatable = ( 'amd.com/cpx_nps4' => 8, 'cpu' => 32 );
  ok( deploy( resource_naming => 'mixed' ), 'resource_naming mixed: deployed' ) or diag $@;
  is( plugin_args()->[-1], '-resource_naming_strategy=mixed', '... mixed reaches the flag' );
  ok( grep( { /\[ok\] amd\.com\/cpx_nps4: 8 on synapse/ } @info ), '... the wait takes the partition resource' );
  is_deeply( \@warn, [], '... no warning' );
  is( $slept, 0, '... at the first poll' );

  ok( deploy( resource_naming => 'single' ), 'the same node under single' ) or diag $@;
  is( $slept, 24, '... waits for amd.com/gpu only, the full two minutes' );
  like( $warn[0], qr/^  amd\.com\/gpu resource did not appear/, '... and warns about amd.com/gpu' );
}
{
  local %allocatable = ( 'amd.com/gpu' => 1 );
  ok( deploy( resource_naming => 'mixed' ), 'mixed on a GPU without partitions' ) or diag $@;
  ok( grep( { /\[ok\] amd\.com\/gpu: 1 on synapse/ } @info ), '... amd.com/gpu counts too' );
}
{
  local %allocatable = ( 'nvidia.com/gpu' => 2 );
  ok( deploy( resource_naming => 'mixed' ), 'mixed, only nvidia.com/gpu on the node' ) or diag $@;
  like( $warn[0], qr/^  amd\.com\/\* resource did not appear/, '... warns, naming the amd.com/ prefix' );
}

for my $bad ( 'Single', 'none', '', ' mixed', 'mixed ', [ 'mixed' ] ) {
  my $shown = ref $bad ? 'an array ref' : "'$bad'";
  ok( !deploy( resource_naming => $bad ), "resource_naming $shown: dies" );
  like( $@, qr/^resource_naming must be one of single, mixed, not /, '... saying which values are known' );
  is_deeply( \@api_for, [], '... before the cluster is touched' );
}

# --- wait (k101) ----------------------------------------------------------------

ok( deploy( wait => 0 ), 'wait => 0: deployed' ) or diag $@;
is_deeply( \@calls, ['create DaemonSet/amdgpu-device-plugin-daemonset'], '... no list Node, no wait' );
ok( grep( { /not waiting for GPU resources \(wait => 0\)/ } @info ), '... says it does not wait' );
ok( !grep( { /device plugin ready/ } @info ), '... and does not claim the plugin is ready' );

ok( deploy( wait => 0, node_labeller => 1 ), 'wait => 0 with node_labeller' ) or diag $@;
is( $calls[-1], 'create DaemonSet/amdgpu-labeller-daemonset', '... the labeller is still deployed, then nothing' );

ok( deploy( wait => 1 ), 'wait => 1: deployed' ) or diag $@;
is( $calls[-1], 'list Node', '... waits' );

{
  # k106, seen on synapse: a redeploy after the plugin was gone. The node
  # keeps capacity amd.com/gpu 1; allocatable is 0 until the plugin registers.
  local %allocatable = ( 'amd.com/gpu' => 0 );
  local %capacity    = ( 'amd.com/gpu' => 1 );
  ok( deploy(), 'capacity 1, allocatable 0: deployed' ) or diag $@;
  ok( !grep( { /\[ok\]/ } @info ), '... no [ok] for the capacity left behind' );
  is( $slept, 24, '... waits the full two minutes' );
  like( $warn[0], qr/^  amd\.com\/gpu resource did not appear/, '... and warns' );
}

# --- deploy_amd_node_labeller (k101) ---------------------------------------------

ok( deploy_labeller(), 'labeller alone: deployed' ) or diag $@;
is_deeply( \@api_for, ['/tmp/kc.yaml'], '... through the given kubeconfig' );
is_deeply( \@calls,
  [ 'create ClusterRole/cr-node-labeller',
    'create ClusterRoleBinding/labeller',
    'create ServiceAccount/node-labeller-sa',
    'create DaemonSet/amdgpu-labeller-daemonset' ],
  '... its four objects, no plugin, no wait' );
like( $info[0], qr/^Deploying AMD GPU node labeller 1\.31\.0\.11/, '... names the version' );
is_deeply( \@warn, [], '... no warning' );

my $own = { nodeAffinity => { requiredDuringSchedulingIgnoredDuringExecution => { nodeSelectorTerms => [
  { matchExpressions => [ { key => 'ocp.internal/amd-gpu.present', operator => 'In', values => ['true'] } ] },
] } } };
ok( deploy_labeller( affinity => $own, version => '1.31.0.10' ), 'labeller with its own affinity and version' ) or diag $@;
my ($lab_ds) = map { $_->[1] } grep { $_->[0] eq 'DaemonSet' } @created;
is_deeply( $lab_ds->{spec}{template}{spec}{affinity}, $own, '... the affinity on its pods' );
is( $lab_ds->{spec}{template}{spec}{containers}[0]{image}, 'rocm/k8s-device-plugin:labeller-1.31.0.10',
  '... the version on its image' );

# node_labeller => 1 sends exactly what deploy_amd_node_labeller does.
deploy_labeller( affinity => $affinity );
my @alone = @created;
deploy( affinity => $affinity, node_labeller => 1 );
my @with_plugin = grep { $_->[1]{metadata}{name} !~ /device-plugin/ } @created;
is_deeply( \@with_plugin, \@alone, 'node_labeller => 1: the same four objects as deploy_amd_node_labeller' );
is( scalar @alone, 4, '... four of them' );

{
  local %exists = map { $_ => 1 } qw( cr-node-labeller labeller node-labeller-sa amdgpu-labeller-daemonset );
  ok( deploy_labeller(), 'labeller there already: deployed' ) or diag $@;
  is( scalar( grep { /^update / } @calls ), 4, '... each of the four updated' );
}

ok( !deploy_labeller( affinity => 'every node' ), 'labeller, affinity not a hashref: dies' );
like( $@, qr/^affinity must be a hash reference/, '... saying so' );
is_deeply( \@api_for, [], '... before the cluster is touched' );

ok( !eval { Rex::Rancher::K8s::deploy_amd_node_labeller(); 1 }, 'labeller, no kubeconfig: dies' );
like( $@, qr/^kubeconfig required/, '... saying so' );

# Exported, and re-exported by Rex::Rancher like the NVIDIA one; the
# functions its pipeline does not call are not re-exported.
ok( grep( { $_ eq 'deploy_amd_device_plugin' } @Rex::Rancher::K8s::EXPORT ), 'exported by Rex::Rancher::K8s' );
require Rex::Rancher;
ok( grep( { $_ eq 'deploy_amd_device_plugin' } @Rex::Rancher::EXPORT ), 're-exported by Rex::Rancher' );
for my $f (qw( deploy_amd_node_labeller remove_amd_device_plugin remove_amd_node_labeller )) {
  ok( grep( { $_ eq $f } @Rex::Rancher::K8s::EXPORT ), "$f exported by Rex::Rancher::K8s" );
  ok( !grep( { $_ eq $f } @Rex::Rancher::EXPORT ), "... not re-exported by Rex::Rancher" );
}

done_testing;
