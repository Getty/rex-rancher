use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# Offline tests for Rex::Rancher::Cilium.
#
# 1. Helm values: the per-distribution defaults are unchanged, caller values
#    deep-merge over them, gateway_api adds gatewayAPI.enabled, and k3s gets
#    kube-proxy replacement at the control plane address (never loopback)
#    with its pool on k3s' cluster-cidr, as kubernetes-ocp k178.
# 2. Release handling: Helm's release Secrets decode to status, chart version
#    and values, and _release_action turns that into install / noop / upgrade
#    / reinstall (or dies where acting could take down a working network).
# 3. The re-run case the old "cannot re-use a name" swallow covered: an
#    existing release at the requested version is a no-op, not a failure --
#    both with a kubeconfig (decided from the release) and without one (the
#    swallow is kept there).
#
# `run`, `file` and the Kubernetes::REST client are faked, so no host or
# cluster is involved. This proves decision logic and command strings, not a
# deploy.
# -----------------------------------------------------------------------------

use IO::Compress::Gzip qw( gzip );
use IO::K8s;
use JSON::MaybeXS;
use MIME::Base64 qw( encode_base64 );
use Rex::Rancher::Cilium;

$Rex::Logger::silent = 1;

my $C = 'Rex::Rancher::Cilium';
my $T = JSON()->true;
my $F = JSON()->false;

# -----------------------------------------------------------------------------
# Fakes: remote shell and local API
# -----------------------------------------------------------------------------

my ( @cmds, %files );
our $run_hook;
{
  no warnings 'redefine';
  *Rex::Rancher::Cilium::run = sub {
    my ( $cmd ) = @_;
    push @cmds, $cmd;
    if ( $cmd =~ /^cilium version --client/ ) { $? = 0; return 'cilium-cli: v0.16.23' }
    if ( $run_hook ) { my @r = $run_hook->( $cmd ); return $r[0] if @r }
    $? = 0;
    return '';
  };
  *Rex::Rancher::Cilium::file = sub { my ( $path, %o ) = @_; $files{$path} = $o{content} };
}

my $k8s = IO::K8s->new;

# Helm stores: base64(gzip(json)); the Secret's data is base64 of that again.
sub helm_secret {
  my ( %a ) = @_;
  my $json = encode_json( {
    name   => 'cilium',
    chart  => { metadata => { name => 'cilium', version => $a{chart_version} } },
    config => $a{config} // {},
  } );
  gzip( \$json => \my $gz );
  my $helm = encode_base64( $gz, '' );
  return {
    name    => 'sh.helm.release.v1.cilium.v'.$a{revision},
    labels  => { owner => 'helm', name => 'cilium', status => $a{status}, version => $a{revision} },
    release => encode_base64( $helm, '' ),
  };
}

{
  package FakeAPI;
  sub new { my ( $class, %a ) = @_; bless { %a, deleted => [], patched => [] }, $class }
  sub list {
    my ( $self ) = @_;
    my @items = map {
      $k8s->struct_to_object( {
        apiVersion => 'v1', kind => 'Secret',
        metadata   => { name => $_->{name}, namespace => 'kube-system', labels => $_->{labels} },
        data       => { release => $_->{release} },
      } )
    } @{ $self->{secrets} // [] };
    return bless { items => \@items }, 'FakeList';
  }
  sub get {
    my ( $self, $kind, $name ) = @_;
    my $obj = $self->{objects}{"$kind/$name"};
    return $obj->() if ref $obj eq 'CODE';
    return $obj if $obj;
    return $self->{daemonset} ? bless( {}, 'FakeObj' ) : die "404 not found\n"
      if $kind eq 'DaemonSet';
    die "404 not found\n";
  }
  sub delete { my ( $self, $kind, $name ) = @_; push @{ $self->{deleted} }, "$kind/$name"; 1 }
  sub patch  { my ( $self, $kind, $name ) = @_; push @{ $self->{patched} }, "$kind/$name"; 1 }
  package FakeList;
  sub items { $_[0]{items} }
}

my $api;
{
  no warnings 'redefine';
  *Rex::Rancher::Cilium::_api = sub { $api };
}

sub values_for { $C->can('_resolve_opts')->( @_ )->{values} }

# -----------------------------------------------------------------------------
# 1. Helm values
# -----------------------------------------------------------------------------

subtest 'rke2 defaults unchanged' => sub {
  my $v = values_for( distribution => 'rke2' );
  is_deeply( $v, {
    cni => { binPath => '/opt/cni/bin', confPath => '/etc/cni/net.d', exclusive => $F },
    ipam                 => { mode => 'kubernetes' },
    operator             => { replicas => 1 },
    kubeProxyReplacement => $T,
    k8sServiceHost       => '127.0.0.1',
    k8sServicePort       => '6443',
  }, 'same values the old heredoc wrote' );
  my $yaml = Rex::Rancher::Cilium::_helm_values_yaml($v);
  like( $yaml, qr/^k8sServicePort: '6443'$/m, 'port stays a YAML string' );
  like( $yaml, qr/^  exclusive: false$/m,     'exclusive is a YAML boolean' );
  like( $yaml, qr/^kubeProxyReplacement: true$/m, 'kubeProxyReplacement boolean' );
  ok( !exists $v->{gatewayAPI}, 'gateway API off by default' );
};

subtest 'k3s: kube-proxy replacement at the control plane, pool = cluster-cidr' => sub {
  my $v = values_for( distribution => 'k3s', k8s_service_host => '203.0.113.7' );
  is_deeply( $v, {
    cni => { binPath => '/opt/cni/bin', confPath => '/etc/cni/net.d', exclusive => $T },
    ipam => {
      mode     => 'cluster-pool',
      operator => { clusterPoolIPv4PodCIDRList => ['10.42.0.0/16'] },
    },
    operator             => { replicas => 1 },
    kubeProxyReplacement => $T,
    k8sServiceHost       => '203.0.113.7',
    k8sServicePort       => '6443',
  }, 'the kubernetes-ocp k178 values, plus the CNI paths and one operator' );
  my $yaml = Rex::Rancher::Cilium::_helm_values_yaml($v);
  like( $yaml, qr/^k8sServicePort: '6443'$/m, 'port stays a YAML string' );
  like( $yaml, qr/^kubeProxyReplacement: true$/m, 'kubeProxyReplacement boolean' );
  like( $yaml, qr/^    clusterPoolIPv4PodCIDRList:\n    - 10\.42\.0\.0\/16$/m, 'pool as a YAML list' );
};

subtest 'k3s: the API address is required and never loopback' => sub {
  my $r = $C->can('_resolve_opts');
  eval { $r->( distribution => 'k3s' ) };
  like( $@, qr/k3s needs k8s_service_host.*127\.0\.0\.1:6444/, 'missing: dies, says why' );
  for my $lo (qw( 127.0.0.1 localhost LOCALHOST ::1 )) {
    eval { $r->( distribution => 'k3s', k8s_service_host => $lo ) };
    like( $@, qr/needs k8s_service_host.*got '\Q$lo\E'/, "$lo: dies" );
  }
  eval { $r->( distribution => 'k3s', helm_values => { k8sServiceHost => 'localhost' } ) };
  like( $@, qr/got 'localhost'/, 'loopback through helm_values: dies' );
  is( values_for( distribution => 'k3s', helm_values => { k8sServiceHost => 'cp' } )->{k8sServiceHost},
    'cp', 'helm_values k8sServiceHost takes the place of k8s_service_host' );
  is( values_for( distribution => 'k3s', k8s_service_host => 'a', helm_values => { k8sServiceHost => 'b' } )
    ->{k8sServiceHost}, 'b', 'helm_values wins, as everywhere' );
  eval { $r->( distribution => 'rke2', k8s_service_host => '203.0.113.7' ) };
  like( $@, qr/k8s_service_host is k3s-only/, 'rke2: refused, not silently ignored' );
};

subtest 'caller values deep-merge over the defaults' => sub {
  my $extra = { operator => { replicas => 2 }, hubble => { relay => { enabled => $T } },
                cni => { exclusive => $T }, ipam => 'cluster-pool' };
  my $v = values_for( distribution => 'rke2', helm_values => $extra );
  is( $v->{operator}{replicas}, 2, 'nested override' );
  is( $v->{cni}{binPath}, '/opt/cni/bin', 'sibling default kept' );
  ok( $v->{cni}{exclusive}, 'nested boolean override' );
  ok( $v->{hubble}{relay}{enabled}, 'new key added' );
  is( $v->{ipam}, 'cluster-pool', 'non-hash replaces a hash' );
  is_deeply( $extra->{operator}, { replicas => 2 }, 'caller hash not modified' );
  is( values_for( distribution => 'rke2' )->{operator}{replicas}, 1, 'defaults not modified' );
};

subtest 'gateway_api sets gatewayAPI.enabled' => sub {
  my $v = values_for( distribution => 'rke2', kubeconfig => '/kc',
    gateway_api => 1, gateway_api_version => 'v1.2.0' );
  ok( $v->{gatewayAPI}{enabled}, 'gatewayAPI.enabled true' );
};

subtest 'gateway_api_channel defaults to experimental' => sub {
  my $r = $C->can('_resolve_opts');
  my %gw = ( gateway_api => 1, gateway_api_version => 'v1.2.0', kubeconfig => '/kc' );
  is( $r->( distribution => 'rke2', %gw )->{gateway_api_channel}, 'experimental',
    'no channel: experimental (keeps TLSRoute for Cilium <= 1.19)' );
  is( $r->( distribution => 'rke2', %gw, gateway_api_channel => 'standard' )->{gateway_api_channel},
    'standard', 'explicit standard kept' );
};

subtest 'option validation dies before touching the host' => sub {
  my $r = $C->can('_resolve_opts');
  my %gw = ( gateway_api => 1, gateway_api_version => 'v1.2.0', kubeconfig => '/kc' );
  my $k3s_gw = $r->( distribution => 'k3s', k8s_service_host => 'cp', %gw );
  ok( $k3s_gw->{gateway_api} && $k3s_gw->{values}{gatewayAPI}{enabled}, 'gateway_api allowed on k3s' );
  ok( eval { $r->( distribution => 'k3s', k8s_service_host => 'cp',
    helm_values => { kubeProxyReplacement => $T, k8sServicePort => '6443' } ); 1 },
    'k3s may set kube-proxy replacement keys' );
  eval { $r->( distribution => 'rke2', %gw, kubeconfig => undef ) };
  like( $@, qr/needs kubeconfig/, 'gateway_api needs kubeconfig' );
  eval { $r->( distribution => 'rke2', %gw, gateway_api_version => undef ) };
  like( $@, qr/needs gateway_api_version/, 'gateway_api needs a version' );
  eval { $r->( distribution => 'rke2', %gw, gateway_api_channel => 'beta' ) };
  like( $@, qr/gateway_api_channel/, 'unknown channel refused' );
  eval { $r->( helm_values => [] ) };
  like( $@, qr/helm_values must be a hashref/, 'helm_values must be a hash' );
  eval { $r->( distribution => 'microk8s' ) };
  like( $@, qr/Unknown distribution/, 'unknown distribution' );
  ok( eval { $r->( distribution => 'rke2', helm_values => { kubeProxyReplacement => $T } ); 1 },
    'rke2 may set kube-proxy replacement keys' );
};

subtest 'cilium command lines' => sub {
  my $cmd = $C->can('_cilium_command');
  my $rke2 = $cmd->( 'install', $C->can('_resolve_opts')->( distribution => 'rke2' ), '/tmp/v.yaml' );
  is( $rke2, 'KUBECONFIG=/etc/rancher/rke2/rke2.yaml cilium install --version 1.17.0 '
    .'--helm-values /tmp/v.yaml --set kubeProxyReplacement=true', 'rke2 install' );
  my $k3s = $cmd->( 'upgrade', $C->can('_resolve_opts')->( distribution => 'k3s',
    k8s_service_host => 'cp', version => '1.18.1' ), '/tmp/v.yaml' );
  is( $k3s, 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml cilium upgrade --version 1.18.1 '
    .'--helm-values /tmp/v.yaml --set kubeProxyReplacement=true', 'k3s upgrade, kube-proxy replacement' );
};

subtest 'gateway API bundle' => sub {
  is( Rex::Rancher::Cilium::_gateway_api_url( 'v1.2.0', 'experimental' ),
    'https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/experimental-install.yaml',
    'bundle URL' );
  my $n = $C->can('_gateway_api_needs_apply');
  my %cur = ( 'gateway.networking.k8s.io/bundle-version' => 'v1.2.0',
              'gateway.networking.k8s.io/channel'        => 'experimental' );
  ok( $n->( undef, 'v1.2.0', 'experimental' ), 'no CRDs yet: apply' );
  ok( !$n->( \%cur, 'v1.2.0', 'experimental' ), 'same bundle: skip' );
  ok( $n->( \%cur, 'v1.3.0', 'experimental' ), 'other version: apply' );
  ok( $n->( \%cur, 'v1.2.0', 'standard' ), 'other channel: apply' );
};

# -----------------------------------------------------------------------------
# 2. Release state and the decision
# -----------------------------------------------------------------------------

my $want = values_for( distribution => 'rke2' );
# The CLI stores more than we set: our values plus its own detected ones.
my $deployed_cfg = { %$want, cluster => { name => 'default' },
  cni => { %{ $want->{cni} } }, k8sServicePort => 6443 };

subtest 'release secrets decode' => sub {
  my $rel = Rex::Rancher::Cilium::_release_from_secrets( [
    helm_secret( revision => 9,  status => 'superseded', chart_version => '1.16.5' ),
    helm_secret( revision => 10, status => 'deployed',   chart_version => '1.17.0', config => $deployed_cfg ),
  ] );
  is( $rel->{revision}, 10, 'newest revision by number, not string' );
  is( $rel->{status}, 'deployed', 'status from labels' );
  is( $rel->{chart_version}, '1.17.0', 'chart version from payload' );
  is( $rel->{config}{cluster}{name}, 'default', 'values from payload' );
  ok( $rel->{has_deployed}, 'has a deployed revision' );
  is_deeply( $rel->{secrets}, [ 'sh.helm.release.v1.cilium.v10', 'sh.helm.release.v1.cilium.v9' ], 'secret names' );
  is( Rex::Rancher::Cilium::_release_from_secrets( [] ), undef, 'no secrets: no release' );
  is( Rex::Rancher::Cilium::_decode_release('not base64 gzip json'), undef, 'garbage decodes to undef' );
};

subtest 'release action' => sub {
  my $act = sub { $C->can('_release_action')->( $_[0], $_[1] // '1.17.0', $_[2] // $want ) };
  my $rel = sub { +{ status => 'deployed', chart_version => '1.17.0', config => $deployed_cfg,
                     has_deployed => 1, revision => 3, @_ } };

  is( $act->(undef), 'install', 'no release: install' );
  is( $act->( $rel->() ), 'noop', 'same version, values in effect: noop (the re-run case)' );
  is( $act->( $rel->( chart_version => 'v1.17.0' ) ), 'noop', 'leading v ignored' );
  is( $act->( $rel->(), 'v1.17.0' ), 'noop', 'leading v ignored on the request too' );
  is( $act->( $rel->(), '1.18.0' ), 'upgrade', 'other version: upgrade' );
  is( $act->( $rel->(), undef, { %$want, operator => { replicas => 2 } } ), 'upgrade',
    'changed value: upgrade' );
  is( $act->( $rel->(), undef, { %$want, gatewayAPI => { enabled => $T } } ), 'upgrade',
    'value not yet set: upgrade' );
  is( $act->( $rel->( chart_version => undef ) ), 'upgrade', 'unreadable payload: upgrade, never noop' );
  is( $act->( $rel->( status => 'failed' ) ), 'upgrade', 'failed upgrade: upgrade again' );
  is( $act->( $rel->( status => 'failed', has_deployed => 0 ) ), 'reinstall', 'failed first install: reinstall' );
  is( $act->( $rel->( status => $_ ) ), 'reinstall', "$_: reinstall" )
    for qw( pending-install uninstalling uninstalled );
  for my $st (qw( pending-upgrade pending-rollback )) {
    eval { $act->( $rel->( status => $st ) ) };
    like( $@, qr/stuck in $st.*sh\.helm\.release\.v1\.cilium\.v3/s, "$st: dies naming the secret" );
  }
  my $pool = { %$want, ipam => { mode => 'cluster-pool' } };
  eval { $act->( $rel->(), undef, $pool ) };
  like( $@, qr/runs ipam\.mode kubernetes, the requested values ipam\.mode cluster-pool.*Redeploy.*mode => 'kubernetes'/s,
    'deployed: changing ipam.mode dies naming both modes' );
  eval { $act->( $rel->( status => 'failed' ), undef, $pool ) };
  like( $@, qr/runs ipam\.mode kubernetes/, 'failed upgrade: same refusal' );
  is( $act->( $rel->( config => { %$deployed_cfg, ipam => {} } ), undef, $pool ), 'upgrade',
    'no ipam.mode in the release: not refused' );
  is( $act->( $rel->(), '1.18.0' ), 'upgrade', 'same ipam.mode: upgrade as before' );
  eval { $act->( $rel->( status => 'superseded' ) ) };
  like( $@, qr/unexpected state 'superseded'/, 'unknown state dies' );
};

subtest 'boolean values compare against decoded JSON' => sub {
  my $s = $C->can('_values_subset');
  ok( $s->( { a => $T }, { a => JSON::MaybeXS->new->decode('{"a":true}')->{a} } ), 'true eq true' );
  ok( !$s->( { a => $T }, { a => JSON::MaybeXS->new->decode('{"a":false}')->{a} } ), 'true ne false' );
  ok( $s->( { p => '6443' }, { p => 6443 } ), 'string and number alike' );
  ok( !$s->( { a => { b => 1 } }, { a => 1 } ), 'hash vs scalar' );
  ok( $s->( { l => [ 1, 2 ] }, { l => [ 1, 2 ] } ), 'equal arrays' );
  ok( !$s->( { l => [ 1 ] }, { l => [ 1, 2 ] } ), 'arrays compare whole' );
};

# -----------------------------------------------------------------------------
# 3. install_cilium end to end against the fakes
# -----------------------------------------------------------------------------

sub cilium_cmds { grep { /cilium (install|upgrade|uninstall)/ } @cmds }

subtest 'with kubeconfig: existing release at the version is a noop' => sub {
  @cmds = ();
  $api = FakeAPI->new( secrets => [
    helm_secret( revision => 1, status => 'deployed', chart_version => '1.17.0', config => $deployed_cfg ) ] );
  install_cilium( distribution => 'rke2', kubeconfig => '/kc' );
  is( scalar cilium_cmds(), 0, 'no install, no upgrade' );
  ok( $files{'/tmp/cilium-values-rke2.yaml'}, 'values file still written' );
};

subtest 'with kubeconfig: other version upgrades' => sub {
  @cmds = ();
  $api = FakeAPI->new( secrets => [
    helm_secret( revision => 1, status => 'deployed', chart_version => '1.16.5', config => $deployed_cfg ) ] );
  install_cilium( distribution => 'rke2', kubeconfig => '/kc' );
  is_deeply( [ map { /cilium (\w+)/ } cilium_cmds() ], ['upgrade'], 'exactly one upgrade' );
};

subtest 'with kubeconfig: k3s release on ipam kubernetes dies before upgrade' => sub {
  @cmds = ();
  $api = FakeAPI->new( secrets => [
    helm_secret( revision => 1, status => 'deployed', chart_version => '1.17.0', config => $deployed_cfg ) ] );
  eval { install_cilium( distribution => 'k3s', k8s_service_host => 'cp', kubeconfig => '/kc' ) };
  like( $@, qr/runs ipam\.mode kubernetes, the requested values ipam\.mode cluster-pool/, 'dies naming both modes' );
  is( scalar cilium_cmds(), 0, 'no cilium upgrade' );

  @cmds = ();
  install_cilium( distribution => 'k3s', k8s_service_host => 'cp', kubeconfig => '/kc',
    helm_values => { ipam => { mode => 'kubernetes' } } );
  is_deeply( [ map { /cilium (\w+)/ } cilium_cmds() ], ['upgrade'], 'matching helm_values: upgrade' );
};

subtest 'with kubeconfig: fresh cluster installs and checks the DaemonSet' => sub {
  @cmds = ();
  $api = FakeAPI->new( secrets => [], daemonset => 1 );
  install_cilium( distribution => 'k3s', k8s_service_host => 'cp', kubeconfig => '/kc' );
  is_deeply( [ map { /cilium (\w+)/ } cilium_cmds() ], ['install'], 'one install' );

  $api = FakeAPI->new( secrets => [], daemonset => 0 );
  eval { install_cilium( distribution => 'rke2', kubeconfig => '/kc' ) };
  like( $@, qr/DaemonSet kube-system\/cilium does not exist/, 'exit 0 without a DaemonSet dies' );
};

subtest 'with kubeconfig: stale first install is purged, then installed' => sub {
  @cmds = ();
  $api = FakeAPI->new( daemonset => 1, secrets => [
    helm_secret( revision => 1, status => 'failed', chart_version => '1.17.0' ) ] );
  install_cilium( distribution => 'rke2', kubeconfig => '/kc' );
  is_deeply( [ map { /cilium (\w+)/ } cilium_cmds() ], [ 'uninstall', 'install' ], 'uninstall, then install' );
  is_deeply( $api->{deleted}, ['Secret/sh.helm.release.v1.cilium.v1'], 'release secret removed' );
};

subtest 'with kubeconfig: a failing install is not swallowed' => sub {
  @cmds = ();
  $api = FakeAPI->new( secrets => [] );
  $run_hook = sub { return unless $_[0] =~ /cilium install/; $? = 1 << 8; 'Error: cannot re-use a name that is still in use' };
  eval { install_cilium( distribution => 'rke2', kubeconfig => '/kc' ) };
  like( $@, qr/cilium install failed: .*cannot re-use a name/, 'dies with the CLI output' );
  $run_hook = undef;
};

subtest 'without kubeconfig: the re-run swallow is kept' => sub {
  @cmds = ();
  $run_hook = sub { return unless $_[0] =~ /cilium install/; $? = 1 << 8; 'Error: cannot re-use a name that is still in use' };
  ok( eval { install_cilium( distribution => 'rke2' ); 1 }, 'existing release counts as success' ) or diag $@;

  $run_hook = sub { return unless $_[0] =~ /cilium install/; $? = 1 << 8; 'Error: boom' };
  eval { install_cilium( distribution => 'rke2' ) };
  like( $@, qr/cilium install failed: Error: boom/, 'any other failure dies' );
  $run_hook = undef;
};

# -----------------------------------------------------------------------------
# 4. A running Cilium keeps what it runs (k43): IPAM mode and pool from its
#    ConfigMap, k8sServiceHost from its DaemonSet, operator.replicas from the
#    release -- unless the caller asked for them, where a change the running
#    cluster cannot take dies before the host is touched.
# -----------------------------------------------------------------------------

sub configmap {
  my ( %data ) = @_;
  $k8s->struct_to_object( { apiVersion => 'v1', kind => 'ConfigMap',
    metadata => { name => 'cilium-config', namespace => 'kube-system' }, data => \%data } );
}

sub daemonset {
  my ( %a ) = @_;
  $k8s->struct_to_object( { apiVersion => 'apps/v1', kind => 'DaemonSet',
    metadata => { name => 'cilium', namespace => 'kube-system', generation => $a{generation} // 1 },
    spec => { selector => {}, template => { spec => { containers => [
      { name => 'cilium-agent', image => 'cilium',
        env => [ map { { name => $_, value => $a{env}{$_} } } sort keys %{ $a{env} // {} } ] },
    ] } } },
    status => { currentNumberScheduled => $a{desired} // 1, desiredNumberScheduled => $a{desired} // 1,
      numberMisscheduled => 0, numberReady => $a{ready} // 1,
      updatedNumberScheduled => $a{updated} // $a{desired} // 1,
      observedGeneration => $a{observed} // $a{generation} // 1 },
  } );
}

sub operator_deployment {
  my ( %a ) = @_;
  $k8s->struct_to_object( { apiVersion => 'apps/v1', kind => 'Deployment',
    metadata => { name => 'cilium-operator', namespace => 'kube-system', generation => 1 },
    spec => { replicas => $a{replicas} // 1, selector => {}, template => {} },
    status => { readyReplicas => $a{ready} // 1, updatedReplicas => $a{ready} // 1, observedGeneration => 1 },
  } );
}

sub adopt {
  my ( $running, %opts ) = @_;
  my $o = $C->can('_resolve_opts')->( kubeconfig => '/kc', %opts );
  return $C->can('_adopt_running')->( $o, $running )->{values};
}

subtest 'which values the caller set' => sub {
  my $e = $C->can('_explicit_values');
  is_deeply( $e->( {} ), { ipam_mode => 0, pool => 0, k8s_service_host => 0, operator_replicas => 0 },
    'nothing given: all defaults' );
  is_deeply( $e->( { ipam => { mode => 'kubernetes' } } ),
    { ipam_mode => 1, pool => 0, k8s_service_host => 0, operator_replicas => 0 }, 'mode only' );
  is( $e->( { ipam => { operator => { clusterPoolIPv4PodCIDRList => ['10.1.0.0/16'] } } } )->{pool}, 1, 'pool' );
  is( $e->( { ipam => { operator => { clusterPoolIPv4MaskSize => 24 } } } )->{pool}, 0,
    'another operator key is not the pool' );
  is_deeply( [ @{ $e->( { ipam => 'cluster-pool' } ) }{qw( ipam_mode pool )} ], [ 1, 1 ],
    'a non-hash ipam sets both' );
  is( $e->( {}, 'cp' )->{k8s_service_host}, 1, 'k8s_service_host option' );
  is( $e->( { k8sServiceHost => 'cp' } )->{k8s_service_host}, 1, 'k8sServiceHost value' );
  is( $e->( { operator => { replicas => 2 } } )->{operator_replicas}, 1, 'operator.replicas' );
};

subtest 'adopt: IPAM mode and pool follow the running Cilium' => sub {
  my $pool = { ipam_mode => 'cluster-pool', pool => ['10.0.0.0/8'] };
  is_deeply( adopt( $pool, distribution => 'rke2' )->{ipam},
    { mode => 'cluster-pool', operator => { clusterPoolIPv4PodCIDRList => ['10.0.0.0/8'] } },
    'rke2 on a cluster-pool cluster: never switched to kubernetes (the k43 danger)' );
  is_deeply( adopt( { ipam_mode => 'kubernetes' }, distribution => 'rke2' )->{ipam},
    { mode => 'kubernetes' }, 'rke2 on kubernetes: unchanged' );
  is_deeply( adopt( { ipam_mode => 'kubernetes' }, distribution => 'k3s', k8s_service_host => 'cp' )->{ipam},
    { mode => 'kubernetes' }, 'k3s on kubernetes: mode kept, default pool dropped' );
  is_deeply( adopt( { ipam_mode => 'cluster-pool', pool => ['10.100.0.0/16'] },
      distribution => 'k3s', k8s_service_host => 'cp' )->{ipam},
    { mode => 'cluster-pool', operator => { clusterPoolIPv4PodCIDRList => ['10.100.0.0/16'] } },
    'k3s: the running pool replaces the default one' );
  is_deeply( adopt( { ipam_mode => 'cluster-pool' }, distribution => 'k3s', k8s_service_host => 'cp' )->{ipam},
    { mode => 'cluster-pool' }, 'no readable pool: the default gives way to the chart\'s' );
  is_deeply( adopt( {}, distribution => 'rke2' )->{ipam}, { mode => 'kubernetes' },
    'no ConfigMap: defaults stand' );
  my $keep = adopt( $pool, distribution => 'rke2',
    helm_values => { ipam => { operator => { clusterPoolIPv4MaskSize => 26 } } } );
  is( $keep->{ipam}{operator}{clusterPoolIPv4MaskSize}, 26, 'caller\'s other ipam keys kept' );
  is_deeply( $keep->{ipam}{operator}{clusterPoolIPv4PodCIDRList}, ['10.0.0.0/8'], 'next to the running pool' );

  eval { adopt( $pool, distribution => 'rke2', helm_values => { ipam => { mode => 'kubernetes' } } ) };
  like( $@, qr{runs ipam\.mode cluster-pool \(ConfigMap kube-system/cilium-config\), the requested values ipam\.mode kubernetes},
    'explicit other mode: dies naming both' );
  is( adopt( $pool, distribution => 'rke2', helm_values => { ipam => { mode => 'cluster-pool' } } )
    ->{ipam}{operator}{clusterPoolIPv4PodCIDRList}[0], '10.0.0.0/8', 'explicit same mode: pool still adopted' );

  my $two = { ipam_mode => 'cluster-pool', pool => [ '10.0.0.0/16', '10.1.0.0/16' ] };
  eval { adopt( $two, distribution => 'rke2',
    helm_values => { ipam => { operator => { clusterPoolIPv4PodCIDRList => ['10.9.0.0/16'] } } } ) };
  like( $@, qr{cluster-pool is 10\.0\.0\.0/16 10\.1\.0\.0/16 .*requested clusterPoolIPv4PodCIDRList 10\.9\.0\.0/16}s,
    'explicit other pool: dies naming both' );
  ok( eval { adopt( $two, distribution => 'rke2',
    helm_values => { ipam => { operator => { clusterPoolIPv4PodCIDRList => [ '10.1.0.0/16', '10.0.0.0/16' ] } } } ); 1 },
    'explicit same pool in another order: fine' ) or diag $@;
  ok( eval { adopt( { ipam_mode => 'kubernetes' }, distribution => 'rke2',
    helm_values => { ipam => { operator => { clusterPoolIPv4PodCIDRList => ['10.9.0.0/16'] } } } ); 1 },
    'a pool on a kubernetes-mode cluster is not compared' );
};

subtest 'adopt: k8sServiceHost (k3s) and operator.replicas' => sub {
  my $v = adopt( { k8s_service_host => '10.0.0.1', operator_replicas => 2 }, distribution => 'k3s' );
  is( $v->{k8sServiceHost}, '10.0.0.1', 'k3s: running host used when none given' );
  is( $v->{operator}{replicas}, 2, 'operator.replicas from the release, not forced to 1' );
  is( adopt( { k8s_service_host => '10.0.0.1' }, distribution => 'k3s', k8s_service_host => 'cp' )
    ->{k8sServiceHost}, 'cp', 'given host wins' );
  is( adopt( { k8s_service_host => '10.0.0.1' }, distribution => 'rke2' )->{k8sServiceHost},
    '127.0.0.1', 'rke2 keeps 127.0.0.1' );
  is( adopt( { operator_replicas => 2 }, distribution => 'rke2',
    helm_values => { operator => { replicas => 3 } } )->{operator}{replicas}, 3, 'given replicas win' );
  is( adopt( {}, distribution => 'rke2' )->{operator}{replicas}, 1, 'nothing running: default 1' );
};

subtest 'read the running Cilium' => sub {
  $api = FakeAPI->new( objects => {
    'ConfigMap/cilium-config' => configmap( ipam => 'cluster-pool', 'cluster-pool-ipv4-cidr' => '10.0.0.0/16 10.1.0.0/16' ),
    'DaemonSet/cilium'        => daemonset( env => { KUBERNETES_SERVICE_HOST => '203.0.113.7' } ),
  } );
  is_deeply( $C->can('_read_running')->( $api, { config => { operator => { replicas => 2 } } } ), {
    ipam_mode => 'cluster-pool', pool => [ '10.0.0.0/16', '10.1.0.0/16' ],
    k8s_service_host => '203.0.113.7', operator_replicas => 2,
  }, 'mode, pool list, host, replicas' );

  $api = FakeAPI->new( objects => { 'ConfigMap/cilium-config' => configmap() } );
  is( $C->can('_read_running')->( $api, undef )->{ipam_mode}, 'cluster-pool',
    'ConfigMap without ipam: the agent default cluster-pool' );

  $api = FakeAPI->new( objects => { 'ConfigMap/cilium-config' => sub { die "Kubernetes API error: 403 forbidden\n" } } );
  eval { $C->can('_read_running')->( $api, undef ) };
  like( $@, qr{Cannot read ConfigMap kube-system/cilium-config: .*403}, 'an API error dies, never guesses' );
};

subtest 'install_cilium: a running cluster-pool rke2 cluster is upgraded on cluster-pool' => sub {
  @cmds = ();
  $api = FakeAPI->new(
    secrets => [ helm_secret( revision => 1, status => 'deployed', chart_version => '1.16.5',
      config => { cluster => { name => 'default' } } ) ],
    objects => { 'ConfigMap/cilium-config' => configmap( ipam => 'cluster-pool', 'cluster-pool-ipv4-cidr' => '10.0.0.0/8' ) },
  );
  install_cilium( distribution => 'rke2', kubeconfig => '/kc' );
  is_deeply( [ map { /cilium (\w+)/ } cilium_cmds() ], ['upgrade'], 'upgraded' );
  like( $files{'/tmp/cilium-values-rke2.yaml'}, qr/^  mode: cluster-pool$/m, 'values keep cluster-pool' );
  like( $files{'/tmp/cilium-values-rke2.yaml'}, qr{^    - 10\.0\.0\.0/8$}m, 'and the running pool' );

  @cmds = ();
  eval { install_cilium( distribution => 'rke2', kubeconfig => '/kc', helm_values => { ipam => { mode => 'kubernetes' } } ) };
  like( $@, qr/runs ipam\.mode cluster-pool/, 'explicit kubernetes: dies' );
  is_deeply( \@cmds, [], 'before anything ran on the host' );
};

subtest 'install_cilium: a stale release is reinstalled without adopting' => sub {
  @cmds = ();
  $api = FakeAPI->new( daemonset => 1,
    secrets => [ helm_secret( revision => 1, status => 'failed', chart_version => '1.17.0' ) ],
    objects => { 'ConfigMap/cilium-config' => configmap( ipam => 'cluster-pool' ) } );
  install_cilium( distribution => 'rke2', kubeconfig => '/kc' );
  like( $files{'/tmp/cilium-values-rke2.yaml'}, qr/^  mode: kubernetes$/m, 'no working Cilium: defaults' );
};

subtest 'upgrade_cilium: k3s keeps the running k8sServiceHost' => sub {
  @cmds = ();
  $api = FakeAPI->new( objects => {
    'ConfigMap/cilium-config' => configmap( ipam => 'cluster-pool', 'cluster-pool-ipv4-cidr' => '10.42.0.0/16' ),
    'DaemonSet/cilium'        => daemonset( env => { KUBERNETES_SERVICE_HOST => '203.0.113.7' } ),
  } );
  upgrade_cilium( distribution => 'k3s', kubeconfig => '/kc' );
  like( $files{'/tmp/cilium-values-k3s.yaml'}, qr/^k8sServiceHost: 203\.0\.113\.7$/m, 'host from the DaemonSet' );
  is_deeply( [ map { /cilium (\w+)/ } cilium_cmds() ], ['upgrade'], 'upgraded' );

  @cmds = ();
  $api = FakeAPI->new;
  eval { upgrade_cilium( distribution => 'k3s', kubeconfig => '/kc' ) };
  like( $@, qr/k3s needs k8s_service_host/, 'no running Cilium and no host: dies' );
  is_deeply( \@cmds, [], 'before anything ran on the host' );
};

subtest 'wait for readiness' => sub {
  my $r = $C->can('_readiness');
  ok( $r->( daemonset(), operator_deployment() )->{ready}, 'all ready' );
  my $st = $r->( daemonset( desired => 3, ready => 2 ), operator_deployment() );
  ok( !$st->{ready}, 'a node not ready' );
  like( $st->{detail}, qr{cilium 2/3 ready, 3/3 updated; cilium-operator 1/1 ready}, 'detail says so' );
  ok( !$r->( daemonset( desired => 2, updated => 1 ), operator_deployment() )->{ready}, 'rollout incomplete' );
  like( $r->( daemonset( generation => 3, observed => 2 ), operator_deployment() )->{detail},
    qr/rollout not observed yet/, 'new generation not observed' );
  ok( !$r->( daemonset(), operator_deployment( ready => 0 ) )->{ready}, 'operator not ready' );
  like( $r->( undef, undef )->{detail}, qr{DaemonSet kube-system/cilium not found; Deployment kube-system/cilium-operator not found},
    'nothing there' );

  my $resolve = $C->can('_resolve_opts');
  eval { $resolve->( wait => 1 ) };
  like( $@, qr/wait needs kubeconfig/, 'wait needs kubeconfig' );
  eval { $resolve->( wait => 1, kubeconfig => '/kc', wait_duration => '10m' ) };
  like( $@, qr/wait_duration must be a whole number of seconds/, 'duration in seconds' );
  is( $resolve->( wait => 1, kubeconfig => '/kc' )->{wait_duration}, 600, 'default 600s' );

  my $slept = 0;
  no warnings 'redefine';
  local *Rex::Rancher::Cilium::_sleep = sub { $slept++ };
  use warnings 'redefine';

  $api = FakeAPI->new( secrets => [], objects => {
    'DaemonSet/cilium' => daemonset(), 'Deployment/cilium-operator' => operator_deployment() } );
  ok( eval { install_cilium( distribution => 'rke2', kubeconfig => '/kc', wait => 1 ); 1 }, 'ready: returns' ) or diag $@;
  is( $slept, 0, 'without sleeping' );

  $api = FakeAPI->new( secrets => [ helm_secret( revision => 1, status => 'deployed', chart_version => '1.16.5',
    config => $deployed_cfg ) ], objects => {
    'DaemonSet/cilium' => daemonset( desired => 2, ready => 1 ), 'Deployment/cilium-operator' => operator_deployment() } );
  eval { upgrade_cilium( distribution => 'rke2', kubeconfig => '/kc', wait => 1, wait_duration => 12 ) };
  like( $@, qr{Cilium was not ready within 12s: cilium 1/2 ready}, 'timeout dies with the state' );
  is( $slept, 2, 'three polls, 5s apart' );
};

subtest 'ensure_gateway_api_crds' => sub {
  @cmds = ();
  eval { ensure_gateway_api_crds( version => 'v1.2.0' ) };
  like( $@, qr/needs kubeconfig/, 'kubeconfig required' );
  eval { ensure_gateway_api_crds( kubeconfig => '/kc' ) };
  like( $@, qr/needs version/, 'version required' );
  eval { ensure_gateway_api_crds( kubeconfig => '/kc', version => 'v1.2.0', channel => 'beta' ) };
  like( $@, qr/gateway_api_channel must be/, 'channel checked' );

  my @called;
  no warnings 'redefine';
  local *Rex::Rancher::Cilium::_ensure_gateway_api_crds = sub { push @called, [ @_[ 1, 2 ] ]; $main::applied };
  use warnings 'redefine';

  our $applied = 0;
  $api = FakeAPI->new( objects => { 'Deployment/cilium-operator' => operator_deployment() } );
  is( ensure_gateway_api_crds( kubeconfig => '/kc', version => 'v1.2.0' ), 0, 'current: 0' );
  is_deeply( $called[-1], [ 'v1.2.0', 'experimental' ], 'default channel experimental' );
  is_deeply( $api->{patched}, [], 'operator left alone' );

  $applied = 1;
  is( ensure_gateway_api_crds( kubeconfig => '/kc', version => 'v1.6.1', channel => 'standard' ), 1, 'applied: 1' );
  is_deeply( $api->{patched}, ['Deployment/cilium-operator'], 'operator restarted' );
  is_deeply( \@cmds, [], 'nothing on the remote host' );
};

done_testing;
