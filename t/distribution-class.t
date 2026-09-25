use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# Rex::Rancher::Distribution and its RKE2/K3s classes, offline.
#
# - both classes implement every distribution-specific method themselves, so
#   one cannot be changed without the other being there to compare;
# - new_for: default rke2, unknown names die with the message install_server
#   always gave, role picks the service and the rke2 env file;
# - the values the Server/Agent/Cilium modules used to keep in their own
#   tables, pinned here per distribution and role.
#
# Pure: nothing here runs a command. What the host steps do is covered by the
# other tests with `run` faked; neither says a real node comes up.
# -----------------------------------------------------------------------------

use JSON::MaybeXS ();
use Rex::Rancher::Distribution;

my $D = 'Rex::Rancher::Distribution';

my @PER_DISTRIBUTION = qw(
  name label config_dir install_url kubeconfig token_file server_token
  default_disable default_cluster_cidr binary release_url artifact_dir
  containerd_dir server_service agent_service env_file default_start_verb
  asset_name cilium_config script_install_cmd artifact_install_cmds
  run_server_install_script
);

is_deeply( [ sort keys %{ $D->distribution_classes } ], [qw( k3s rke2 )], 'rke2 and k3s' );

for my $class ( sort values %{ $D->distribution_classes } ) {
  ok( $class->isa($D), $class.' is a '.$D );
  no strict 'refs';
  my @missing = grep { !defined &{ $class.'::'.$_ } } @PER_DISTRIBUTION;
  is_deeply( \@missing, [], $class.' implements every distribution-specific method itself' );
  ok( !$class->can($_), $class.': no Rex DSL '.$_.' as a method' ) for qw( run file can_run );
}

subtest 'new_for' => sub {
  isa_ok( $D->new_for(undef), $D.'::RKE2', 'undef' );
  isa_ok( $D->new_for('rke2'), $D.'::RKE2', 'rke2' );
  isa_ok( $D->new_for('k3s'),  $D.'::K3s',  'k3s' );
  is( $D->new_for('k3s')->role, 'server', 'server by default' );
  for my $bad ( 'containerd', 'RKE2', 'k3s ', '' ) {
    ok( !eval { $D->new_for($bad); 1 }, "'$bad' dies" );
    is( $@, "Unknown distribution: $bad (expected 'rke2' or 'k3s')\n", "'$bad': message, no line number" );
  }
  ok( !eval { $D->new_for( 'rke2', role => 'worker' ); 1 }, 'unknown role dies' );
  like( $@, qr/role must be 'server' or 'agent'/, '... saying which exist' );
};

my %want = (
  rke2 => {
    name => 'rke2', label => 'RKE2', config_dir => '/etc/rancher/rke2',
    config_file => '/etc/rancher/rke2/config.yaml', registries_file => '/etc/rancher/rke2/registries.yaml',
    install_url => 'https://get.rke2.io', kubeconfig => '/etc/rancher/rke2/rke2.yaml',
    token_file => '/var/lib/rancher/rke2/server/node-token', server_token => '/var/lib/rancher/rke2/server/token',
    binary => 'rke2', release_url => 'https://github.com/rancher/rke2/releases/download',
    artifact_dir => '/tmp/rke2-artifacts', containerd_dir => '/var/lib/rancher/rke2/agent/etc/containerd',
    default_start_verb => 'start', default_cluster_cidr => undef,
    default_disable => [qw( rke2-ingress-nginx rke2-traefik rke2-traefik-crd )],
    cni_bin_dir => '/opt/cni/bin', cni_conf_dir => '/etc/cni/net.d',
    restart_services_cmd => 'systemctl restart rke2-server.service 2>/dev/null || systemctl restart rke2-agent.service 2>/dev/null',
  },
  k3s => {
    name => 'k3s', label => 'K3s', config_dir => '/etc/rancher/k3s',
    config_file => '/etc/rancher/k3s/config.yaml', registries_file => '/etc/rancher/k3s/registries.yaml',
    install_url => 'https://get.k3s.io', kubeconfig => '/etc/rancher/k3s/k3s.yaml',
    token_file => '/var/lib/rancher/k3s/server/node-token', server_token => '/var/lib/rancher/k3s/server/token',
    binary => 'k3s', release_url => 'https://github.com/k3s-io/k3s/releases/download',
    artifact_dir => '/tmp/k3s-artifacts', containerd_dir => '/var/lib/rancher/k3s/agent/etc/containerd',
    default_start_verb => 'restart', default_cluster_cidr => '10.42.0.0/16',
    default_disable => [qw( traefik servicelb )],
    cni_bin_dir => '/opt/cni/bin', cni_conf_dir => '/etc/cni/net.d',
    restart_services_cmd => 'systemctl restart k3s.service 2>/dev/null || systemctl restart k3s-agent.service 2>/dev/null',
  },
);

my %role = (
  rke2 => { server => [ 'rke2-server', '/etc/default/rke2-server' ],
            agent  => [ 'rke2-agent.service', '/etc/default/rke2-agent' ] },
  k3s  => { server => [ 'k3s', undef ],
            agent  => [ 'k3s-agent.service', undef ] },
);

for my $name (qw( rke2 k3s )) {
  subtest $name => sub {
    my $d = $D->new_for($name);
    is_deeply( $d->$_, $want{$name}{$_}, $_ ) for sort keys %{ $want{$name} };

    push @{ $d->default_disable }, 'mutated';
    is_deeply( $d->default_disable, $want{$name}{default_disable}, 'default_disable is a new list each time' );

    for my $r (qw( server agent )) {
      my $rd = $D->new_for( $name, role => $r );
      is( $rd->service,  $role{$name}{$r}[0], "$r: service" );
      is( $rd->env_file, $role{$name}{$r}[1], "$r: env_file" );
      is( $rd->is_agent ? 1 : 0, $r eq 'agent' ? 1 : 0, "$r: is_agent" );
    }
  };
}

subtest 'cilium_config' => sub {
  my $r = $D->new_for('rke2')->cilium_config;
  is_deeply( [ sort keys %$r ], [ 'cni', 'disable-kube-proxy' ], 'rke2 keys' );
  is( $r->{cni}, 'none', 'rke2: cni none' );
  ok( JSON::MaybeXS::is_bool( $r->{'disable-kube-proxy'} ) && $r->{'disable-kube-proxy'}, 'rke2: real true' );

  my $k = $D->new_for('k3s')->cilium_config;
  is_deeply( [ sort keys %$k ], [ 'cluster-cidr', 'disable-kube-proxy', 'disable-network-policy', 'flannel-backend' ],
    'k3s keys' );
  is( $k->{'cluster-cidr'}, '10.42.0.0/16', 'k3s: its default cluster-cidr' );
  ok( JSON::MaybeXS::is_bool( $k->{$_} ) && $k->{$_}, "k3s: $_ real true" )
    for 'disable-kube-proxy', 'disable-network-policy';
};

subtest 'asset_name' => sub {
  is( $D->new_for('rke2')->asset_name('amd64'), 'rke2.linux-amd64.tar.gz', 'rke2 amd64' );
  is( $D->new_for('k3s')->asset_name('amd64'),  'k3s',                     'k3s amd64: bare name' );
  is( $D->new_for('k3s')->asset_name('arm64'),  'k3s-arm64',               'k3s arm64' );
};

done_testing;
