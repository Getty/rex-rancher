# ABSTRACT: K3s: paths, services and installer

package Rex::Rancher::Distribution::K3s;
our $VERSION = '0.003';
use v5.14.4;
use Moo;
use JSON::MaybeXS;
use Rex::Commands::Run ();
use namespace::autoclean;

extends 'Rex::Rancher::Distribution';

sub name                 { 'k3s' }
sub label                { 'K3s' }
sub config_dir           { '/etc/rancher/k3s' }
sub install_url          { 'https://get.k3s.io' }
sub channel_url          { 'https://update.k3s.io/v1-release/channels/stable' }
sub kubeconfig           { '/etc/rancher/k3s/k3s.yaml' }
sub token_file           { '/var/lib/rancher/k3s/server/node-token' }
sub server_token         { '/var/lib/rancher/k3s/server/token' }
sub binary               { 'k3s' }
sub release_url          { 'https://github.com/k3s-io/k3s/releases/download' }
sub artifact_dir         { '/tmp/k3s-artifacts' }
sub containerd_dir       { '/var/lib/rancher/k3s/agent/etc/containerd' }
sub server_service       { 'k3s' }
sub agent_service        { 'k3s-agent.service' }
# A re-run picks up a new binary and config.yaml, as the install script's own
# restart did before INSTALL_K3S_SKIP_START. Not narrowed to restart_reasons
# like rke2: the script rewrites k3s.service and k3s.service.env on every run
# (so their mtime alone would say "changed" each time), the unit's arguments
# come from this run's installer line, and the k3s path is not live-verified.
sub default_start_verb   { 'restart' }

# Formerly --disable flags on the installer line; config.yaml carries the same
# and keeps caller-supplied names out of the shell.
sub default_disable { [ 'traefik', 'servicelb' ] }

# k3s' built-in default, written out with cilium because Cilium's
# cluster-pool IPAM has to hand out the same range (Rex::Rancher::Cilium).
sub default_cluster_cidr { '10.42.0.0/16' }

# None: k3s' agent code finds a host NVIDIA toolkit and wires it plus the
# nvidia RuntimeClass without help (kubernetes-ocp).
sub env_file { undef }

sub asset_name {
  my ( $self, $arch ) = @_;
  return $arch eq 'amd64' ? 'k3s' : "k3s-$arch";
}

# Flannel, the embedded network policy controller and kube-proxy go, Cilium
# takes over all three; cluster-cidr is stated so Cilium's cluster-pool gets
# the same range (as kubernetes-ocp k178, verified live there). All
# server-side; k3s agents take them from the server, and every server of a
# cluster must carry the same.
sub cilium_config {
  my ( $self ) = @_;
  return {
    'flannel-backend'        => 'none',
    'disable-network-policy' => JSON()->true,
    'disable-kube-proxy'     => JSON()->true,
    'cluster-cidr'           => $self->default_cluster_cidr,
  };
}

# INSTALL_K3S_SKIP_START, server and agent: the script's own `systemctl
# restart` of the Type=notify unit blocks until k3s is up, forever for a join
# that cannot reach its server; the caller starts it --no-block and waits
# bounded. No K3S_TOKEN: the token is in config.yaml, and anything on this
# line shows up in ps. traefik/servicelb are disabled in config.yaml too.
sub script_install_cmd {
  my ( $self, $server, $version ) = @_;
  my @env;
  push @env, "K3S_URL=$server"              if $server;
  push @env, "INSTALL_K3S_VERSION=$version" if $version;
  push @env, 'INSTALL_K3S_SKIP_START=true';
  my $env_str = join('', map { "$_ " } @env);
  return "curl -sfL " . $self->install_url . " | ${env_str}sh -s - " . $self->role
    . ( $self->is_agent ? '' : ' --write-kubeconfig-mode=644' );
}

# Put the verified binary where the K3s install script looks for it: next to
# it, then rename, so a running k3s ("text file busy") is replaced atomically.
# SKIP_DOWNLOAD=binary skips only the binary; the SELinux RPM on RHEL-likes is
# still fetched, as with curl | sh. BIN_DIR pinned to where we put the binary.
sub artifact_install_cmds {
  my ( $self, $spec, $server, $version ) = @_;
  my $role = $self->role;
  my $place = "install -m 0755 -o root -g root '$spec->{dir}/$spec->{asset}' /usr/local/bin/.k3s.rex-new"
    . " && mv -f /usr/local/bin/.k3s.rex-new /usr/local/bin/k3s";
  my @env;
  push @env, "K3S_URL=$server" if $server;
  push @env, 'INSTALL_K3S_SKIP_DOWNLOAD=binary', 'INSTALL_K3S_BIN_DIR=/usr/local/bin',
    "INSTALL_K3S_VERSION=$version";
  push @env, 'INSTALL_K3S_SKIP_START=true';
  my $cmd = join(' ', @env) . " sh $spec->{script} $role";
  $cmd .= ' --write-kubeconfig-mode=644' if $role eq 'server';
  return ( $place, $cmd );
}

sub run_server_install_script {
  my ( $self, $server, $version ) = @_;
  Rex::Commands::Run::run($self->script_install_cmd($server, $version), auto_die => 1);
}

1;

=head1 SYNOPSIS

  my $k3s = Rex::Rancher::Distribution->new_for('k3s', role => 'agent');
  $k3s->service;                                   # k3s-agent.service
  $k3s->script_install_cmd('https://cp1:6443');
  # curl -sfL https://get.k3s.io | K3S_URL=https://cp1:6443 INSTALL_K3S_SKIP_START=true sh -s - agent

=head1 DESCRIPTION

The K3s side of L<Rex::Rancher::Distribution>. Configuration in
C</etc/rancher/k3s>, units C<k3s> and C<k3s-agent.service>, installer from
L<https://get.k3s.io> with C<INSTALL_K3S_SKIP_START> (the unit is restarted
C<--no-block> and waited on instead) and C<K3S_URL> for a join, release
binaries C<k3s> / C<k3s-ARCH>. The service is restarted on every run: the
install script rewrites its unit and C<k3s.service.env> each time, so it is
not narrowed to L<Rex::Rancher::Distribution/restart_reasons> as on RKE2.
The version skew rules of L<Rex::Rancher::Distribution/start_verb> and
L<Rex::Rancher::Distribution/check_version_skew> apply as on RKE2: a
running k3s is not restarted onto an unpinned new minor.

With C<cilium> the server config gets C<flannel-backend: none>,
C<disable-network-policy: true>, C<disable-kube-proxy: true> and
C<cluster-cidr: 10.42.0.0/16> (K3s' own default, also Cilium's pool). K3s
needs no C<PATH> line for a host NVIDIA runtime.

The K3s path has not been run live through Rex::Rancher; RKE2 is the
verified distribution. The methods are those documented in
L<Rex::Rancher::Distribution>.

=head1 SEE ALSO

L<Rex::Rancher::Distribution>, L<Rex::Rancher::Distribution::RKE2>

=cut
