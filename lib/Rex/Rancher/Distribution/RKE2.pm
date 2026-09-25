# ABSTRACT: RKE2: paths, services and installer of the default distribution

package Rex::Rancher::Distribution::RKE2;
our $VERSION = '0.003';
use v5.14.4;
use Moo;
use JSON::MaybeXS;
use Rex::Commands::Run ();
use namespace::autoclean;

# No `use utf8` here, on purpose: see Rex::Rancher::Distribution.

extends 'Rex::Rancher::Distribution';

sub name                 { 'rke2' }
sub label                { 'RKE2' }
sub config_dir           { '/etc/rancher/rke2' }
sub install_url          { 'https://get.rke2.io' }
sub channel_url          { 'https://update.rke2.io/v1-release/channels/stable' }
sub kubeconfig           { '/etc/rancher/rke2/rke2.yaml' }
sub token_file           { '/var/lib/rancher/rke2/server/node-token' }
sub server_token         { '/var/lib/rancher/rke2/server/token' }
sub binary               { 'rke2' }
sub release_url          { 'https://github.com/rancher/rke2/releases/download' }
sub artifact_dir         { '/tmp/rke2-artifacts' }
sub containerd_dir       { '/var/lib/rancher/rke2/agent/etc/containerd' }
sub server_service       { 'rke2-server' }
sub agent_service        { 'rke2-agent.service' }
sub default_start_verb   { 'start' }

# No bundled ingress controller: RKE2 ships the Traefik charts since v1.30.3
# and deploys Traefik by default on new clusters since v1.36; a chart name
# the installed RKE2 does not ship is ignored.
sub default_disable { [ 'rke2-ingress-nginx', 'rke2-traefik', 'rke2-traefik-crd' ] }

# RKE2's own default (10.42.0.0/16) applies unwritten.
sub default_cluster_cidr { undef }

# rke2-server/-agent.service read EnvironmentFile=-/etc/default/%N and set no
# PATH (see ensure_nvidia_runtime_path).
sub env_file {
  my ( $self ) = @_;
  return $self->is_agent ? '/etc/default/rke2-agent' : '/etc/default/rke2-server';
}

sub asset_name {
  my ( $self, $arch ) = @_;
  return "rke2.linux-$arch.tar.gz";
}

# Cilium is the only CNI and replaces kube-proxy
# (Rex::Rancher::Cilium wires kubeProxyReplacement).
sub cilium_config {
  return {
    'cni'                => 'none',
    'disable-kube-proxy' => JSON()->true,
  };
}

sub script_install_cmd {
  my ( $self, $server, $version ) = @_;
  # No server here: an HA join takes it from config.yaml.
  my @env;
  push @env, 'INSTALL_RKE2_TYPE=agent' if $self->is_agent;
  push @env, "INSTALL_RKE2_VERSION=$version" if $version;
  my $env_str = join('', map { "$_ " } @env);
  return "curl -sfL " . $self->install_url . " | ${env_str}sh -";
}

sub artifact_install_cmds {
  my ( $self, $spec, $server, $version ) = @_;
  my @env = ("INSTALL_RKE2_ARTIFACT_PATH=$spec->{dir}");
  push @env, 'INSTALL_RKE2_TYPE=agent' if $self->is_agent;
  push @env, "INSTALL_RKE2_VERSION=$version";
  return ( join(' ', @env) . " sh $spec->{script}" );
}

sub run_server_install_script {
  my ( $self, $server, $version ) = @_;
  # auto_die => 0: the script emits GPG key import info on STDERR which can
  # cause a non-zero exit on some distros (Rocky 10). Success is confirmed
  # after install_server_package by `command -v rke2` instead.
  Rex::Commands::Run::run($self->script_install_cmd($server, $version), auto_die => 0);
}

# After either install method: the binary has to be there (the script's exit
# status is swallowed above). The version check follows in the caller: a
# failed pinned upgrade leaves the old binary in place.
after install_server_package => sub {
  my ( $self ) = @_;
  my $check = Rex::Commands::Run::run("command -v rke2 2>/dev/null", auto_die => 0);
  die "RKE2 install script failed — rke2 binary not found\n"
    unless $check && $check =~ /rke2/;
};

1;

=head1 SYNOPSIS

  my $rke2 = Rex::Rancher::Distribution->new_for('rke2');
  $rke2->service;              # rke2-server
  $rke2->script_install_cmd;   # curl -sfL https://get.rke2.io | sh -

=head1 DESCRIPTION

The RKE2 side of L<Rex::Rancher::Distribution>, the default and the live
verified distribution. Configuration in C</etc/rancher/rke2>, units
C<rke2-server> and C<rke2-agent.service>, installer from
L<https://get.rke2.io> (agents with C<INSTALL_RKE2_TYPE=agent>), release
tarballs C<rke2.linux-ARCH.tar.gz>. A running service is left running on a
re-run unless it has to take something new: a changed C<config.yaml>,
C<registries.yaml>, C</etc/default> file or containerd drop-in, or a new
binary restart it (see L<Rex::Rancher::Distribution/restart_reasons>) --
a new binary only as the version skew rules allow (see
L<Rex::Rancher::Distribution/start_verb>).

On a server the install script's exit status is ignored, because it prints
GPG key import noise that ends non-zero on some hosts (Rocky 10);
C<command -v rke2> after either install method decides instead. With
C<cilium> the server config gets C<cni: none> and C<disable-kube-proxy:
true>. Both units set no C<PATH>, so a host-installed NVIDIA runtime needs
the C<PATH=> line L<Rex::Rancher::Distribution/ensure_nvidia_runtime_path>
writes to C</etc/default/rke2-server> or C</etc/default/rke2-agent>.

The methods are those documented in L<Rex::Rancher::Distribution>.

=head1 SEE ALSO

L<Rex::Rancher::Distribution>, L<Rex::Rancher::Distribution::K3s>

=cut
