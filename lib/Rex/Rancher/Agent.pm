# ABSTRACT: Rancher Kubernetes agent (worker node) installation

package Rex::Rancher::Agent;

use v5.14.4;
use warnings;

use Rex::Commands::File;
use Rex::Commands::Run;
use Rex::Logger;
use Rex::Rancher::Server;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  install_agent
);

my %PATHS = (
  rke2 => {
    config_dir => '/etc/rancher/rke2',
    config_file => '/etc/rancher/rke2/config.yaml',
    registries_file => '/etc/rancher/rke2/registries.yaml',
    service => 'rke2-agent.service',
  },
  k3s => {
    config_dir => '/etc/rancher/k3s',
    config_file => '/etc/rancher/k3s/config.yaml',
    registries_file => '/etc/rancher/k3s/registries.yaml',
    service => 'k3s-agent.service',
  },
);

sub _paths {
  my ($distribution) = @_;
  return $PATHS{$distribution} || die "Unknown distribution: $distribution";
}

=method install_agent

Install and configure a Rancher Kubernetes agent (worker node) and join
an existing cluster.

  install_agent(
    distribution   => 'rke2',                   # 'rke2' (default) or 'k3s'
    server         => 'https://10.0.0.1:9345',  # server URL (required)
    token          => 'K10...',                  # join token (required)
    version        => 'v1.28.4+rke2r1',         # optional, auto-detected
    node_name      => 'worker-01',              # optional
    registry_cache => 'http://cache:5000',      # optional pull-through cache
    registry_upstream => 'https://registry-1.docker.io',  # optional
    registry_name  => 'docker.io',              # optional
  );

=cut

sub install_agent {
  my (%opts) = @_;

  my $distribution = $opts{distribution} // 'rke2';
  my $server       = $opts{server} or die "server is required for install_agent";
  my $token        = $opts{token} or die "token is required for install_agent";
  my $version      = $opts{version};
  my $node_name    = $opts{node_name};

  my $paths = _paths($distribution);

  Rex::Logger::info("Installing $distribution agent to join $server");

  _write_config($paths, $distribution, %opts);
  _write_registries($paths, %opts);
  _run_installer($distribution, $version, $server, $token);
  _enable_service($paths);

  Rex::Logger::info("$distribution agent installed and running");
}

sub _write_config {
  my ($paths, $distribution, %opts) = @_;

  my $server    = $opts{server};
  my $token     = $opts{token};
  my $node_name = $opts{node_name};

  Rex::Logger::info("Writing $distribution agent config");

  run "mkdir -p $paths->{config_dir}", auto_die => 1;

  my @lines;
  push @lines, "server: $server";
  push @lines, "token: $token";
  push @lines, "node-name: $node_name" if $node_name;

  file $paths->{config_file},
    content => join("\n", @lines) . "\n";
}

sub _write_registries {
  my ($paths, %opts) = @_;

  return unless $opts{registries};

  Rex::Rancher::Server::_generate_registries_yaml(
    $paths->{config_dir} . '/', $opts{registries}
  );
}

sub _run_installer {
  my ($distribution, $version, $server, $token) = @_;

  Rex::Logger::info("Running $distribution agent installer");

  if ($distribution eq 'k3s') {
    my @env;
    push @env, "K3S_URL=$server";
    push @env, "K3S_TOKEN=$token";
    push @env, "INSTALL_K3S_VERSION=$version" if $version;
    my $env = join(" ", @env);
    run "curl -sfL https://get.k3s.io | $env sh -s - agent", auto_die => 1;
  }
  else {
    my @env;
    push @env, "INSTALL_RKE2_TYPE=agent";
    push @env, "INSTALL_RKE2_VERSION=$version" if $version;
    my $env = join(" ", @env);
    run "curl -sfL https://get.rke2.io | $env sh -", auto_die => 1;
  }
}

sub _enable_service {
  my ($paths) = @_;

  my $service = $paths->{service};
  Rex::Logger::info("Enabling and starting $service");
  run "systemctl enable $service", auto_die => 1;
  run "systemctl start $service", auto_die => 1;
}

1;

=head1 SYNOPSIS

  use Rex::Rancher::Agent;

  # Join an RKE2 cluster as worker
  install_agent(
    server => 'https://10.0.0.1:9345',
    token  => 'K10abc123...',
  );

  # Join a K3s cluster as worker
  install_agent(
    distribution => 'k3s',
    server       => 'https://10.0.0.1:6443',
    token        => 'K10abc123...',
    version      => 'v1.28.4+k3s1',
    node_name    => 'worker-01',
  );

  # With pull-through registry cache
  install_agent(
    distribution   => 'rke2',
    server         => 'https://10.0.0.1:9345',
    token          => 'K10abc123...',
    registry_cache => 'http://cache.local:5000',
  );

=head1 DESCRIPTION

L<Rex::Rancher::Agent> installs and configures a Rancher Kubernetes
agent (worker node) for either RKE2 or K3s. It handles writing the
agent configuration, setting up registry mirrors, running the
distribution installer, and enabling the agent service.

Registry configuration is shared with L<Rex::Rancher::Server> via
C<_generate_registries_yaml()>.

=head1 SEE ALSO

L<Rex::Rancher>, L<Rex::Rancher::Server>, L<Rex::Rancher::Node>, L<Rex>

=cut
