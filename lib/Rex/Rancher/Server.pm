# ABSTRACT: Rancher Kubernetes server (control plane) installation

package Rex::Rancher::Server;

use v5.14.4;
use warnings;

use Rex::Commands::File;
use Rex::Commands::Fs;
use Rex::Commands::Run;
use Rex::Logger;
use YAML::PP;
use JSON::MaybeXS;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  install_server
  update_registries
  get_kubeconfig
  get_token
);

my %PATHS = (
  rke2 => {
    config_dir  => '/etc/rancher/rke2/',
    service     => 'rke2-server',
    install_url => 'https://get.rke2.io',
    kubeconfig  => '/etc/rancher/rke2/rke2.yaml',
    token_file  => '/var/lib/rancher/rke2/server/node-token',
  },
  k3s => {
    config_dir  => '/etc/rancher/k3s/',
    service     => 'k3s',
    install_url => 'https://get.k3s.io',
    kubeconfig  => '/etc/rancher/k3s/k3s.yaml',
    token_file  => '/var/lib/rancher/k3s/server/node-token',
  },
);

=head1 FUNCTIONS

=cut

sub _paths {
  my ($distribution) = @_;
  $distribution //= 'rke2';

  die "Unknown distribution: $distribution (expected 'rke2' or 'k3s')\n"
    unless exists $PATHS{$distribution};

  return { %{$PATHS{$distribution}} };
}

=method install_server(%opts)

Install and start a Rancher Kubernetes server (control plane) node.

Options:

=over

=item C<distribution> — C<rke2> (default) or C<k3s>

=item C<token> — shared secret for joining nodes to the cluster

=item C<server> — URL of existing server to join (for HA; omit for first node)

=item C<tls_san> — additional TLS SAN entries (arrayref or comma-separated string)

=item C<node_labels> — node labels (arrayref of C<key=value> strings)

=item C<registries> — private registry mirror config (hashref). Structure: C<< { mirrors => { "docker.io" => { endpoint => ["https://registry.example.com"] } }, configs => { ... } } >>. Written to C<registries.yaml> in the config directory.

=item C<cilium> — use Cilium as CNI (default: C<1>). Sets C<cni: none> and C<disable-kube-proxy: true>. Set to C<0> to keep RKE2's built-in Canal CNI.

=back

  install_server(
    distribution => 'rke2',
    token        => 'my-cluster-secret',
    tls_san      => ['loadbalancer.example.com'],
    node_labels  => ['role=control-plane'],
  );

=cut

sub install_server {
  my (%opts) = @_;

  my $distribution = $opts{distribution} // 'rke2';
  my $paths        = _paths($distribution);
  my $token        = $opts{token} // _generate_token();
  my $server       = $opts{server};
  my $tls_san      = $opts{tls_san};
  my $node_labels  = $opts{node_labels};
  my $registries   = $opts{registries};
  my $cilium       = exists $opts{cilium} ? $opts{cilium} : 1;

  Rex::Logger::info("Installing $distribution server (control plane)...");

  # Ensure config directory exists
  file $paths->{config_dir}, ensure => 'directory';

  # Write config.yaml
  _write_config($paths, $token, $server, $tls_san, $node_labels, $cilium);

  # Write registries.yaml if configured
  if ($registries) {
    _generate_registries_yaml($paths->{config_dir}, $registries);
  }

  # Install and start
  if ($distribution eq 'k3s') {
    _install_k3s($paths, $token, $server);
  }
  else {
    _install_rke2($paths);
  }

  Rex::Logger::info("$distribution server installation complete");

  return 1;
}

=method update_registries(%opts)

Update the registries.yaml on an existing node and restart containerd
to pick up the new configuration. Use this after deploying a registry
into the cluster to make it available to all nodes.

  update_registries(
    distribution => 'rke2',
    registries   => {
      mirrors => {
        'docker.io'         => { endpoint => ['http://registry.internal:5000'] },
        'registry.internal' => { endpoint => ['http://registry.internal:5000'] },
      },
    },
  );

=cut

sub update_registries {
  my (%opts) = @_;

  my $distribution = $opts{distribution} // 'rke2';
  my $registries   = $opts{registries} or die "update_registries requires 'registries' option\n";
  my $paths        = _paths($distribution);

  Rex::Logger::info("Updating registries.yaml for $distribution");

  _generate_registries_yaml($paths->{config_dir}, $registries);

  # Restart containerd to pick up new config
  if ($distribution eq 'rke2') {
    run "systemctl restart rke2-server.service 2>/dev/null || systemctl restart rke2-agent.service 2>/dev/null",
      auto_die => 0;
  }
  else {
    run "systemctl restart k3s.service 2>/dev/null || systemctl restart k3s-agent.service 2>/dev/null",
      auto_die => 0;
  }

  Rex::Logger::info("Registries updated, containerd restarted");
}

=method get_kubeconfig($distribution)

Retrieve the kubeconfig content from the server. Returns the file content
as a string.

C<$distribution> defaults to C<rke2>.

=cut

sub get_kubeconfig {
  my ($distribution) = @_;
  my $paths = _paths($distribution);

  Rex::Logger::info("Retrieving kubeconfig from " . $paths->{kubeconfig});

  my $content = run "cat " . $paths->{kubeconfig}, auto_die => 1;
  return $content;
}

=method get_token($distribution)

Retrieve the node join token from the server. Returns the token string.

C<$distribution> defaults to C<rke2>.

=cut

sub get_token {
  my ($distribution) = @_;
  my $paths = _paths($distribution);

  Rex::Logger::info("Retrieving node token from " . $paths->{token_file});

  my $content = run "cat " . $paths->{token_file}, auto_die => 1;
  chomp $content;
  return $content;
}

sub _generate_token {
  my $token = run "head -c 36 /dev/urandom | base64 | tr -d '\\n/+='  | head -c 48",
    auto_die => 0;
  chomp $token;
  die "Failed to generate random token\n" unless $token && length($token) >= 32;
  Rex::Logger::info("Generated cluster token (auto)");
  return $token;
}

#
# Config file generation
#

sub _write_config {
  my ($paths, $token, $server, $tls_san, $node_labels, $cilium) = @_;

  my %config = (
    'token' => $token,
  );

  if ($cilium) {
    $config{'cni'}                = 'none';
    $config{'disable-kube-proxy'} = JSON()->true;
  }

  $config{'disable'} = ['rke2-ingress-nginx'];

  $config{server} = $server if $server;

  if ($tls_san) {
    my @sans = ref $tls_san eq 'ARRAY' ? @{$tls_san} : split(/,/, $tls_san);
    $config{'tls-san'} = \@sans;
  }

  if ($node_labels) {
    my @labels = ref $node_labels eq 'ARRAY' ? @{$node_labels} : ($node_labels);
    $config{'node-label'} = \@labels;
  }

  my $config_file = $paths->{config_dir} . "config.yaml";
  Rex::Logger::info("Writing config to $config_file");

  file $config_file,
    content => YAML::PP->new(boolean => 'JSON::PP')->dump_string(\%config);
}

#
# RKE2 installation (pre-download artifact approach)
#

sub _install_rke2 {
  my ($paths) = @_;

  Rex::Logger::info("Installing RKE2 via install script...");

  # Download and run the RKE2 install script.
  # auto_die => 0: the script emits GPG key import info on STDERR which can
  # cause a non-zero exit on some distros (Rocky 10). Verify via rpm/dpkg instead.
  run "curl -sfL " . $paths->{install_url} . " | sh -", auto_die => 0;
  my $check = run "command -v rke2 2>/dev/null", auto_die => 0;
  die "RKE2 install script failed — rke2 binary not found\n"
    unless $check && $check =~ /rke2/;

  # Enable and start the service
  run "systemctl enable " . $paths->{service}, auto_die => 1;
  # --no-block: return immediately; RKE2 first start pulls many images and
  # exceeds systemctl's default 90s activation timeout.
  run "systemctl start --no-block " . $paths->{service}, auto_die => 1;

  # Wait only until kubeconfig is written — API readiness is checked locally
  # by the caller via Rex::Rancher::K8s::wait_for_api after saving the file.
  _wait_for_kubeconfig($paths);
}

#
# K3s installation (simple curl | sh approach)
#

sub _install_k3s {
  my ($paths, $token, $server) = @_;

  Rex::Logger::info("Installing K3s via install script...");

  my @env;
  push @env, "K3S_TOKEN=$token";

  if ($server) {
    push @env, "K3S_URL=$server";
  }

  my $env_str = join(" ", @env);
  my $cmd = "curl -sfL " . $paths->{install_url}
    . " | $env_str sh -s - server"
    . " --disable=traefik"
    . " --disable=servicelb"
    . " --write-kubeconfig-mode=644";

  run $cmd, auto_die => 1;

  _wait_for_kubeconfig($paths);
}

#
# Wait until the kubeconfig file appears on the remote host.
# API readiness is checked locally by the caller via Rex::Rancher::K8s::wait_for_api.
#

sub _wait_for_kubeconfig {
  my ($paths) = @_;
  my $kubeconfig = $paths->{kubeconfig};

  Rex::Logger::info("Waiting for " . $paths->{service} . " to write kubeconfig...");

  for my $i (1..60) {
    my $out = run "test -f $kubeconfig && echo yes", auto_die => 0;
    if ($? == 0 && ($out // '') =~ /yes/) {
      Rex::Logger::info("  Kubeconfig ready at $kubeconfig");
      return 1;
    }
    Rex::Logger::info("  Not ready yet ($i/60), waiting...");
    sleep 5;
  }

  Rex::Logger::info($paths->{service} . " kubeconfig did not appear — check manually", "warn");
  return 0;
}

sub _generate_registries_yaml {
  my ($config_dir, $registries) = @_;

  my $registries_file = $config_dir . "registries.yaml";
  Rex::Logger::info("Writing registries config to $registries_file");

  file $registries_file,
    content => YAML::PP->new(boolean => 'JSON::PP')->dump_string($registries);
}

1;

=head1 SYNOPSIS

  use Rex::Rancher::Server;

  # Install RKE2 server (default)
  install_server(
    token   => 'my-cluster-secret',
    tls_san => ['lb.example.com'],
  );

  # Install K3s server
  install_server(
    distribution => 'k3s',
    token        => 'my-cluster-secret',
    tls_san      => ['lb.example.com'],
  );

  # Join additional control plane node (HA)
  install_server(
    distribution => 'rke2',
    token        => 'my-cluster-secret',
    server       => 'https://first-server:9345',
  );

  # Retrieve kubeconfig and token
  my $kubeconfig = get_kubeconfig('rke2');
  my $token      = get_token('k3s');

=head1 DESCRIPTION

L<Rex::Rancher::Server> handles control plane installation for both RKE2
and K3s Kubernetes distributions. It provides a unified interface for
installing, configuring, and managing server nodes.

RKE2 uses the pre-download artifact approach via the official install
script at L<https://get.rke2.io>. K3s uses the simpler curl-pipe-sh
method with inline flags to disable Traefik and ServiceLB.

Both distributions share the same config file layout under
C</etc/rancher/E<lt>distE<gt>/> and the same registries.yaml format.

=head1 SEE ALSO

L<Rex::Rancher>, L<Rex::Rancher::Node>, L<Rex::Rancher::Agent>, L<Rex::Rancher::Cilium>, L<Rex>

=cut
