# ABSTRACT: Rancher Kubernetes server (control plane) installation

package Rex::Rancher::Server;

use v5.14.4;
use warnings;

use Rex::Commands::File;
use Rex::Commands::Fs;
use Rex::Commands::Run;
use Rex::Logger;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  install_server
  get_kubeconfig
  get_token
);

my %PATHS = (
  rke2 => {
    config_dir  => '/etc/rancher/rke2/',
    service     => 'rke2-server',
    install_url => 'https://get.rke2.io',
    kubeconfig  => '/etc/rancher/rke2/rke2.yaml',
    kubectl     => '/var/lib/rancher/rke2/bin/kubectl',
    token_file  => '/var/lib/rancher/rke2/server/node-token',
  },
  k3s => {
    config_dir  => '/etc/rancher/k3s/',
    service     => 'k3s',
    install_url => 'https://get.k3s.io',
    kubeconfig  => '/etc/rancher/k3s/k3s.yaml',
    kubectl     => 'kubectl',
    token_file  => '/var/lib/rancher/k3s/server/node-token',
  },
);

=head1 FUNCTIONS

=cut

=method _paths($distribution)

Returns a hashref of paths for the given distribution (C<rke2> or C<k3s>).
Keys: C<config_dir>, C<service>, C<install_url>, C<kubeconfig>, C<kubectl>,
C<token_file>.

Dies if the distribution is not recognized.

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

=item C<registries> — private registry config (hashref, see L</_generate_registries_yaml>)

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
  my $token        = $opts{token} // die "install_server requires a 'token' option\n";
  my $server       = $opts{server};
  my $tls_san      = $opts{tls_san};
  my $node_labels  = $opts{node_labels};
  my $registries   = $opts{registries};

  Rex::Logger::info("Installing $distribution server (control plane)...");

  # Ensure config directory exists
  file $paths->{config_dir}, ensure => 'directory';

  # Write config.yaml
  _write_config($paths, $token, $server, $tls_san, $node_labels);

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

#
# Config file generation
#

sub _write_config {
  my ($paths, $token, $server, $tls_san, $node_labels) = @_;

  my @lines;

  push @lines, "token: $token";

  if ($server) {
    push @lines, "server: $server";
  }

  if ($tls_san) {
    my @sans = ref $tls_san eq 'ARRAY' ? @{$tls_san} : split(/,/, $tls_san);
    push @lines, "tls-san:";
    for my $san (@sans) {
      $san =~ s/^\s+|\s+$//g;
      push @lines, "  - $san";
    }
  }

  if ($node_labels) {
    my @labels = ref $node_labels eq 'ARRAY' ? @{$node_labels} : ($node_labels);
    push @lines, "node-label:";
    for my $label (@labels) {
      push @lines, "  - \"$label\"";
    }
  }

  my $config_file = $paths->{config_dir} . "config.yaml";
  Rex::Logger::info("Writing config to $config_file");

  file $config_file,
    content => join("\n", @lines) . "\n";
}

#
# RKE2 installation (pre-download artifact approach)
#

sub _install_rke2 {
  my ($paths) = @_;

  Rex::Logger::info("Installing RKE2 via install script...");

  # Download and run the RKE2 install script
  run "curl -sfL " . $paths->{install_url} . " | sh -", auto_die => 1;

  # Enable and start the service
  run "systemctl enable " . $paths->{service}, auto_die => 1;
  run "systemctl start " . $paths->{service}, auto_die => 1;

  _wait_for_service($paths);
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

  _wait_for_service($paths);
}

#
# Wait for the service to become ready
#

sub _wait_for_service {
  my ($paths) = @_;

  Rex::Logger::info("Waiting for " . $paths->{service} . " to become ready...");

  my $kubectl = $paths->{kubectl};
  my $kubeconfig = $paths->{kubeconfig};

  # Wait up to 120 seconds for the node to be ready
  my $ready = 0;
  for my $i (1..24) {
    my $output = run "$kubectl --kubeconfig=$kubeconfig get nodes 2>&1", auto_die => 0;
    if ($output && $output =~ /\bReady\b/ && $output !~ /\bNotReady\b/) {
      $ready = 1;
      last;
    }
    Rex::Logger::info("  Not ready yet, waiting... ($i/24)");
    run "sleep 5", auto_die => 0;
  }

  if ($ready) {
    Rex::Logger::info($paths->{service} . " is ready");
  }
  else {
    Rex::Logger::info($paths->{service} . " may not be fully ready yet — check manually", "warn");
  }
}

=method _generate_registries_yaml($config_dir, $registries)

Generate a C<registries.yaml> file for private container registry
configuration. Shared between Server and Agent modules.

C<$registries> is a hashref:

  {
    mirrors => {
      "docker.io" => {
        endpoint => ["https://registry.example.com"],
      },
    },
    configs => {
      "registry.example.com" => {
        auth => {
          username => "user",
          password => "pass",
        },
        tls => {
          insecure_skip_verify => 1,
        },
      },
    },
  }

=cut

sub _generate_registries_yaml {
  my ($config_dir, $registries) = @_;

  my @lines;

  if ($registries->{mirrors}) {
    push @lines, "mirrors:";
    for my $mirror (sort keys %{$registries->{mirrors}}) {
      push @lines, "  \"$mirror\":";
      my $conf = $registries->{mirrors}{$mirror};
      if ($conf->{endpoint}) {
        push @lines, "    endpoint:";
        for my $ep (@{$conf->{endpoint}}) {
          push @lines, "      - \"$ep\"";
        }
      }
    }
  }

  if ($registries->{configs}) {
    push @lines, "configs:";
    for my $registry (sort keys %{$registries->{configs}}) {
      push @lines, "  \"$registry\":";
      my $conf = $registries->{configs}{$registry};
      if ($conf->{auth}) {
        push @lines, "    auth:";
        for my $key (sort keys %{$conf->{auth}}) {
          push @lines, "      $key: \"$conf->{auth}{$key}\"";
        }
      }
      if ($conf->{tls}) {
        push @lines, "    tls:";
        for my $key (sort keys %{$conf->{tls}}) {
          my $val = $conf->{tls}{$key};
          # Booleans
          if ($val eq '1' || $val eq 'true') {
            push @lines, "      $key: true";
          }
          elsif ($val eq '0' || $val eq 'false') {
            push @lines, "      $key: false";
          }
          else {
            push @lines, "      $key: \"$val\"";
          }
        }
      }
    }
  }

  my $registries_file = $config_dir . "registries.yaml";
  Rex::Logger::info("Writing registries config to $registries_file");

  file $registries_file,
    content => join("\n", @lines) . "\n";
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

L<Rex>, L<Rex::GPU>

=cut
