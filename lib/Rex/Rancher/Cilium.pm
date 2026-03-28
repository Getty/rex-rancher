# ABSTRACT: Cilium CNI installation for Rancher Kubernetes distributions

package Rex::Rancher::Cilium;

use v5.14.4;
use warnings;

use Rex::Commands::File;
use Rex::Commands::Gather;
use Rex::Commands::Run;
use Rex::Logger;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  install_cilium
  upgrade_cilium
);

use constant CILIUM_VERSION     => '1.17.0';
use constant CILIUM_CLI_VERSION => 'v0.16.23';

=head1 FUNCTIONS

=cut

=method install_cilium(%opts)

Install Cilium CNI on a Rancher Kubernetes cluster (RKE2 or K3s).

Handles:

=over

=item Cilium CLI binary installation

=item Helm values generation for the target distribution

=item Cilium installation via the CLI

=back

Options:

  install_cilium(
    distribution => 'rke2',       # 'rke2' or 'k3s' (default: 'rke2')
    version      => '1.17.0',     # Cilium version (default: CILIUM_VERSION)
    cli_version  => 'v0.16.23',   # CLI version (default: CILIUM_CLI_VERSION)
    api_server   => 'https://127.0.0.1:6443',  # optional
  );

=cut

sub install_cilium {
  my (%opts) = @_;

  my $distribution = $opts{distribution} // 'rke2';
  my $version      = $opts{version}      // CILIUM_VERSION;
  my $cli_version  = $opts{cli_version}  // CILIUM_CLI_VERSION;
  my $api_server   = $opts{api_server};

  Rex::Logger::info("Installing Cilium $version on $distribution cluster");

  _install_cilium_cli($cli_version);

  my $paths = _paths_for($distribution);
  my $values_file = _write_helm_values($distribution, $version, $paths);

  my @cmd = (
    "cilium install",
    "--version $version",
    "--helm-values $values_file",
  );
  push @cmd, "--set kubeProxyReplacement=true" if $distribution eq 'rke2';
  push @cmd, "--api-server $api_server" if $api_server;

  my $env = "KUBECONFIG=$paths->{kubeconfig}";
  my $install_cmd = "$env " . join(" ", @cmd);

  Rex::Logger::info("Running: $install_cmd");
  run $install_cmd, auto_die => 1;

  Rex::Logger::info("Cilium $version installed on $distribution cluster");
}

=method upgrade_cilium(%opts)

Upgrade an existing Cilium installation on a Rancher Kubernetes cluster.

Options are the same as C<install_cilium>, plus:

  upgrade_cilium(
    distribution => 'rke2',
    version      => '1.17.0',
  );

=cut

sub upgrade_cilium {
  my (%opts) = @_;

  my $distribution = $opts{distribution} // 'rke2';
  my $version      = $opts{version}      // CILIUM_VERSION;
  my $cli_version  = $opts{cli_version}  // CILIUM_CLI_VERSION;
  my $api_server   = $opts{api_server};

  Rex::Logger::info("Upgrading Cilium to $version on $distribution cluster");

  _install_cilium_cli($cli_version);

  my $paths = _paths_for($distribution);
  my $values_file = _write_helm_values($distribution, $version, $paths);

  my @cmd = (
    "cilium upgrade",
    "--version $version",
    "--helm-values $values_file",
  );
  push @cmd, "--api-server $api_server" if $api_server;

  my $env = "KUBECONFIG=$paths->{kubeconfig}";
  my $upgrade_cmd = "$env " . join(" ", @cmd);

  Rex::Logger::info("Running: $upgrade_cmd");
  run $upgrade_cmd, auto_die => 1;

  Rex::Logger::info("Cilium upgraded to $version on $distribution cluster");
}

#
# Cilium CLI installation
#

sub _install_cilium_cli {
  my ($cli_version) = @_;

  # Check if already installed at the right version
  my $current = run "cilium version --client 2>/dev/null | head -1", auto_die => 0;
  if ($current && $current =~ /\Q$cli_version\E/) {
    Rex::Logger::info("Cilium CLI $cli_version already installed");
    return;
  }

  Rex::Logger::info("Installing Cilium CLI $cli_version");

  my $arch = run "uname -m", auto_die => 1;
  chomp $arch;
  $arch = 'amd64' if $arch eq 'x86_64';
  $arch = 'arm64' if $arch eq 'aarch64';

  my $url = "https://github.com/cilium/cilium-cli/releases/download/$cli_version/cilium-linux-$arch.tar.gz";

  run "curl -fsSL '$url' -o /tmp/cilium-linux-$arch.tar.gz", auto_die => 1;
  run "tar xzf /tmp/cilium-linux-$arch.tar.gz -C /tmp cilium", auto_die => 1;
  run "mv /tmp/cilium /usr/local/bin/cilium", auto_die => 1;
  run "chmod 755 /usr/local/bin/cilium", auto_die => 1;
  run "rm -f /tmp/cilium-linux-$arch.tar.gz", auto_die => 0;

  Rex::Logger::info("Cilium CLI $cli_version installed to /usr/local/bin/cilium");
}

#
# Distribution-specific paths
#

sub _paths_for {
  my ($distribution) = @_;

  if ($distribution eq 'rke2') {
    return {
      kubeconfig  => '/etc/rancher/rke2/rke2.yaml',
      cni_bin     => '/opt/cni/bin',
      cni_conf    => '/etc/cni/net.d',
      socket_path => '/run/k3s/containerd/containerd.sock',
    };
  }
  elsif ($distribution eq 'k3s') {
    return {
      kubeconfig  => '/etc/rancher/k3s/k3s.yaml',
      cni_bin     => '/opt/cni/bin',
      cni_conf    => '/etc/cni/net.d',
      socket_path => '/run/k3s/containerd/containerd.sock',
    };
  }
  else {
    die "Unknown distribution: $distribution (expected 'rke2' or 'k3s')\n";
  }
}

#
# Helm values generation
#

sub _write_helm_values {
  my ($distribution, $version, $paths) = @_;

  my $values_file = "/tmp/cilium-values-$distribution.yaml";

  my $cni_exclusive = $distribution eq 'rke2' ? 'false' : 'true';

  my $values = <<YAML;
cni:
  binPath: $paths->{cni_bin}
  confPath: $paths->{cni_conf}
  exclusive: $cni_exclusive
ipam:
  mode: kubernetes
YAML

  if ($distribution eq 'rke2') {
    $values .= <<'YAML';
kubeProxyReplacement: true
k8sServiceHost: 127.0.0.1
k8sServicePort: "6443"
operator:
  replicas: 1
YAML
  }
  elsif ($distribution eq 'k3s') {
    $values .= <<'YAML';
operator:
  replicas: 1
YAML
  }

  file $values_file, content => $values;

  Rex::Logger::info("Wrote Helm values to $values_file");
  return $values_file;
}

1;

=head1 SYNOPSIS

  use Rex::Rancher::Cilium;

  # Install Cilium on an RKE2 cluster
  install_cilium(
    distribution => 'rke2',
  );

  # Install Cilium on a K3s cluster
  install_cilium(
    distribution => 'k3s',
    version      => '1.17.0',
  );

  # Upgrade an existing installation
  upgrade_cilium(
    distribution => 'rke2',
    version      => '1.17.0',
  );

=head1 DESCRIPTION

L<Rex::Rancher::Cilium> provides Cilium CNI installation and management
for Rancher Kubernetes distributions (RKE2 and K3s). It handles:

=over

=item * Cilium CLI binary download and installation

=item * Distribution-specific Helm values generation

=item * Cilium installation and upgrades via the CLI

=back

The module generates appropriate Helm values for each distribution,
handling differences in CNI paths, containerd socket locations, and
kube-proxy replacement settings.

=head1 SEE ALSO

L<Rex::Rancher>, L<Rex::Rancher::Node>, L<Rex>

=cut
