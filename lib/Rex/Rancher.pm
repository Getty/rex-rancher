# ABSTRACT: Rancher Kubernetes (RKE2/K3s) deployment automation for Rex

package Rex::Rancher;

use v5.14.4;
use warnings;

our $VERSION = '0.001';

use Rex::Rancher::Node;
use Rex::Rancher::Server;
use Rex::Rancher::Agent;
use Rex::Rancher::Cilium;
use Rex::Rancher::K8s;
use Rex::Logger;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  rancher_deploy_server
  rancher_deploy_agent
  wait_for_api
  untaint_node
  deploy_nvidia_device_plugin
);

=method rancher_deploy_server(%opts)

Full control plane deployment: prepare node, install Rancher K8s
distribution, and set up Cilium CNI.

If C<gpu =E<gt> 1> is passed and L<Rex::GPU> is installed, GPU detection
and driver installation is performed automatically. After Cilium is
installed, the NVIDIA device plugin DaemonSet is deployed via the
Kubernetes API and the cluster waits for C<nvidia.com/gpu> resources
to appear on the node.

Options:

=over

=item C<distribution> — C<rke2> (default) or C<k3s>

=item C<gpu> — detect and set up GPU drivers (default: C<0>, requires L<Rex::GPU>)

=item C<reboot> — reboot after driver install and wait for host to reconnect (default: C<0>, only meaningful with C<gpu =E<gt> 1>)

=item C<hostname> — Node hostname (optional)

=item C<domain> — Domain name (optional)

=item C<timezone> — Timezone (default: C<UTC>)

=item C<token> — Cluster token

=item C<tls_san> — Additional TLS SAN for API server cert. The first entry
is also used as the server address in the saved local kubeconfig.

=item C<kubeconfig_file> — Local path to save the cluster kubeconfig after
the server is up (optional). If not given, no kubeconfig is saved locally
and the NVIDIA device plugin step is skipped even with C<gpu =E<gt> 1>.

=back

=cut

sub _check_connection {
  my $conn = Rex::get_current_connection() or return;
  return if Rex::is_local();

  my $type = eval { $conn->{conn}->get_connection_type() } // '';
  return if $type eq 'LibSSH';

  my $sftp = eval { Rex::get_sftp() };
  return if $sftp && eval { $sftp->stat('/'); 1 };

  die "This host has no SFTP subsystem and you are not using the LibSSH "
    . "connection backend.\n"
    . "Add 'set connection => \"LibSSH\"' to your Rexfile and install "
    . "Rex::LibSSH to deploy to SFTP-less hosts.\n";
}

sub rancher_deploy_server {
  my (%opts) = @_;
  my $distribution    = $opts{distribution}    // 'rke2';
  my $kubeconfig_file = $opts{kubeconfig_file};

  _check_connection();
  prepare_node(%opts);

  _gpu_setup_if_requested($distribution, %opts);

  install_server(%opts);

  # Fetch and save kubeconfig locally, then wait for the API from this machine.
  # install_server only waits for the kubeconfig file to appear on the remote;
  # actual API readiness is confirmed here via Rex::Rancher::K8s::wait_for_api.
  my $local_kc = _save_kubeconfig_locally($distribution, $kubeconfig_file, %opts);
  wait_for_api(kubeconfig => $local_kc) if $local_kc;

  install_cilium(distribution => $distribution);

  if ($opts{gpu} && $local_kc) {
    deploy_nvidia_device_plugin(kubeconfig => $local_kc);
  }

  Rex::Logger::info("$distribution server deployment complete");
}

=method rancher_deploy_agent(%opts)

Full worker node deployment: prepare node, join existing cluster.

Options: Same as L</rancher_deploy_server> plus:

=over

=item C<server> — Server URL to join (required)

=item C<token> — Join token (required)

=back

=cut

sub rancher_deploy_agent {
  my (%opts) = @_;
  my $distribution = $opts{distribution} // 'rke2';

  prepare_node(%opts);

  _gpu_setup_if_requested($distribution, %opts);

  install_agent(%opts);

  Rex::Logger::info("$distribution agent deployment complete");
}

sub _gpu_setup_if_requested {
  my ($distribution, %opts) = @_;

  return unless $opts{gpu};

  my $loaded = eval { require Rex::GPU; Rex::GPU->import(); 1 };
  unless ($loaded) {
    die "gpu => 1 requested but Rex::GPU is not installed. Install the Rex-GPU distribution.\n";
  }

  Rex::GPU::gpu_setup(
    containerd_config => $distribution,
    reboot            => ($opts{reboot} // 0),
  );
}

sub _save_kubeconfig_locally {
  my ($distribution, $output_file, %opts) = @_;

  return unless $output_file;

  my $content = eval { get_kubeconfig($distribution) };
  unless ($content) {
    Rex::Logger::info("Could not fetch kubeconfig from remote — skipping local save", "warn");
    return;
  }

  # RKE2/K3s writes 127.0.0.1 in the kubeconfig; patch to the real address
  my $server_addr = _kubeconfig_server_addr(%opts);
  if ($server_addr) {
    $content =~ s{https://127\.0\.0\.1:(\d+)}{https://$server_addr:$1}g;
  }

  open(my $fh, '>', $output_file)
    or do {
      Rex::Logger::info("Could not write kubeconfig to $output_file: $!", "warn");
      return;
    };
  print $fh $content;
  close $fh;

  Rex::Logger::info("Kubeconfig saved to $output_file");
  return $output_file;
}

sub _kubeconfig_server_addr {
  my (%opts) = @_;
  return $opts{kubeconfig_server} if $opts{kubeconfig_server};
  my $tls_san = $opts{tls_san};
  return unless $tls_san;
  my @sans = ref $tls_san eq 'ARRAY' ? @{$tls_san} : split(/,/, $tls_san);
  return $sans[0] if @sans;
  return;
}

1;

=head1 SYNOPSIS

  use Rex -feature => ['1.4'];
  use Rex::Rancher;

  # Deploy RKE2 control plane (no GPU)
  task "deploy_server", sub {
    rancher_deploy_server(
      distribution    => 'rke2',
      hostname        => 'cp-01',
      domain          => 'k8s.example.com',
      token           => 'my-secret',
      tls_san         => 'k8s.example.com',
      kubeconfig_file => "$ENV{HOME}/.kube/mycluster.yaml",
    );
  };

  # Deploy RKE2 control plane with GPU support
  task "deploy_gpu_server", sub {
    rancher_deploy_server(
      distribution    => 'rke2',
      gpu             => 1,    # requires Rex::GPU installed
      reboot          => 1,    # reboot after driver install
      hostname        => 'gpu-cp-01',
      domain          => 'k8s.example.com',
      token           => 'my-secret',
      tls_san         => 'gpu-cp-01.k8s.example.com',
      kubeconfig_file => "$ENV{HOME}/.kube/gpu-cluster.yaml",
    );
  };

  # Deploy K3s worker with GPU support
  task "deploy_gpu_worker", sub {
    rancher_deploy_agent(
      distribution => 'k3s',
      gpu          => 1,    # requires Rex::GPU installed
      hostname     => 'gpu-01',
      domain       => 'k8s.example.com',
      server       => 'https://10.0.0.1:6443',
      token        => 'K10...',
    );
  };

=head1 DESCRIPTION

L<Rex::Rancher> provides complete Kubernetes cluster deployment automation
for Rancher distributions (RKE2 and K3s) using the L<Rex> orchestration
framework.

GPU support is optional — pass C<gpu =E<gt> 1> and install L<Rex::GPU>
separately. Without it, Rex::Rancher works perfectly for non-GPU nodes.

When deploying a GPU server node, the full pipeline runs automatically:

=over

=item 1. Node preparation (hostname, timezone, swap off)

=item 2. GPU driver install + NVIDIA Container Toolkit (via L<Rex::GPU>)

=item 3. RKE2/K3s server install + Cilium CNI

=item 4. NVIDIA device plugin DaemonSet (via L<Rex::Rancher::K8s>)

=back

Pass C<kubeconfig_file> to save the cluster kubeconfig locally. This is
required for the NVIDIA device plugin step (step 4) to work.

For fine-grained control, use the individual modules directly:

=over

=item L<Rex::Rancher::Node> — Node preparation

=item L<Rex::Rancher::Server> — Control plane installation

=item L<Rex::Rancher::Agent> — Worker node installation

=item L<Rex::Rancher::Cilium> — Cilium CNI management

=item L<Rex::Rancher::K8s> — Kubernetes API operations

=back

=head1 SEE ALSO

L<Rex>, L<Rex::GPU>, L<Rex::Rancher::K8s>

=cut
