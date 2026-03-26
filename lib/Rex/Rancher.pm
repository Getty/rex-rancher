# ABSTRACT: Rancher Kubernetes (RKE2/K3s) deployment automation for Rex

package Rex::Rancher;

use v5.14.4;
use warnings;

our $VERSION = '0.001';

use Rex::Rancher::Node;
use Rex::Rancher::Server;
use Rex::Rancher::Agent;
use Rex::Rancher::Cilium;
use Rex::Logger;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  rancher_deploy_server
  rancher_deploy_agent
);

=method rancher_deploy_server(%opts)

Full control plane deployment: prepare node, install Rancher K8s
distribution, and set up Cilium CNI.

If C<gpu =E<gt> 1> is passed and L<Rex::GPU> is installed, GPU detection
and driver installation is performed automatically.

Options:

=over

=item C<distribution> — C<rke2> (default) or C<k3s>

=item C<gpu> — detect and set up GPU drivers (default: C<0>, requires L<Rex::GPU>)

=item C<hostname> — Node hostname (optional)

=item C<domain> — Domain name (optional)

=item C<timezone> — Timezone (default: C<UTC>)

=item C<token> — Cluster token

=item C<tls_san> — Additional TLS SAN for API server cert

=back

=cut

sub rancher_deploy_server {
  my (%opts) = @_;
  my $distribution = $opts{distribution} // 'rke2';

  prepare_node(%opts);

  _gpu_setup_if_requested($distribution, %opts);

  install_server(%opts);

  install_cilium(distribution => $distribution);

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

  Rex::GPU::gpu_setup(containerd_config => $distribution);
}

1;

=head1 SYNOPSIS

  use Rex -feature => ['1.4'];
  use Rex::Rancher;

  # Deploy RKE2 control plane (no GPU)
  task "deploy_server", sub {
    rancher_deploy_server(
      distribution => 'rke2',
      hostname     => 'cp-01',
      domain       => 'k8s.example.com',
      token        => 'my-secret',
      tls_san      => 'k8s.example.com',
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

For fine-grained control, use the individual modules directly:

=over

=item L<Rex::Rancher::Node> — Node preparation

=item L<Rex::Rancher::Server> — Control plane installation

=item L<Rex::Rancher::Agent> — Worker node installation

=item L<Rex::Rancher::Cilium> — Cilium CNI management

=back

=head1 SEE ALSO

L<Rex>, L<Rex::GPU>

=cut
