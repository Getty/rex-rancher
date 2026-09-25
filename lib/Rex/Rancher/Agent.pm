# ABSTRACT: Rancher Kubernetes agent (worker node) installation

package Rex::Rancher::Agent;
our $VERSION = '0.003';
use v5.14.4;
use warnings;

use Rex::Commands::File;
use Rex::Commands::Run;
use Rex::Logger;
use Rex::Rancher::Distribution;
use Rex::Rancher::Options;
use Rex::Rancher::K8s ();
use YAML::PP;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  install_agent
);

=method install_agent

Write the agent configuration, optionally write C<registries.yaml>, run the
distribution installer, enable and start the agent service, and wait until
C<systemctl is-active> reports it active (up to 10 minutes). A service that
ends up C<failed> or never gets active dies with the last 50 lines of its
journal in the message, after the line "It joins the cluster via SERVER --
check that this node can reach that address": an unreachable C<server> is
the most common cause.

Required options:

=over

=item C<server>

URL of the server to join. For RKE2: C<https://SERVER_IP:9345>. For K3s:
C<https://SERVER_IP:6443>.

=item C<token>

Node join token. Obtain from the running server with
L<Rex::Rancher::Server/get_token>.

=back

Optional options:

=over

=item C<distribution>

C<rke2> (default) or C<k3s>; anything else dies before the host is touched.

=item C<version>

Pinned version string, e.g. C<v1.28.4+rke2r1> for RKE2 or C<v1.28.4+k3s1>
for K3s. If omitted, the latest stable release is installed. When given, the
installed binary's C<--version> is checked against it after the installer
ran, and a mismatch dies before the service is started (the K3s install script
runs with C<INSTALL_K3S_SKIP_START>).

The version skew rules of L<Rex::Rancher::Server/install_server>'s
C<version> apply to a running agent the same way (a jump of more than one
minor or a downgrade dies before anything is installed; the next minor
without a pinned C<version> is installed but not restarted onto, with a
warning), and to a stopped one against its installed binary. With C<kubeconfig>, the agent is also never brought to a newer
minor than the control plane (see there).

=item C<kubeconfig>

Local path to a kubeconfig of the cluster (as C<rancher_deploy_server>'s
C<kubeconfig_file> saves it). With it, the control plane's version is read
through the API before anything is written to the host (the lowest
C<kubeletVersion> of the control-plane nodes, see
L<Rex::Rancher::K8s/control_plane_version>), and an agent version of a
newer minor dies: a kubelet must never be newer than the API server. A
newer patch of the same minor is fine. The agent version checked is
C<version>, or the stable channel's (as for C<install_server>); when that
cannot be resolved, the installed binary is checked before the agent is
started, and dies with it installed but not (re)started. An API that does
not answer dies before the host is touched. Without C<kubeconfig> the agent
cannot be checked against the control plane: upgrade the servers first and
pin C<version>.

=item C<install_method>

C<script> (default: C<curl | sh>, unchanged) or C<artifact>: download the
release artifact for the node's architecture on the host, verify it against
the official C<sha256sum-ARCH.txt> (a mismatch dies), and install from it.
Requires C<version>. Details, including the RPM-host caveat for RKE2, in
L<Rex::Rancher::Server/install_server>.

=item C<node_name>

Override the Kubernetes node name. If omitted, the system hostname is used.

=item C<node_labels>

Node labels applied at join time (C<node-label> in C<config.yaml>), as an
arrayref of C<key=value> strings. Same as
L<Rex::Rancher::Server/install_server>'s C<node_labels>; like there, labels
are only read when the agent registers, not on a re-run against a node that
already joined.

=item C<registries>

Private registry mirror configuration hashref. Same structure as
L<Rex::Rancher::Server/install_server>'s C<registries> option. Written to
C<registries.yaml> in the distribution config directory.

=item C<nvidia_runtime_path>

If true, and C<nvidia-container-runtime> is on the host's C<PATH>, write a
C<PATH=> line to C</etc/default/rke2-agent> before the installer runs, so rke2
finds a host-installed NVIDIA runtime at service start (a running agent is
restarted when the file changed). Same behaviour as
L<Rex::Rancher::Server/install_server>'s C<nvidia_runtime_path>; no effect on
k3s. Default: C<0>; L<Rex::Rancher/rancher_deploy_agent> turns it on for
C<gpu =E<gt> 1, gpu_setup =E<gt> 0>.

=back

  install_agent(
    distribution => 'rke2',
    server       => 'https://10.0.0.1:9345',
    token        => 'K10abc123...',
  );

=cut

sub install_agent {
  my (%opts) = @_;

  my $distribution = $opts{distribution} // 'rke2';
  my $server       = $opts{server} or die "server is required for install_agent\n";
  my $token        = $opts{token} or die "token is required for install_agent\n";
  my $version      = $opts{version};
  my $node_name    = $opts{node_name};
  my $method       = Rex::Rancher::Options->resolve_install_method($opts{install_method}, $version);

  my $dist = Rex::Rancher::Distribution->new_for($distribution, role => 'agent');

  # Before anything is written or installed: an agent never goes to a newer
  # minor than the control plane, nor skips or goes back a minor itself.
  my $server_version = _control_plane_version($opts{kubeconfig});
  $dist->check_version_skew(version => $version, server_version => $server_version);

  Rex::Logger::info("Installing $distribution agent to join $server");

  _write_config($dist, %opts);
  _write_registries($dist, %opts);
  # Before the installer and the first start, as on the server.
  $dist->ensure_nvidia_runtime_path if $opts{nvidia_runtime_path};
  _run_installer($dist, $version, $server, $method);
  $dist->verify_installed_version($version);
  # Again with what was installed: the check above had to go without it
  # when the channel did not resolve.
  $dist->check_agent_version($dist->installed_version, $server_version, 1)
    if defined $server_version;
  _enable_service($dist, $server, $version);

  Rex::Logger::info("$distribution agent installed and running");
}

# The control plane's version through the given kubeconfig, or nothing
# without one. Asked for with a kubeconfig, so it has to answer: an API
# error or no version dies before the host is touched.
sub _control_plane_version {
  my ($kubeconfig) = @_;
  return unless defined $kubeconfig && length $kubeconfig;
  my $version = eval { Rex::Rancher::K8s::control_plane_version(kubeconfig => $kubeconfig) };
  die "Could not read the control plane's version through $kubeconfig ("
    . ( $@ =~ s/\s+\z//r ) . "); nothing was installed\n" if $@;
  die "The API behind $kubeconfig reports no control plane version; nothing "
    . "was installed. Omit kubeconfig to join without the version check\n"
    unless defined $version;
  Rex::Logger::info("Control plane runs $version");
  return $version;
}

# Same keys on rke2 and k3s agents; node-label as in the server's
# config.yaml (Rex::Rancher::Server).
sub _build_agent_config {
  my (%opts) = @_;

  my %config = (
    server => $opts{server},
    token  => $opts{token},
  );
  $config{'node-name'} = $opts{node_name} if $opts{node_name};

  if (my $node_labels = $opts{node_labels}) {
    my @labels = ref $node_labels eq 'ARRAY' ? @{$node_labels} : ($node_labels);
    $config{'node-label'} = \@labels;
  }

  return \%config;
}

sub _write_config {
  my ($dist, %opts) = @_;

  Rex::Logger::info("Writing " . $dist->name . " agent config");

  run "mkdir -p " . $dist->config_dir, auto_die => 1;

  $dist->write_secret_file($dist->config_file,
    YAML::PP->new->dump_string(_build_agent_config(%opts)));
}

sub _write_registries {
  my ($dist, %opts) = @_;

  return unless $opts{registries};

  $dist->write_registries($opts{registries});
}

# The token is NOT on any installer line, for either distribution:
# _write_config has already put it into config.yaml, and anything on these
# lines shows up in ps. k3s' script does not start the agent
# (INSTALL_K3S_SKIP_START); _enable_service starts it bounded.
sub _run_installer {
  my ($dist, $version, $server, $method) = @_;

  Rex::Logger::info("Running " . $dist->name . " agent installer");

  if (($method // 'script') eq 'artifact') {
    my $spec = $dist->fetch_artifacts($version);
    run $_, auto_die => 1 for $dist->artifact_install_cmds($spec, $server, $version);
    return;
  }

  run $dist->script_install_cmd($server, $version), auto_die => 1;
}

sub _enable_service {
  my ($dist, $server, $version) = @_;

  my $service = $dist->service;
  # k3s: restart, as the install script did before INSTALL_K3S_SKIP_START,
  # so a re-run still picks up a new binary and config.yaml. rke2's
  # installer never started the agent: start, or restart for a stale
  # containerd config or a change since it started (see
  # Rex::Rancher::Distribution's start_verb).
  my $verb = $dist->start_verb(pinned => ( defined $version && length $version ));
  Rex::Logger::info("Enabling and starting $service");
  run "systemctl enable $service", auto_die => 1;
  # --no-block, same as the server: a start that fails or outlasts systemd's
  # activation timeout ends in wait_for_service, which reports the journal,
  # instead of a bare systemctl error (or, for an agent that cannot reach
  # its server, a Type=notify start that never returns).
  run "systemctl $verb --no-block $service", auto_die => 1;
  # An unreachable server address (a wrong or private IP) is the usual
  # reason an agent never gets active: name it next to the journal.
  $dist->wait_for_service(
    hint => "It joins the cluster via $server -- check that this node can reach that address");
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

  # With a pull-through registry mirror
  install_agent(
    distribution => 'rke2',
    server       => 'https://10.0.0.1:9345',
    token        => 'K10abc123...',
    registries   => {
      mirrors => { 'docker.io' => { endpoint => ['http://cache.local:5000'] } },
    },
  );

=head1 DESCRIPTION

L<Rex::Rancher::Agent> installs and configures a Rancher Kubernetes worker
node for either RKE2 or K3s. It handles:

=over

=item * Writing C<config.yaml> with the server URL, token, and optional node name
and node labels

=item * Writing C<registries.yaml> for private registry mirrors (optional)

=item * Running the official distribution installer via C<curl | sh>, or from a
checksum-verified release artifact (C<install_method =E<gt> 'artifact'>)

=item * Enabling and starting the agent systemd service, and waiting until it
is active (journal tail in the error if it is not)

=back

For RKE2 the installer is fetched from L<https://get.rke2.io> with
C<INSTALL_RKE2_TYPE=agent>. For K3s the installer from L<https://get.k3s.io>
is used with the C<K3S_URL> environment variable and
C<INSTALL_K3S_SKIP_START>: instead of the script's own blocking restart, the
agent is restarted with C<--no-block> and waited on for at most 10 minutes,
so an agent that cannot reach its server dies with its journal instead of
hanging the deploy. A running C<rke2-agent> is only started, which leaves it
alone, unless its C<config.yaml>, C<registries.yaml>,
C</etc/default/rke2-agent>, containerd drop-ins, NVIDIA runtime or binary
changed since it started, or its containerd config is still the output of
L<Rex::GPU> 0.001's template: then it is restarted, as described under
"Re-runs" and "RKE2 installation" in L<Rex::Rancher::Server>, which also
describes the version skew rules that apply to agents as to servers. For both distributions the
token is read from C<config.yaml> and never passed on the installer command
line, where C<ps> would show it. C<config.yaml> and C<registries.yaml> are
written C<0600 root:root>.

Registry configuration uses the same YAML structure and helper as
L<Rex::Rancher::Server>, so mirrors configured for the server are directly
reusable for agents.

=head1 SEE ALSO

L<Rex::Rancher>, L<Rex::Rancher::Server>, L<Rex::Rancher::Node>, L<Rex>

=cut
