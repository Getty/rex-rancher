# ABSTRACT: Rancher Kubernetes server (control plane) installation

package Rex::Rancher::Server;
our $VERSION = '0.003';
use v5.14.4;
use warnings;

use Rex::Commands::File;
use Rex::Commands::Fs;
use Rex::Commands::Run;
use Rex::Logger;
use Rex::Rancher::Distribution;
use YAML::PP;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  install_server
  update_registries
  get_kubeconfig
  get_token
);

=head1 FUNCTIONS

=cut

=method install_server(%opts)

Write the cluster configuration file, optionally write C<registries.yaml>,
install the distribution, start the service, wait until C<systemctl
is-active> reports it active, and then wait until the kubeconfig file is
written to disk by the server process.

Returns C<1> on success. Dies if installation fails, the distribution is
unknown, the installed version differs from a pinned C<version>, or the
service does not become active within 10 minutes. A service that ends up
C<failed> or never gets active makes the C<die> message carry the last 50
lines of its journal (C<journalctl -u SERVICE -n 50 --no-pager>).

Options:

=over

=item C<distribution>

C<rke2> (default) or C<k3s>. B<rke2 is the verified distribution.> The k3s
path carries the configuration kubernetes-ocp verified live (see L</cilium>),
but has not itself been run live through Rex::Rancher.

=item C<token>

Shared secret used for node joining. If omitted, the token the server is
already sealed with (C</var/lib/rancher/rke2/server/token>, K3s:
C</var/lib/rancher/k3s/server/token>) is reused, so re-running
C<install_server> on a live control plane never rotates its token. Only on a
fresh server (no such file) is a new one generated (up to 48 random
alphanumeric characters, never fewer than 32).
A passed C<token> always wins.

The token is written to C<config.yaml> only; it is never put on the installer
command line or into its environment, where C<ps> would show it. C<config.yaml>
is written C<0600 root:root>, including when it already exists.

=item C<server>

URL of an existing server node to join. Used for multi-server HA setups
(omit for the first/only server). For RKE2 the port is C<9345>; for K3s it
is C<6443>.

=item C<tls_san>

Additional TLS Subject Alternative Names for the API server certificate,
as an arrayref or a comma-separated string. Include the load balancer
address, public IP, or DNS name so that kubeconfig clients can connect.

=item C<version>

Pinned version string, e.g. C<v1.30.4+rke2r1> for RKE2 or C<v1.30.4+k3s1>
for K3s, handed to the installer as C<INSTALL_RKE2_VERSION> /
C<INSTALL_K3S_VERSION>. If omitted, the latest stable release is installed.

When given, the version the installed binary reports (C<rke2 --version> /
C<k3s --version>) is compared with it after the installer ran, and a
mismatch dies (on RKE2 before the service is started; the K3s install
script has already restarted it). This catches a pinned
install or upgrade that failed while an older binary is still on the host.

=item C<install_method>

How the distribution gets onto the host. C<script> (default) pipes the
official install script into C<sh> (C<curl -sfL https://get.rke2.io | sh ->,
K3s: C<https://get.k3s.io>), exactly as without this option.

C<artifact> pre-downloads the release artifact for the node's own
architecture (C<uname -m> on the host: C<amd64> or C<arm64>, anything else
dies) from the GitHub release, verifies it against the release's official
C<sha256sum-ARCH.txt> and dies loudly on a mismatch, then runs the install
script against the local file: RKE2 via C<INSTALL_RKE2_ARTIFACT_PATH>
(tarball C<rke2.linux-ARCH.tar.gz>), K3s by installing the binary to
C</usr/local/bin/k3s> and running the script with
C<INSTALL_K3S_SKIP_DOWNLOAD=binary>. Downloads run on the host with C<curl>
(no SFTP, nothing is uploaded) into C</tmp/rke2-artifacts> /
C</tmp/k3s-artifacts>, which are emptied first. Requires C<version>; dies
without one.

On RPM-based hosts (Rocky, RHEL) RKE2's install script uses the tarball
instead of its RPM method when given an artifact path, so no C<rke2-selinux>
package is installed, and a host that already carries RKE2 from RPMs is
refused by the script ("existing RKE2 RPMs").

=item C<node_name>

Kubernetes node name, written as C<node-name> to C<config.yaml>. If omitted,
the system hostname is used.

=item C<disable>

Packaged components to switch off, as an arrayref or a comma-separated
string, written as C<disable> to C<config.yaml>. The names are
distribution-specific. Default: C<['rke2-ingress-nginx', 'rke2-traefik',
'rke2-traefik-crd']> on rke2 (no bundled ingress controller: RKE2 ships the
Traefik charts since v1.30.3, opt-in, and deploys Traefik by default on new
clusters since v1.36; a name the installed RKE2 does not ship is ignored),
C<['traefik', 'servicelb']> on k3s. A given list replaces the default rather
than extending it; C<[]> disables nothing. Independent of C<cilium>.

  # keep the default and also drop metrics-server
  disable => [qw( rke2-ingress-nginx rke2-traefik rke2-traefik-crd
                  rke2-metrics-server )],

=item C<cluster_cidr>

The pod network, one IPv4 CIDR such as C<10.42.0.0/16>, written as
C<cluster-cidr> to C<config.yaml> on RKE2 and K3s alike, with or without
C<cilium>. Anything else (including a dual-stack list) dies before the host
is touched. Every server of a cluster needs the same value (RKE2 refuses a
joining server that differs), and it cannot be changed on a running cluster.
L<Rex::Rancher::Cilium/install_cilium> takes the same value as Cilium's
pool, used in C<cluster-pool> mode (see there). Default: nothing written on
RKE2 (RKE2's own default, C<10.42.0.0/16>, applies); on K3s with C<cilium>
C<10.42.0.0/16> is written, without it nothing.

=item C<node_labels>

Node labels applied at join time, as an arrayref of C<key=value> strings.

=item C<registries>

Private registry mirror configuration. Written to C<registries.yaml> in the
distribution config directory, C<0600 root:root>
(it may hold registry passwords). Structure:

  {
    mirrors => {
      'docker.io' => { endpoint => ['http://registry.internal:5000'] },
    },
    configs => {
      'registry.internal:5000' => {
        auth => { username => 'user', password => 'pass' },
      },
    },
  }

=item C<cilium>

If true (default: C<1>), switch off the distribution's own CNI in the
server config so that Cilium is the only one. Set to C<0> to keep the
distribution's default CNI (Canal on RKE2, Flannel on K3s).

On B<rke2>, C<cni: none> and C<disable-kube-proxy: true> are written,
preparing the node for Cilium with full kube-proxy replacement.

On B<k3s>, C<flannel-backend: none>, C<disable-network-policy: true>,
C<disable-kube-proxy: true> and C<cluster-cidr: 10.42.0.0/16> (or
C<cluster_cidr>) are written:
Flannel, k3s's embedded network policy controller and kube-proxy are
switched off, and Cilium takes over all three with kube-proxy replacement.
C<cluster-cidr> is k3s's own default, written out because Cilium's
cluster-pool IPAM is given the same range (see L<Rex::Rancher::Cilium>). These
are server settings that k3s agents take from the server; an additional
server joining with C<server> gets the same keys, as k3s requires them to
match across servers. The same keys and Cilium values were verified live in
kubernetes-ocp (k3s v1.36.4+k3s1, Cilium 1.20.0, Gateway API v1.6.1); the
k3s path through Rex::Rancher has not been run live, and differs in the
Cilium version it defaults to (see L<Rex::Rancher::Cilium>).

=item C<nvidia_runtime_path>

If true, and C<nvidia-container-runtime> is on the host's C<PATH>, write
C<PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin> to
C</etc/default/rke2-server> before the installer runs. The rke2 unit sets no
C<PATH>, and rke2 looks for the NVIDIA runtime only when the service starts;
without it a host- or vendor-installed toolkit (C</usr/bin>, e.g. DGX OS) is
not wired into containerd. Other lines of the file are kept, an existing
C<PATH=> line is replaced. If the file changed while the service is already
running, the service is restarted (see L</Re-runs>). The GPU
Operator's toolkit (C</usr/local/nvidia/toolkit>) is found by rke2 without
this. No effect on k3s. Default: C<0>; L<Rex::Rancher/rancher_deploy_server>
turns it on for C<gpu =E<gt> 1, gpu_setup =E<gt> 0>.

=back

  install_server(
    distribution => 'rke2',
    token        => 'my-cluster-secret',
    tls_san      => ['loadbalancer.example.com'],
    node_labels  => ['role=control-plane'],
    version      => 'v1.30.4+rke2r1',
    node_name    => 'cp-01',
  );

  # Checksum-verified release artifact instead of curl | sh
  install_server(
    version        => 'v1.30.4+rke2r1',
    install_method => 'artifact',
  );

=cut

sub install_server {
  my (%opts) = @_;

  my $distribution = $opts{distribution} // 'rke2';
  Rex::Logger::info(
    "k3s has not been run live through Rex::Rancher; rke2 is the verified "
      . "distribution.", "warn")
    if $distribution eq 'k3s';
  my $dist         = Rex::Rancher::Distribution->new_for($distribution);
  # Validated before anything touches the host (the token lookup reads it).
  my $method       = Rex::Rancher::Distribution->resolve_install_method($opts{install_method}, $opts{version});
  my $cluster_cidr = Rex::Rancher::Distribution->check_cluster_cidr($opts{cluster_cidr});
  my $token        = _resolve_token($dist, $opts{token});
  my $server       = $opts{server};
  my $tls_san      = $opts{tls_san};
  my $node_labels  = $opts{node_labels};
  my $registries   = $opts{registries};
  my $cilium       = exists $opts{cilium} ? $opts{cilium} : 1;
  my $version      = $opts{version};
  my $node_name    = $opts{node_name};
  my $disable      = $opts{disable};

  Rex::Logger::info("Installing $distribution server (control plane)...");

  # Ensure config directory exists
  file $dist->config_dir . '/', ensure => 'directory';

  # Write config.yaml
  _write_config($dist, $token, $server, $tls_san, $node_labels, $cilium,
    $node_name, $disable, $cluster_cidr);

  # Write registries.yaml if configured
  if ($registries) {
    $dist->write_registries($registries);
  }

  # Before the installer: rke2 looks for the NVIDIA runtime only when its
  # service starts.
  $dist->ensure_nvidia_runtime_path if $opts{nvidia_runtime_path};

  # Install and start
  _install($dist, $server, $version, $method);

  Rex::Logger::info("$distribution server installation complete");

  return 1;
}

=method update_registries(%opts)

Update C<registries.yaml> on an already-running node and restart the
distribution service to pick up the new registry mirror configuration.

Use this to add or change registry mirrors after the cluster is up — for
example, after deploying an in-cluster registry that you want every node
to use as a pull-through cache.

Required options:

=over

=item C<registries>

Registry mirror hashref (same structure as C<install_server>'s C<registries>
option).

=back

Optional options:

=over

=item C<distribution>

C<rke2> (default) or C<k3s>. Controls which service is restarted.

=back

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
  my $dist         = Rex::Rancher::Distribution->new_for($distribution);

  Rex::Logger::info("Updating registries.yaml for $distribution");

  $dist->write_registries($registries);

  # Restart containerd to pick up new config: whichever unit this node runs.
  run $dist->restart_services_cmd, auto_die => 0;

  Rex::Logger::info("Registries updated, containerd restarted");
}

=method get_kubeconfig($distribution)

Read the kubeconfig file from the remote server and return its content as
a string. The file is read directly via C<cat> over SSH; no SFTP is used.

C<$distribution> defaults to C<rke2>.

Note: RKE2 and K3s both write C<https://127.0.0.1> as the server address.
The caller is responsible for substituting the real server address before
saving the kubeconfig for external use. L<Rex::Rancher/rancher_deploy_server>
performs this substitution automatically.

Dies if the file cannot be read.

=cut

sub get_kubeconfig {
  my ($distribution) = @_;
  my $dist = Rex::Rancher::Distribution->new_for($distribution);

  Rex::Logger::info("Retrieving kubeconfig from " . $dist->kubeconfig);

  my $content = run "cat " . $dist->kubeconfig, auto_die => 1;
  return $content;
}

=method get_token($distribution)

Read the node join token from the server and return it as a string
(trailing newline stripped).

C<$distribution> defaults to C<rke2>.

The token is stored at:

=over

=item RKE2: C</var/lib/rancher/rke2/server/node-token>

=item K3s: C</var/lib/rancher/k3s/server/node-token>

=back

Dies if the file cannot be read (e.g. server not yet started).

=cut

sub get_token {
  my ($distribution) = @_;
  my $dist = Rex::Rancher::Distribution->new_for($distribution);

  Rex::Logger::info("Retrieving node token from " . $dist->token_file);

  my $content = run "cat " . $dist->token_file, auto_die => 1;
  chomp $content;
  return $content;
}

# Never rotate the token a control plane is already sealed with: the datastore
# encryption key derives from it at bootstrap and is only re-checked at the
# NEXT start, so a fresh token in config.yaml arms a fatal "bootstrap data
# already found and encrypted with different token" on the next restart.
sub _resolve_token {
  my ($dist, $given) = @_;
  return $given if defined $given;
  my $existing = _existing_server_token($dist);
  if (defined $existing) {
    Rex::Logger::info("Reusing existing cluster token from " . $dist->server_token);
    return $existing;
  }
  return _generate_token();
}

# Read over the exec channel (no SFTP). A missing or unreadable file means
# "fresh server" and degrades to undef; it must never abort the install.
sub _existing_server_token {
  my ($dist) = @_;
  my $out = run "cat " . $dist->server_token . " 2>/dev/null", auto_die => 0;
  return unless $? == 0 && defined $out;
  $out =~ s/\s+\z//;
  return length $out ? $out : undef;
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

sub _build_server_config {
  my ($dist, $token, $server, $tls_san, $node_labels, $cilium,
    $node_name, $disable, $cluster_cidr) = @_;

  my %config = (
    'token' => $token,
  );

  # With cilium, Cilium is the only CNI and replaces kube-proxy on both
  # distributions (Rex::Rancher::Cilium wires kubeProxyReplacement); which
  # keys that takes is the distribution's cilium_config.
  %config = ( %config, %{ $dist->cilium_config } ) if $cilium;

  # A given cluster_cidr is written on both distributions, with or without
  # cilium; every server of a cluster must carry the same one (RKE2 refuses
  # a join that differs). Without it rke2 keeps its own default, unwritten.
  $config{'cluster-cidr'} = $cluster_cidr if defined $cluster_cidr;

  # Packaged components to switch off. Undef means the distribution's
  # default_disable (rke2: ingress-nginx + traefik charts, unknown chart
  # names are ignored by RKE2; k3s: traefik + servicelb). An explicit empty
  # list disables nothing. Independent of cilium.
  my @disable = !defined $disable       ? @{ $dist->default_disable }
              : ref $disable eq 'ARRAY' ? @{$disable}
              :                           split(/,/, $disable);
  $config{'disable'} = \@disable if @disable;

  $config{server} = $server if $server;
  $config{'node-name'} = $node_name if $node_name;

  if ($tls_san) {
    my @sans = ref $tls_san eq 'ARRAY' ? @{$tls_san} : split(/,/, $tls_san);
    $config{'tls-san'} = \@sans;
  }

  if ($node_labels) {
    my @labels = ref $node_labels eq 'ARRAY' ? @{$node_labels} : ($node_labels);
    $config{'node-label'} = \@labels;
  }

  return \%config;
}

sub _write_config {
  my ($dist, $token, $server, $tls_san, $node_labels, $cilium,
    $node_name, $disable, $cluster_cidr) = @_;

  my $config =
    _build_server_config($dist, $token, $server, $tls_san, $node_labels, $cilium,
      $node_name, $disable, $cluster_cidr);

  my $config_file = $dist->config_file;
  Rex::Logger::info("Writing config to $config_file");

  $dist->write_secret_file($config_file,
    YAML::PP->new(boolean => 'JSON::PP')->dump_string($config));
}

#
# Install and start. Server and agent share the steps in
# Rex::Rancher::Distribution; what differs between rke2 and k3s is there too.
#

sub _install {
  my ($dist, $server, $version, $method) = @_;

  # No token on any installer line: it is already in config.yaml (written
  # before the installer runs), and anything on these lines shows up in ps.
  $dist->install_server_package($server, $version, $method);
  # The binary being there is not enough when a version is pinned: a failed
  # pinned upgrade leaves the old one in place.
  $dist->verify_installed_version($version);

  # Enable and start the service. --no-block: return immediately; RKE2 first
  # start pulls many images and exceeds systemctl's default 90s activation
  # timeout, and k3s' Type=notify unit blocks until k3s is up, forever for
  # an HA join that cannot reach its first server. Start or restart as the
  # distribution wants it (start_verb), then the bounded wait.
  my $service = $dist->service;
  run "systemctl enable " . $service, auto_die => 1;
  run "systemctl " . $dist->start_verb . " --no-block " . $service,
    auto_die => 1;

  $dist->wait_for_service;

  # Then wait until kubeconfig is written — API readiness is checked locally
  # by the caller via Rex::Rancher::K8s::wait_for_api after saving the file.
  _wait_for_kubeconfig($dist);
}

#
# Wait until the kubeconfig file appears on the remote host.
# API readiness is checked locally by the caller via Rex::Rancher::K8s::wait_for_api.
#

sub _wait_for_kubeconfig {
  my ($dist) = @_;
  my $kubeconfig = $dist->kubeconfig;

  Rex::Logger::info("Waiting for " . $dist->service . " to write kubeconfig...");

  for my $i (1..60) {
    my $out = run "test -f $kubeconfig && echo yes", auto_die => 0;
    if ($? == 0 && ($out // '') =~ /yes/) {
      Rex::Logger::info("  Kubeconfig ready at $kubeconfig");
      return 1;
    }
    Rex::Logger::info("  Not ready yet ($i/60), waiting...");
    sleep 5;
  }

  Rex::Logger::info($dist->service . " kubeconfig did not appear — check manually", "warn");
  return 0;
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

  # Join additional control plane node (HA setup)
  install_server(
    distribution => 'rke2',
    token        => 'my-cluster-secret',
    server       => 'https://first-server:9345',
  );

  # Retrieve kubeconfig and join token from a running server
  my $kubeconfig = get_kubeconfig('rke2');
  my $token      = get_token('rke2');

  # Update registry mirrors on an already-running node
  update_registries(
    distribution => 'rke2',
    registries   => {
      mirrors => { 'docker.io' => { endpoint => ['http://cache:5000'] } },
    },
  );

=head1 DESCRIPTION

L<Rex::Rancher::Server> handles control plane installation for both RKE2
and K3s Kubernetes distributions. It provides a unified interface for
installing, configuring, and managing server nodes.

=head2 RKE2 installation

By default the official install script at L<https://get.rke2.io> is fetched
and run via C<curl -sfL … | sh ->; with C<install_method =E<gt> 'artifact'>
the checksum-verified release tarball is installed instead (see
L</install_server>). The service is started with C<--no-block> to avoid
systemd's 90-second activation timeout (RKE2's first start pulls many
container images), then polled with C<systemctl is-active> for up to 10
minutes; a C<failed> or never-active service dies with its journal tail.
A running C<rke2-server> is left running on a re-run (C<systemctl start>)
unless it has to take something new (see L</Re-runs>). It is also restarted
if C<agent/etc/containerd/config.toml> is still the output of the C<config.toml.tmpl> that L<Rex::GPU> 0.001 wrote (only
C<imports> and C<version = 2>, no C<SystemdCgroup>, sandbox image or registry
mirrors) and that template is gone (L<Rex::GPU> 0.002's C<gpu_setup> removes
it), the service is restarted once, with a warning, so rke2 regenerates its
containerd config. If the template is still there, nothing is restarted and a
warning names what to remove and the restart command. K3s is restarted on
every run anyway (below), so it regenerates its config either way.
After that the function waits until the kubeconfig file appears at
C</etc/rancher/rke2/rke2.yaml>; API readiness is confirmed separately by the
caller using L<Rex::Rancher::K8s/wait_for_api>.

=head2 Re-runs

A running RKE2 reads its configuration only when it starts, so
C<install_server> (and L<Rex::Rancher::Agent/install_agent> for
C<rke2-agent>) restarts a running service with C<--no-block>, logging why,
when the host has changed under it since its main process started:

=over

=item * C<config.yaml>, C<config.yaml.d/>, C<registries.yaml> or
C</etc/default/rke2-server> (C<-agent>) modified, or a containerd
C<config.toml.tmpl>, C<config-v3.toml.tmpl> or C<config-v3.toml.d/> drop-in
(as L<Rex::GPU> writes) — by modification time, and Rex rewrites a file only
when its content differs, so the same options twice change nothing;

=item * C<nvidia-container-runtime> installed or upgraded (by inode change
time);

=item * an installed C<rke2> binary of another version than the running one.

=back

Nothing changed: C<systemctl start>, the service keeps running. Changes
made by hand or left by an interrupted earlier run count as well. What
cannot be determined (no C<ps>) counts as unchanged, with a warning. Details
in L<Rex::Rancher::Distribution/restart_reasons>.

A restart takes this server's API and etcd member down for its duration and
touches no other node. Several servers of one HA cluster restarting at the
same time can lose etcd quorum: deploy them one after another (Rex's
default), not in parallel. K3s is restarted on every run, as its install
script rewrites the unit each time.

=head2 K3s installation

The official install script at L<https://get.k3s.io> is used (piped, or run
against the checksum-verified binary with C<install_method =E<gt>
'artifact'>), with C<K3S_URL> set when joining an existing server. The
script runs with C<INSTALL_K3S_SKIP_START>: instead of its own blocking
restart, C<k3s.service> is restarted with C<--no-block>, then the same
C<systemctl is-active> wait (at most 10 minutes, journal tail on failure) as
for RKE2 follows, so a joining server that cannot reach the first one dies
instead of hanging the deploy. Then the kubeconfig wait. The token is read from
C<config.yaml> and never passed on the command line. Traefik and
ServiceLB are disabled by default (C<disable> in C<config.yaml>, see
L</install_server>) to leave room for Cilium and external load balancers.

=head2 Config layout

Both distributions use C</etc/rancher/E<lt>distE<gt>/config.yaml> with the
same key names (C<token>, C<tls-san>, C<node-name>, C<node-label>,
C<disable>, C<cni>, etc.). When
C<cilium =E<gt> 1> (the default), the distribution's own CNI is switched off
so that Cilium is the only one: on RKE2 C<cni: none> and
C<disable-kube-proxy: true>, on K3s C<flannel-backend: none>,
C<disable-network-policy: true>, C<disable-kube-proxy: true> and
C<cluster-cidr: 10.42.0.0/16>; on both, Cilium's kube-proxy replacement takes
over. See L</install_server>'s C<cilium>.

Registry mirrors are written to C<registries.yaml> in the same directory.
Both files are C<0600 root:root>: C<config.yaml> holds the join token,
C<registries.yaml> may hold registry credentials.

=head1 SEE ALSO

L<Rex::Rancher>, L<Rex::Rancher::Node>, L<Rex::Rancher::Agent>,
L<Rex::Rancher::Cilium>, L<Rex::Rancher::K8s>, L<Rex>

=cut
