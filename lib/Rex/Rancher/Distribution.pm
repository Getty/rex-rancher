# ABSTRACT: What RKE2 and K3s differ in, and the host steps they share

package Rex::Rancher::Distribution;
our $VERSION = '0.003';
use v5.14.4;
use Moo;
use Rex::Commands::File ();
use Rex::Commands::Run ();
use Rex::Logger ();
use YAML::PP;
use namespace::autoclean;

# No `use utf8` here, on purpose: the die messages carry UTF-8 em dashes as
# byte strings, exactly as Rex::Rancher::Server always emitted them.

=attr role

C<server> (default) or C<agent>: which side of the distribution this object
speaks for. L</service> and L</env_file>, and the installer command lines
(L</script_install_cmd>, L</artifact_install_cmds>) follow it; everything
else is the same for both.

=cut

has role => (
  is      => 'ro',
  default => 'server',
  isa     => sub {
    die "role must be 'server' or 'agent'\n"
      unless defined $_[0] && ( $_[0] eq 'server' || $_[0] eq 'agent' );
  },
);

=method is_agent

True for C<< role => 'agent' >>.

=cut

sub is_agent { $_[0]->role eq 'agent' }

=method distribution_classes

  Rex::Rancher::Distribution->distribution_classes
  # { rke2 => 'Rex::Rancher::Distribution::RKE2', k3s => '...::K3s' }

The distribution names C<distribution> options accept, each with the class
that implements it. A subclass may override it to add or replace one.

=cut

sub distribution_classes {
  return {
    rke2 => 'Rex::Rancher::Distribution::RKE2',
    k3s  => 'Rex::Rancher::Distribution::K3s',
  };
}

=method new_for

  my $dist  = Rex::Rancher::Distribution->new_for('k3s');
  my $agent = Rex::Rancher::Distribution->new_for('rke2', role => 'agent');

The object for a C<distribution> option value; C<undef> means C<rke2>.
Anything not in L</distribution_classes> dies with C<Unknown distribution:
NAME (expected 'rke2' or 'k3s')>. Further arguments go to C<new>.

=cut

sub new_for {
  my ( $class, $name, %args ) = @_;
  $name //= 'rke2';
  my $impl = $class->distribution_classes->{$name}
    // die "Unknown distribution: $name (expected 'rke2' or 'k3s')\n";
  return $impl->new(%args);
}

=method name

C<rke2> or C<k3s>, as in the C<distribution> option.

=method label

C<RKE2> or C<K3s>, for log lines.

=method config_dir

C</etc/rancher/rke2> / C</etc/rancher/k3s>, without a trailing slash.

=method install_url

The official install script: C<https://get.rke2.io> / C<https://get.k3s.io>.

=method kubeconfig

The kubeconfig the server writes (C<rke2.yaml> / C<k3s.yaml>).

=method token_file

The node join token the server writes (C<server/node-token>).

=method server_token

The token the control plane is sealed with (C<server/token>).

=method default_disable

A new arrayref of the packaged components switched off when C<disable> is
not given.

=method default_cluster_cidr

The pod network written out (and handed to Cilium's cluster-pool) when
C<cilium> is on and C<cluster_cidr> is not given: C<10.42.0.0/16> on K3s,
C<undef> on RKE2, which keeps its own default unwritten.

=method binary

The distribution binary (C<rke2> / C<k3s>), asked for C<--version>.

=method release_url

The GitHub release download base the artifacts come from.

=method artifact_dir

Where C<install_method =E<gt> 'artifact'> downloads to on the host.

=method containerd_dir

The directory holding the generated containerd C<config.toml>.

=method server_service

The server's systemd unit: C<rke2-server> / C<k3s>.

=method agent_service

The agent's systemd unit: C<rke2-agent.service> / C<k3s-agent.service>.

=method env_file

The C<EnvironmentFile> of the L</role>'s unit that gets the C<PATH> for the
NVIDIA runtime lookup, or C<undef> where none is needed (K3s).

=method default_start_verb

How the service is started when its containerd config is not stale:
C<start> (RKE2: a running service is restarted only for
L</restart_reasons>) or C<restart> (K3s, on every run, as its install
script did).

=method asset_name

  $dist->asset_name('arm64')   # rke2.linux-arm64.tar.gz / k3s-arm64

The release artifact for a GOARCH.

=method cilium_config

The C<config.yaml> keys that leave pod networking, network policy and
kube-proxy to Cilium, as a new hashref with real booleans.

=method script_install_cmd

  $dist->script_install_cmd($server, $version)

The C<curl | sh> install line for the L</role>. C<$server> (join URL) and
C<$version> may be C<undef>. The token is never on it.

=method artifact_install_cmds

  $dist->artifact_install_cmds($spec, $server, $version)

The command lines that install from a verified L</fetch_artifacts> spec, in
order, for the L</role>. Each has to succeed.

=method run_server_install_script

  $dist->run_server_install_script($server, $version)

Run L</script_install_cmd> for a server, with the exit-status handling the
distribution's install script needs.

=cut

=method service

The unit of the L</role>: L</server_service> or L</agent_service>.

=cut

sub service {
  my ( $self ) = @_;
  return $self->is_agent ? $self->agent_service : $self->server_service;
}

=method config_file

C<config.yaml> in L</config_dir>.

=method registries_file

C<registries.yaml> in L</config_dir>.

=cut

sub config_file     { $_[0]->config_dir.'/config.yaml' }
sub registries_file { $_[0]->config_dir.'/registries.yaml' }

=method cni_bin_dir

Where the kubelet of either distribution looks for CNI binaries once its
own CNI is off, C</opt/cni/bin>: Cilium's C<cni.binPath>.

=method cni_conf_dir

Where it looks for CNI configuration, C</etc/cni/net.d>: Cilium's
C<cni.confPath>.

=cut

sub cni_bin_dir  { '/opt/cni/bin' }
sub cni_conf_dir { '/etc/cni/net.d' }

=method restart_services_cmd

The line L<Rex::Rancher::Server/update_registries> runs: restart the server
unit, or the agent unit if that fails.

=cut

sub restart_services_cmd {
  my ( $self ) = @_;
  return 'systemctl restart '.$self->server_service.'.service 2>/dev/null || systemctl restart '
    .$self->agent_service.' 2>/dev/null';
}

#
# Option checks (pure -- they die before anything touches the host)
#

=method resolve_install_method

  my $method = Rex::Rancher::Distribution->resolve_install_method($method, $version);

C<script> (default) or C<artifact>; anything else dies, and so does
C<artifact> without a version.

=cut

sub resolve_install_method {
  my ( $self, $method, $version ) = @_;
  $method //= 'script';
  die "Unknown install_method: $method (expected 'script' or 'artifact')\n"
    unless $method eq 'script' || $method eq 'artifact';
  die "install_method 'artifact' requires a version (e.g. v1.30.4+rke2r1)\n"
    if $method eq 'artifact' && !$version;
  return $method;
}

=method check_cluster_cidr

  Rex::Rancher::Distribution->check_cluster_cidr($cidr);

Returns C<$cidr> when it is one IPv4 CIDR, C<undef> for C<undef>, and dies
otherwise (Cilium's pool is IPv4 only here, so no dual-stack).

=cut

sub check_cluster_cidr {
  my ( $self, $cidr ) = @_;
  return unless defined $cidr;
  my @part = $cidr =~ m{\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})\z};
  die "cluster_cidr must be one IPv4 CIDR such as 10.42.0.0/16, got '$cidr' "
    . "(dual-stack is not supported: Cilium's pool is IPv4 here)\n"
    unless @part && !grep({ $_ > 255 } @part[0 .. 3]) && $part[4] <= 32;
  return $cidr;
}

#
# Release artifacts (install_method => 'artifact')
#

=method goarch

  Rex::Rancher::Distribution->goarch("aarch64\n")   # arm64

The GOARCH release artifacts are named by, from C<uname -m> output. Dies
for anything but amd64 and arm64.

=cut

sub goarch {
  my ( $self, $uname ) = @_;
  $uname //= '';
  $uname =~ s/\s+\z//;
  my %goarch = (
    x86_64  => 'amd64',
    amd64   => 'amd64',
    aarch64 => 'arm64',
    arm64   => 'arm64',
  );
  return $goarch{$uname}
    // die "Unsupported node architecture '$uname' for install_method 'artifact'"
    . " (amd64 and arm64 only)\n";
}

=method artifact_spec

  my $spec = $dist->artifact_spec($arch, $version);

Where the install script, the artifact and its checksum file come from and
go to: a hashref with C<dir>, C<script>, C<script_url>, C<asset>,
C<asset_url>, C<sums> and C<sums_url>. Dies without a version or for one
with characters a URL or shell line must not carry.

=cut

sub artifact_spec {
  my ( $self, $arch, $version ) = @_;

  die "install_method 'artifact' requires a version\n" unless $version;
  die "Invalid version '$version'\n" unless $version =~ /\A[A-Za-z0-9._+-]+\z/;

  (my $url_version = $version) =~ s/\+/%2B/g;
  my $base  = $self->release_url . '/' . $url_version;
  my $dir   = $self->artifact_dir;
  my $asset = $self->asset_name($arch);
  my $sums  = "sha256sum-$arch.txt";

  return {
    dir        => $dir,
    script     => "$dir/install.sh",
    script_url => $self->install_url,
    asset      => $asset,
    asset_url  => "$base/$asset",
    sums       => $sums,
    sums_url   => "$base/$sums",
  };
}

=method expected_sha256

  $dist->expected_sha256($sums_text, $asset)

The checksum for exactly C<$asset> in an official C<sha256sum-ARCH.txt>, or
nothing. Exact name match: C<k3s> does not pick up
C<k3s-airgap-images-...>.

=cut

sub expected_sha256 {
  my ( $self, $sums_text, $asset ) = @_;
  for my $line (split /\n/, $sums_text // '') {
    return lc $1 if $line =~ /\A\s*([0-9a-fA-F]{64})\s+\*?\Q$asset\E\s*\z/;
  }
  return;
}

=method sha256_of

The first field of C<sha256sum FILE> output, or nothing.

=cut

sub sha256_of {
  my ( $self, $out ) = @_;
  return lc $1 if ($out // '') =~ /\A\s*([0-9a-fA-F]{64})\b/;
  return;
}

=method verify_sha256

  $dist->verify_sha256($expected, $actual, $asset)

Returns C<1> when both are there and equal, dies otherwise.

=cut

sub verify_sha256 {
  my ( $self, $expected, $actual, $asset ) = @_;
  die "No checksum for $asset in the release's sha256sum file\n"
    unless defined $expected;
  die "Could not compute sha256 of downloaded $asset\n"
    unless defined $actual;
  die "Checksum mismatch for $asset: expected $expected, got $actual\n"
    unless $expected eq $actual;
  return 1;
}

=method download_cmd

  $dist->download_cmd($url, $dest, $progress)

The C<curl> line that downloads C<$url> to C<$dest> on the host; with
C<$progress> it shows a progress bar.

=cut

sub download_cmd {
  my ( $self, $url, $dest, $progress ) = @_;
  # --progress-bar keeps output flowing during the ~60 MB tarball download,
  # so a long silent curl does not look like a hung channel.
  my $flags = $progress ? '-fL --progress-bar' : '-fsSL';
  return "curl $flags -o '$dest' '$url' 2>&1";
}

=method fetch_artifacts

  my $spec = $dist->fetch_artifacts($version);

Download install script, artifact and checksum file on the host (C<curl>,
no SFTP, no upload) into an emptied L</artifact_dir>, for the host's own
architecture, and verify the artifact. Dies on any failure. Returns the
L</artifact_spec>.

=cut

sub fetch_artifacts {
  my ( $self, $version ) = @_;
  my $distribution = $self->name;

  my $arch = $self->goarch(Rex::Commands::Run::run("uname -m", auto_die => 1));
  my $spec = $self->artifact_spec($arch, $version);
  my $dir  = $spec->{dir};

  Rex::Logger::info("Downloading $distribution $version artifacts for $arch to $dir");

  Rex::Commands::Run::run("rm -rf '$dir' && mkdir -p '$dir'", auto_die => 1);

  for my $dl (
    [ $spec->{script_url}, $spec->{script},             0 ],
    [ $spec->{sums_url},   "$dir/$spec->{sums}",        0 ],
    [ $spec->{asset_url},  "$dir/$spec->{asset}",       1 ],
  ) {
    my ($url, $dest, $progress) = @{$dl};
    my $out = Rex::Commands::Run::run($self->download_cmd($url, $dest, $progress), auto_die => 0);
    die "Download failed: $url\n"
      . ($progress ? "If this 404s, $distribution $version publishes no build for '$arch'.\n" : '')
      . ($out // '') . "\n"
      unless $? == 0;
  }

  my $sums   = Rex::Commands::Run::run("cat '$dir/$spec->{sums}'", auto_die => 1);
  my $actual = Rex::Commands::Run::run("sha256sum '$dir/$spec->{asset}'", auto_die => 1);
  # scalar(): both return empty on no match; in this list they must stay undef.
  $self->verify_sha256(scalar($self->expected_sha256($sums, $spec->{asset})),
    scalar($self->sha256_of($actual)), $spec->{asset});
  Rex::Logger::info("  $spec->{asset}: sha256 verified");

  return $spec;
}

#
# Server install step: artifact or script, then whatever the distribution
# needs to confirm it.
#

=method install_server_package

  $dist->install_server_package($server, $version, $method);

Put the distribution onto a server host with C<$method> (C<script> or
C<artifact>). Installing only: the version check and the service start
are the caller's.

=cut

sub install_server_package {
  my ( $self, $server, $version, $method ) = @_;

  if (($method // 'script') eq 'artifact') {
    my $spec = $self->fetch_artifacts($version);
    Rex::Logger::info("Installing " . $self->label . " from verified artifact $spec->{asset}...");
    # auto_die => 1: with an artifact path RKE2's script takes its tarball
    # method, which has no GPG key import (the Rocky 10 noise that
    # Rex::Rancher::Distribution::RKE2 swallows is the RPM method's), so a
    # non-zero exit here is a real failure.
    Rex::Commands::Run::run($_, auto_die => 1)
      for $self->artifact_install_cmds($spec, $server, $version);
  }
  else {
    Rex::Logger::info("Installing " . $self->label . " via install script...");
    $self->run_server_install_script($server, $version);
  }
}

#
# Installed version
#

=method parse_version_output

The version in C<rke2 --version> / C<k3s --version> output, or nothing.

=cut

# "rke2 version v1.30.4+rke2r1 (abc)" / "k3s version v1.30.4+k3s1 (abc)"
sub parse_version_output {
  my ( $self, $out ) = @_;
  return $1 if ($out // '') =~ /^(?:rke2|k3s) version (\S+)/m;
  return;
}

=method same_version

C<1> when both versions are given and equal, ignoring a leading C<v>.

=cut

sub same_version {
  my ( $self, $want, $got ) = @_;
  return 0 unless defined $want && defined $got;
  my ($w, $g) = ($want, $got);
  s/\Av// for $w, $g;
  return $w eq $g ? 1 : 0;
}

=method verify_installed_version

  $dist->verify_installed_version($version);

Without C<$version> returns C<1> at once. Otherwise asks L</binary> for its
version and dies unless it is C<$version>: a failed pinned install or
upgrade leaves the old binary in place.

=cut

sub verify_installed_version {
  my ( $self, $version ) = @_;
  return 1 unless $version;

  my $distribution = $self->name;
  my $binary = $self->binary;
  my $out    = Rex::Commands::Run::run("$binary --version 2>&1", auto_die => 0);
  my $got    = $self->parse_version_output($out);
  die "Could not determine installed $distribution version ($binary --version):\n"
    . ($out // '') . "\n"
    unless defined $got;
  die "Installed $distribution version is $got, expected $version — the "
    . "install or upgrade did not take effect\n"
    unless $self->same_version($version, $got);
  Rex::Logger::info("  $distribution $got installed");
  return 1;
}

#
# Service start and wait
#

=method start_verb

C<start> or C<restart> for the L</service>. Reads the host.

C<restart> when a running service's containerd C<config.toml> is still the
output of L<Rex::GPU> 0.001's bare C<config.toml.tmpl> and the template is
gone, with a warning, so it regenerates that config; a template still in
place only warns with the command to run. Otherwise L</default_start_verb>,
and where that is C<start> (RKE2), C<restart> when L</restart_reasons> has
any, logging them: a running service reads its configuration only when it
starts.

=cut

sub start_verb {
  my ( $self ) = @_;
  return 'restart' if $self->_stale_containerd_restart;

  # k3s restarts anyway. A `start` of a running rke2 is a no-op, so it is
  # turned into a restart exactly when the service runs on something older
  # than what is on disk now.
  my $default = $self->default_start_verb;
  return $default unless $default eq 'start';
  my @reasons = $self->restart_reasons;
  return $default unless @reasons;
  Rex::Logger::info("Restarting " . $self->service . ", which reads these only when "
    . "it starts: " . join('; ', @reasons));
  return 'restart';
}

# Rex::GPU 0.001 wrote agent/etc/containerd/config.toml.tmpl as a bare
# `imports = [...]` + `version = 2`. rke2 renders a template instead of its
# own config, so config.toml became exactly that: no SystemdCgroup, sandbox
# image or registry mirrors. Rex::GPU 0.002's gpu_setup removes the template
# but deliberately restarts nothing, and config.toml is rewritten only when
# the service starts. So: config.toml still in that shape and the template
# gone -> restart a running service once; the regenerated config no longer
# matches, so the next re-run starts (a no-op) again. Template still there
# -> a restart would render the same file: warn with what to do.
sub _stale_containerd_restart {
  my ( $self ) = @_;
  my $distribution = $self->name;
  my $service = $self->service;

  my $dir    = $self->containerd_dir;
  my $config = Rex::Commands::Run::run("cat $dir/config.toml 2>/dev/null", auto_die => 0);
  return 0 unless $self->is_bare_template_output($config);

  Rex::Commands::Run::run("test -e $dir/config.toml.tmpl", auto_die => 0);
  if ($? == 0) {
    Rex::Logger::info("$dir/config.toml.tmpl holds only imports and version = 2 (as "
      . "Rex::GPU 0.001 wrote it) and replaces ${distribution}'s own containerd config: "
      . "no SystemdCgroup, sandbox image or registry mirrors. Remove it (Rex::GPU "
      . "0.002's gpu_setup does) and run: systemctl restart $service", 'warn');
    return 0;
  }

  Rex::Commands::Run::run("systemctl is-active --quiet $service", auto_die => 0);
  # Not running: the start renders a fresh config.toml anyway.
  return 0 unless $? == 0;
  Rex::Logger::info("$dir/config.toml was rendered from a config.toml.tmpl that is "
    . "gone (Rex::GPU 0.001's); restarting $service so it regenerates its "
    . "containerd config", 'warn');
  return 1;
}

=method restart_watch

The paths the L</role>'s service reads only when it starts and that
Rex::Rancher or L<Rex::GPU> write:
L</config_file>, C<config.yaml.d>, L</registries_file>, L</env_file> (if
any), and in L</containerd_dir> C<config.toml.tmpl>, C<config-v3.toml.tmpl>
and the C<config-v3.toml.d> drop-ins (where L<Rex::GPU> puts
C<99-nvidia.toml>). Paths that do not exist are fine.

Not the distribution's own output (the kubeconfig, C<config.toml>), which
it rewrites on every start.

=cut

sub restart_watch {
  my ( $self ) = @_;
  my $containerd = $self->containerd_dir;
  return (
    $self->config_file,
    $self->config_dir.'/config.yaml.d',
    $self->registries_file,
    ( defined $self->env_file ? ( $self->env_file ) : () ),
    "$containerd/config.toml.tmpl",
    "$containerd/config-v3.toml.tmpl",
    "$containerd/config-v3.toml.d",
  );
}

=method restart_reasons

  my @why = $dist->restart_reasons;

Why the running L</service> would have to be restarted to run what is on
the host now, as log-ready strings; empty when it is not running or nothing
changed. Reads the host:

=over

=item * a L</restart_watch> path modified (mtime) after the service's main
process started. Rex's C<file> leaves a file with unchanged content
untouched, so a re-run with the same options changes nothing; a change left
behind by an interrupted earlier run, or made by hand, counts too.

=item * an C<nvidia-container-runtime> on the C<PATH> whose inode changed
(ctime: a package install or upgrade) after the process started, since the
distribution looks for it only at start.

=item * the running binary (C</proc/PID/exe --version>) reports another
version than the installed L</binary>.

=back

What it cannot determine (no C<ps>, a binary that does not answer
C<--version>) counts as unchanged, with a warning that names it.

=cut

sub restart_reasons {
  my ( $self ) = @_;
  my $service = $self->service;
  my $pid = $self->parse_main_pid(Rex::Commands::Run::run(
    "systemctl show -p MainPID $service 2>/dev/null", auto_die => 0));
  return unless $pid;

  my @reasons;

  # Epoch seconds, both on the host's clock. Only files written after that
  # second count, so one written in the second the process started is missed;
  # everything here is written before the start, minutes earlier.
  my $since = Rex::Commands::Run::run(
    "echo \$(( \$(date +%s) - \$(ps -o etimes= -p $pid) ))", auto_die => 0);
  if (($since // '') =~ /\A\s*(\d+)\s*\z/) {
    $since = $1;
    my $paths   = join(' ', map { "'$_'" } $self->restart_watch);
    my $changed = Rex::Commands::Run::run("find $paths -newermt \@$since 2>/dev/null", auto_die => 0);
    my @changed = grep { length } split /\n/, $changed // '';
    push @reasons, "changed since it started: " . join(', ', @changed) if @changed;

    # ctime: dpkg and rpm keep the package's mtime.
    my $runtime = Rex::Commands::Run::run('p=$(command -v nvidia-container-runtime) && '
      . "find \"\$p\" -newerct \@$since 2>/dev/null", auto_die => 0);
    $runtime = '' unless defined $runtime;
    $runtime =~ s/\s+\z//;
    push @reasons, "$runtime installed since it started" if length $runtime;
  }
  else {
    Rex::Logger::info("Could not tell when $service started (ps -o etimes= -p $pid): "
      . "changes to " . join(', ', $self->restart_watch) . " are not detected; "
      . "restart $service yourself if one of them changed", 'warn');
  }

  # /proc/PID/exe still runs a binary the installer replaced (unlinked).
  my $running   = $self->parse_version_output(
    Rex::Commands::Run::run("/proc/$pid/exe --version 2>&1", auto_die => 0));
  my $installed = $self->parse_version_output(
    Rex::Commands::Run::run($self->binary . " --version 2>&1", auto_die => 0));
  if (defined $running && defined $installed) {
    push @reasons, "it runs $running, $installed is installed"
      unless $self->same_version($running, $installed);
  }
  else {
    Rex::Logger::info("Could not compare the running $service (/proc/$pid/exe "
      . "--version) with the installed " . $self->binary . " --version: a new binary "
      . "is not detected; restart $service yourself after an upgrade", 'warn');
  }

  return @reasons;
}

=method parse_main_pid

The PID in C<systemctl show -p MainPID> output (C<MainPID=1234>), or
nothing for C<0> (not running) and anything else.

=cut

sub parse_main_pid {
  my ( $self, $out ) = @_;
  return $1 if ($out // '') =~ /^MainPID=([1-9]\d*)\s*$/m;
  return;
}

=method is_bare_template_output

  $dist->is_bare_template_output($config_toml)

Pure: is this C<config.toml> the verbatim output of L<Rex::GPU> 0.001's
template -- ignoring blank lines and comments, exactly an C<< imports = >> and a
C<version = 2> line and nothing else? The distributions' own configs always
have C<[plugins...]> sections.

=cut

# Same narrow match as Rex::GPU 0.002's _is_rke2_clobber_tmpl.
sub is_bare_template_output {
  my ( $self, $content ) = @_;
  return 0 unless defined $content && length $content;
  my @lines = grep { /\S/ && !/^\s*#/ } split /\n/, $content;
  return 0 unless @lines;
  my ($imports, $version2) = (0, 0);
  for my $l (@lines) {
    if    ($l =~ /^\s*imports\s*=/)         { $imports  = 1 }
    elsif ($l =~ /^\s*version\s*=\s*2\s*$/) { $version2 = 1 }
    else                                    { return 0 }
  }
  return ($imports && $version2) ? 1 : 0;
}

=method wait_for_service

  $dist->wait_for_service;
  $dist->wait_for_service(hint => 'It joins the cluster via ...');

Poll C<systemctl is-active> for the L</service> until it is C<active>
(C<attempts>, default 60, every C<interval> seconds, default 10). C<failed>
dies at once, any other state is polled until the timeout, which dies too.
Either die message carries the reason, then C<hint> if given, then the last
50 lines of the unit's journal.

=cut

sub wait_for_service {
  my ( $self, %args ) = @_;
  my $service  = $self->service;
  my $attempts = $args{attempts} // 60;
  my $interval = $args{interval} // 10;
  my $hint     = $args{hint};

  Rex::Logger::info("Waiting for $service to become active...");

  my $state = '';
  for my $i (1 .. $attempts) {
    $state = Rex::Commands::Run::run("systemctl is-active $service", auto_die => 0);
    $state = '' unless defined $state;
    $state =~ s/\s+\z//;
    if ($state eq 'active') {
      Rex::Logger::info("  $service is active");
      return 1;
    }
    die $self->_service_failure("is failed", $hint) if $state eq 'failed';
    Rex::Logger::info("  $service is " . ($state || 'unknown') . " ($i/$attempts)");
    sleep $interval if $i < $attempts;
  }

  die $self->_service_failure(
    "did not become active within " . ($attempts * $interval) . "s (last state: "
      . ($state || 'unknown') . ")", $hint);
}

sub _service_failure {
  my ( $self, $reason, $hint ) = @_;
  my $service = $self->service;
  my $journal = Rex::Commands::Run::run("journalctl -u $service -n 50 --no-pager 2>&1", auto_die => 0);
  $journal = '' unless defined $journal;
  $journal =~ s/\s+\z//;
  return "$service $reason\n"
    . ( defined $hint ? "$hint\n" : '' )
    . "--- journalctl -u $service -n 50 ---\n"
    . ($journal eq '' ? '(no journal output)' : $journal) . "\n";
}

#
# NVIDIA runtime lookup: a PATH for the rke2 units.
#

=method runtime_path_line

The C<PATH=> line L</ensure_nvidia_runtime_path> writes: systemd's own
default directories, not the SSH session's C<PATH>, since it becomes the
environment of a service running as root.

=cut

sub runtime_path_line { 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' }

=method env_with_runtime_path

  $dist->env_with_runtime_path($current)

Pure: the env file with exactly one C<PATH> line (L</runtime_path_line>,
last), every other line kept in order. C<undef> when the file already is
exactly that.

=cut

sub env_with_runtime_path {
  my ( $self, $current ) = @_;
  $current //= '';
  my @keep = grep { !/^\s*PATH=/ } split /\n/, $current;
  my $content = join('', map { $_."\n" } @keep, $self->runtime_path_line);
  return $content eq $current ? undef : $content;
}

=method ensure_nvidia_runtime_path

When the L</role>'s unit has an L</env_file> and C<nvidia-container-runtime>
is on the host's C<PATH>, make that file carry L</runtime_path_line>, other
lines kept. Restarts nothing itself: the file is in L</restart_watch>, so
the L</start_verb> of an RKE2 service running since before the write is
C<restart>.

=cut

# rke2-server/-agent.service carry no Environment= and read
# EnvironmentFile=-/etc/default/%N; rke2 scans PATH for nvidia-container-runtime
# at service start only, and the RKE2 GPU docs say to set PATH there. The rke2
# install script does not touch /etc/default, so this survives the install.
# k3s has no env_file: its agent code does the same scan and wired a host
# toolkit plus the nvidia RuntimeClass on a DGX without help (kubernetes-ocp,
# _configure_nvidia_runtime_path).
sub ensure_nvidia_runtime_path {
  my ( $self ) = @_;
  my $env_file = $self->env_file or return;

  unless (Rex::Commands::Run::can_run('nvidia-container-runtime')) {
    Rex::Logger::info("nvidia-container-runtime not on PATH, $env_file left alone "
      . "(the GPU Operator's toolkit is found without it)");
    return;
  }

  my $current = Rex::Commands::Run::run("cat $env_file 2>/dev/null", auto_die => 0);
  my $content = $self->env_with_runtime_path($? == 0 ? $current : '');
  unless (defined $content) {
    Rex::Logger::info("$env_file already carries the PATH for the NVIDIA runtime");
    return;
  }

  Rex::Logger::info("Writing PATH to $env_file for the NVIDIA runtime lookup");
  Rex::Commands::Run::run("mkdir -p /etc/default", auto_die => 1);
  # No secret in here: the file keeps its mode, a new one gets root's umask.
  Rex::Commands::File::file($env_file, content => $content);

  # Only on a re-run: the service reads the file when it starts.
  my $service = $self->service;
  Rex::Commands::Run::run("systemctl is-active --quiet $service", auto_die => 0);
  Rex::Logger::info("$service is running: it takes the new PATH at its next start "
    . "(install_server and install_agent restart it for that)")
    if $? == 0;
}

#
# Secret files: config.yaml, registries.yaml
#

=method write_secret_file

  $dist->write_secret_file($path, $content);

Write C<$content> to C<$path> on the host as C<0600 root:root>, with no
moment in which it is readable by others. Dies if the mode cannot be set.

=cut

# config.yaml carries the join token and registries.yaml may carry registry
# passwords, so both end up 0600 root:root. Rex's `file` writes content to a
# ".rex.tmp.<name>" sibling (LibSSH: `cat >` over an exec channel, no SFTP),
# renames it over the target and only then chmods -- the tmp file would be
# umask-mode (0644) in between. Pre-creating that tmp name at 0600 closes the
# window: `cat >` and SFTP open-truncate both keep an existing inode's mode,
# and the rename carries it to the target. The explicit chmod afterwards is
# what fixes an existing 0644 file whose content is unchanged (Rex then drops
# the tmp file and never touches the target), and fails loudly.
sub write_secret_file {
  my ( $self, $path, $content ) = @_;

  my $tmp = Rex::Commands::File::get_tmp_file_name($path);
  Rex::Commands::Run::run("install -m 600 -o root -g root /dev/null $tmp", auto_die => 1);

  Rex::Commands::File::file($path, content => $content);

  Rex::Commands::Run::run("chown root:root $path && chmod 600 $path", auto_die => 1);
}

=method write_registries

  $dist->write_registries($registries);

Write the registry mirror hashref to L</registries_file> through
L</write_secret_file>.

=cut

sub write_registries {
  my ( $self, $registries ) = @_;

  my $registries_file = $self->registries_file;
  Rex::Logger::info("Writing registries config to $registries_file");

  $self->write_secret_file($registries_file,
    YAML::PP->new(boolean => 'JSON::PP')->dump_string($registries));
}

# Loaded last, at run time: both extend this class, which has to be complete
# (its attributes declared) first.
require Rex::Rancher::Distribution::RKE2;
require Rex::Rancher::Distribution::K3s;

1;

=head1 SYNOPSIS

  use Rex::Rancher::Distribution;

  my $dist = Rex::Rancher::Distribution->new_for($opts{distribution});
  $dist->kubeconfig;          # /etc/rancher/rke2/rke2.yaml
  $dist->service;             # rke2-server

  my $agent = Rex::Rancher::Distribution->new_for('k3s', role => 'agent');
  $agent->service;            # k3s-agent.service
  $agent->wait_for_service(hint => 'It joins the cluster via ...');

=head1 DESCRIPTION

Everything L<Rex::Rancher::Server>, L<Rex::Rancher::Agent> and
L<Rex::Rancher::Cilium> need to know about RKE2 versus K3s lives in one
object: paths, service names, install script and release artifacts, and the
host steps both distributions share (artifact download and checksum, version
check, service start and wait, secret files, the NVIDIA runtime C<PATH>).
L<Rex::Rancher::Distribution::RKE2> and L<Rex::Rancher::Distribution::K3s>
implement the distribution-specific methods; a change to one wants the
other in the same edit.

This is an internal building block of the Rex tasks; the functions those
modules export are the interface for a Rexfile. The host steps use the Rex
DSL (C<run>, C<file>) of the current connection, like those functions.

=head1 SEE ALSO

L<Rex::Rancher>, L<Rex::Rancher::Server>, L<Rex::Rancher::Agent>,
L<Rex::Rancher::Cilium>, L<Rex::Rancher::Distribution::RKE2>,
L<Rex::Rancher::Distribution::K3s>

=cut
