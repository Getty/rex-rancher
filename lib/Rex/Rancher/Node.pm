# ABSTRACT: Linux node preparation for Rancher Kubernetes distributions (RKE2/K3s)

package Rex::Rancher::Node;
our $VERSION = '0.003';
use v5.14.4;
use warnings;

use Rex::Commands::File;
use Rex::Commands::Gather;
use Rex::Commands::Host;
use Rex::Commands::Pkg;
use Rex::Commands::Run;
use Rex::Logger;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  prepare_node
);

=method prepare_node

Prepare a Linux node for Kubernetes. Performs all OS-level configuration
required before installing RKE2 or K3s:

=over

=item * On Debian/Ubuntu, stop C<unattended-upgrades>, C<apt-daily.service>
and C<apt-daily-upgrade.service> (they hold the apt lock on a fresh boot)
and run C<apt-get update>. They are B<not> restarted afterwards; their
timers bring them back on schedule, C<unattended-upgrades> at the next boot.

=item * Install C<curl> and C<ca-certificates>

=item * Set hostname via C<hostnamectl> or C</etc/hostname> (optional)

=item * Add a C<127.0.1.1> entry to C</etc/hosts> when C<hostname> is given:
C<FQDN hostname> with a C<domain>, C<hostname> alone without one (then only
if no line in C</etc/hosts> names the host yet)

=item * Set timezone via C<timedatectl> or symlink (default: C<UTC>)

=item * Set locale via C<localectl> or C</etc/default/locale> (default: C<en_US.UTF-8>).
On Debian/Ubuntu the locale is first enabled in C</etc/locale.gen> and
generated with C<locale-gen> (skipped for C<C>/C<POSIX> and when
C<locale-gen> is not installed)

=item * NTP (default: enabled): nothing is installed when C<timedatectl>
already reports the clock as NTP-synchronized; otherwise C<chrony> is
installed and started. If the C<chrony> install fails, C<systemd-timesyncd>
is started instead, and C<prepare_node> dies only when that is not active
either

=item * Disable and remove swap entries from C</etc/fstab>

=item * Load C<br_netfilter> and C<overlay> kernel modules and persist to
C</etc/modules-load.d/kubernetes.conf>

=item * Write C</etc/sysctl.d/99-kubernetes.conf> with C<net.ipv4.ip_forward>,
C<net.bridge.bridge-nf-call-iptables>, and C<net.bridge.bridge-nf-call-ip6tables>,
then apply with C<sysctl --system>

=back

  prepare_node(
    hostname => 'worker-01',      # optional — short hostname
    domain   => 'k8s.local',      # optional — domain suffix for FQDN
    timezone => 'Europe/Berlin',  # optional, default: UTC
    locale   => 'en_US.UTF-8',    # optional, default: en_US.UTF-8
    ntp      => 1,                 # optional, default: 1 (ensure NTP sync)
  );

If C<hostname> is provided without C<domain>, C</etc/hosts> gets
C<127.0.1.1 hostname> unless a line already names the host (e.g. the public
IP the provider wrote), which is then left alone.

=cut

sub prepare_node {
  my (%opts) = @_;

  my $hostname = $opts{hostname};
  my $domain   = $opts{domain};
  my $timezone = $opts{timezone} // 'UTC';
  my $locale   = $opts{locale}   // 'en_US.UTF-8';
  my $ntp      = exists $opts{ntp} ? $opts{ntp} : 1;

  my $fqdn = ($hostname && $domain) ? "$hostname.$domain" : undef;

  Rex::Logger::info("Preparing node " . ($fqdn // "(unnamed)") . " for Kubernetes");

  _install_base_packages();
  if ($hostname) {
    _set_hostname($hostname, $fqdn);
    _set_hosts_entry($hostname, $fqdn);
  }
  _set_timezone($timezone);
  _set_locale($locale);
  _setup_ntp() if $ntp;
  _disable_swap();
  _load_kernel_modules();
  _configure_sysctl();

  Rex::Logger::info("Node preparation complete" . ($fqdn ? " for $fqdn" : ""));
}

sub _install_base_packages {
  Rex::Logger::info("Installing base packages");
  if (is_debian()) {
    # Stop automatic apt services first — on a fresh Hetzner boot,
    # unattended-upgrades holds /var/lib/dpkg/lock-frontend and apt-get
    # fails immediately (DPkg::Lock::Timeout only covers the dpkg lock,
    # not the apt frontend lock).
    run "systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true",
      auto_die => 0;
    run "apt-get -o DPkg::Lock::Timeout=120 update -q", auto_die => 0;
  }
  pkg ["curl", "ca-certificates"], ensure => "present";
}

sub _set_hostname {
  my ($hostname, $fqdn) = @_;
  Rex::Logger::info("Setting hostname to $hostname");
  if (can_run("hostnamectl")) {
    run "hostnamectl set-hostname $hostname", auto_die => 0;
  }
  else {
    file "/etc/hostname", content => "$hostname\n";
    run "hostname $hostname", auto_die => 0;
  }
}

sub _set_hosts_entry {
  my ($hostname, $fqdn) = @_;
  if ($fqdn) {
    Rex::Logger::info("Configuring /etc/hosts for $fqdn");
    host_entry $fqdn,
      ensure  => "present",
      ip      => "127.0.1.1",
      aliases => [$hostname];
    return;
  }
  # Without a domain only add a missing name: host_entry replaces every line
  # naming the host -- the provider's public-IP line, or a
  # "127.0.0.1 localhost <hostname>" line and localhost with it.
  if (get_host($hostname)) {
    Rex::Logger::info("/etc/hosts already names $hostname, leaving it");
    return;
  }
  Rex::Logger::info("Configuring /etc/hosts for $hostname");
  host_entry $hostname,
    ensure => "present",
    ip     => "127.0.1.1";
}

sub _set_timezone {
  my ($timezone) = @_;
  Rex::Logger::info("Setting timezone to $timezone");
  if (can_run("timedatectl")) {
    run "timedatectl set-timezone $timezone", auto_die => 0;
  }
  else {
    run "ln -sf /usr/share/zoneinfo/$timezone /etc/localtime", auto_die => 0;
    file "/etc/timezone", content => "$timezone\n";
  }
}

sub _set_locale {
  my ($locale) = @_;
  Rex::Logger::info("Setting locale to $locale");
  # Generate first: localectl refuses a locale that is not installed.
  _generate_locale($locale) if is_debian();
  if (can_run("localectl")) {
    run "localectl set-locale LANG=$locale", auto_die => 0;
  }
  else {
    file "/etc/default/locale", content => "LANG=$locale\n";
  }
}

# Debian/Ubuntu only. Debian's locale-gen ignores its arguments and builds
# what /etc/locale.gen enables, Ubuntu's generates the locale it is given;
# enabling the line and naming the locale covers both.
sub _generate_locale {
  my ($locale) = @_;
  return if $locale =~ /^(?:C|POSIX)(?:\.|$)/;
  unless (can_run("locale-gen")) {
    Rex::Logger::info("locale-gen not installed, $locale is not generated", 'warn');
    return;
  }
  my ($charset) = $locale =~ /\.([^.@]+)/;
  run _enable_locale_cmd($locale.' '.$charset, '/etc/locale.gen'), auto_die => 0
    if $charset;
  run "locale-gen $locale", auto_die => 0;
  Rex::Logger::info("locale-gen $locale failed", 'warn') if $? != 0;
}

# Uncomment "<locale> <charset>" in locale.gen, append it when absent.
sub _enable_locale_cmd {
  my ($line, $file) = @_;
  (my $re = $line) =~ s/\./\\./g;
  return 'if [ -f '.$file.' ]; then '
    .q{sed -i -E 's/^#\s*(}.$re.q{)\s*$/\1/' }.$file.'; '
    .q{grep -qE '^}.$re.q{\s*$' }.$file.q{ || echo '}.$line.q{' >> }.$file.'; fi';
}

sub _setup_ntp {
  my $synced = run "timedatectl show --property=NTPSynchronized --value 2>/dev/null", auto_die => 0;
  if (defined $synced && $synced =~ /^\s*yes\s*$/) {
    Rex::Logger::info("Clock already NTP-synchronized, not installing chrony");
    return;
  }

  Rex::Logger::info("Installing and enabling chrony for NTP");
  if (eval { pkg ["chrony"], ensure => "present"; 1 }) {
    run "systemctl enable chronyd 2>/dev/null || systemctl enable chrony 2>/dev/null", auto_die => 0;
    run "systemctl start chronyd 2>/dev/null || systemctl start chrony 2>/dev/null", auto_die => 0;
    return;
  }
  my $err = $@;
  chomp $err;
  Rex::Logger::info("chrony install failed ($err), falling back to systemd-timesyncd", 'warn');

  run "systemctl enable --now systemd-timesyncd 2>/dev/null", auto_die => 0;
  my $active = run "systemctl is-active systemd-timesyncd 2>/dev/null", auto_die => 0;
  die "No NTP: chrony install failed ($err) and systemd-timesyncd is not active\n"
    unless defined $active && $active =~ /^\s*active\s*$/;
  Rex::Logger::info("Using systemd-timesyncd for NTP");
}

sub _disable_swap {
  Rex::Logger::info("Disabling swap");
  run "swapoff -a", auto_die => 0;
  delete_lines_matching "/etc/fstab", matching => qr/\sswap\s/;
}

sub _load_kernel_modules {
  Rex::Logger::info("Loading required kernel modules");
  run "modprobe br_netfilter", auto_die => 0;
  run "modprobe overlay", auto_die => 0;
  file "/etc/modules-load.d/kubernetes.conf", content => "br_netfilter\noverlay\n";
}

sub _configure_sysctl {
  Rex::Logger::info("Configuring kernel parameters for Kubernetes");
  file "/etc/sysctl.d/99-kubernetes.conf",
    content => join("\n",
      "net.bridge.bridge-nf-call-iptables = 1",
      "net.bridge.bridge-nf-call-ip6tables = 1",
      "net.ipv4.ip_forward = 1",
    ) . "\n";
  run "sysctl --system", auto_die => 0;
}

1;

=head1 SYNOPSIS

  use Rex::Rancher::Node;

  # Full preparation with hostname
  prepare_node(
    hostname => 'worker-01',
    domain   => 'k8s.local',
    timezone => 'Europe/Berlin',
  );

  # Minimal preparation — hostname left unchanged; timezone UTC and
  # locale en_US.UTF-8 are still set (the defaults), chrony installed
  prepare_node();

  # Skip NTP (e.g. host is a VM with hypervisor time sync)
  prepare_node(
    hostname => 'vm-01',
    domain   => 'k8s.local',
    ntp      => 0,
  );

=head1 DESCRIPTION

L<Rex::Rancher::Node> prepares a Linux node for Rancher Kubernetes
distributions (RKE2 and K3s). The same L</prepare_node> call is verified on
Debian, Ubuntu, and RHEL/Rocky/Alma — the supported set. openSUSE Leap / SLES
is B<unverified>: the base-package step there falls through to Rex's generic
C<pkg> abstraction (zypper) and has never been exercised on real SUSE
hardware, so it is unsupported and best-effort only.

The module sets OS-level configuration that Kubernetes requires:

=over

=item * B<Swap disabled> — Kubernetes does not function correctly with swap
enabled.

=item * B<Kernel modules> — C<br_netfilter> is needed for iptables to see
bridged traffic; C<overlay> is required for containerd's overlay filesystem.

=item * B<Sysctl parameters> — IP forwarding and bridge netfilter settings
required by Kubernetes networking and CNI plugins.

=item * B<NTP> — Time skew between nodes causes certificate validation
failures and etcd instability. An already synchronized clock is left as it
is; otherwise C<chrony> is installed and started, with C<systemd-timesyncd>
as the fallback when that install fails.

=back

Called automatically by L<Rex::Rancher/rancher_deploy_server> and
L<Rex::Rancher/rancher_deploy_agent>.

=head1 SEE ALSO

L<Rex::Rancher>, L<Rex::Rancher::Server>, L<Rex::Rancher::Agent>, L<Rex>

=cut
