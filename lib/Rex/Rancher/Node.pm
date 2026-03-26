# ABSTRACT: Linux node preparation for Rancher Kubernetes distributions (RKE2/K3s)

package Rex::Rancher::Node;

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

Prepare a Linux node for Kubernetes. Installs base packages, configures
kernel modules, sysctl parameters, disables swap, and optionally sets
hostname, timezone, locale, and NTP.

  prepare_node(
    hostname => 'worker-01',   # optional — short hostname
    domain   => 'k8s.local',   # optional — domain for FQDN
    timezone => 'Europe/Berlin', # optional, default: UTC
    locale   => 'en_US.UTF-8',  # optional, default: en_US.UTF-8
    ntp      => 1,               # optional, default: 1
  );

If C<hostname> and C<domain> are both provided, the node's hostname is set
and an /etc/hosts entry is created. If omitted, hostname configuration is
skipped entirely.

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
  update_package_db if is_debian();
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
  Rex::Logger::info("Configuring /etc/hosts for $fqdn");
  host_entry $fqdn,
    ensure  => "present",
    ip      => "127.0.1.1",
    aliases => [$hostname];
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
  if (can_run("localectl")) {
    run "localectl set-locale LANG=$locale", auto_die => 0;
  }
  else {
    file "/etc/default/locale", content => "LANG=$locale\n";
  }
}

sub _setup_ntp {
  Rex::Logger::info("Installing and enabling chrony for NTP");
  pkg ["chrony"], ensure => "present";
  run "systemctl enable chronyd 2>/dev/null || systemctl enable chrony 2>/dev/null", auto_die => 0;
  run "systemctl start chronyd 2>/dev/null || systemctl start chrony 2>/dev/null", auto_die => 0;
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

  # Without hostname (e.g. cloud instances with pre-configured hostnames)
  prepare_node(
    timezone => 'UTC',
    locale   => 'en_US.UTF-8',
  );

=head1 DESCRIPTION

L<Rex::Rancher::Node> provides Linux node preparation for Rancher
Kubernetes distributions (RKE2/K3s). It handles the base system
configuration needed before installing a Kubernetes distribution:

=over

=item * Base package installation (curl, ca-certificates)

=item * Hostname and /etc/hosts configuration (optional)

=item * Timezone and locale setup

=item * NTP via chrony

=item * Swap disabled

=item * Required kernel modules (br_netfilter, overlay)

=item * Sysctl parameters for Kubernetes networking

=back

This module is distribution-agnostic and works for both RKE2 and K3s
node preparation.

=head1 SEE ALSO

L<Rex::Rancher>, L<Rex::Rancher::GPU>, L<Rex>

=cut
