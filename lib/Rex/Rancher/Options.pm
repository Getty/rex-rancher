# ABSTRACT: Pure checks of install options, before anything touches the host

package Rex::Rancher::Options;
our $VERSION = '0.005';
use v5.14.4;
use warnings;

use Socket qw( AF_INET AF_INET6 inet_pton );

=method resolve_install_method

  my $method = Rex::Rancher::Options->resolve_install_method($method, $version);

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

  Rex::Rancher::Options->check_cluster_cidr($cidr);

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

=method check_kubeconfig_mode

  Rex::Rancher::Options->check_kubeconfig_mode($mode);

Returns C<$mode> when it is a file mode written as a string of a zero and
three octal digits (C<'0640'>), C<undef> for C<undef>, and dies otherwise.
The leading zero is required so that only a string passes: the Perl literal
C<0640> is the number 416, which would read as another mode.

=cut

sub check_kubeconfig_mode {
  my ( $self, $mode ) = @_;
  return unless defined $mode;
  die "kubeconfig_mode must be an octal file mode as a string such as '0640', "
    . "got '$mode'\n" unless !ref $mode && $mode =~ /\A0[0-7]{3}\z/;
  return "$mode";
}

=method check_ipam_mode

  Rex::Rancher::Options->check_ipam_mode($mode);

Returns C<$mode> when it is C<kubernetes> or C<cluster-pool>, C<undef> for
C<undef>, and dies otherwise. These are the two Cilium IPAM modes that work
on RKE2 and K3s from nothing but a CIDR: C<kubernetes> takes the node
C<podCIDR>s the cluster cuts from its C<cluster-cidr>, C<cluster-pool>
cuts per-node ranges from Cilium's own pool. C<multi-pool> needs pools
defined in the Helm values, C<crd>, C<eni>, C<azure>, C<alibabacloud> and
C<delegated-plugin> an external allocator or cloud; those stay a matter of
C<helm_values>.

=cut

sub check_ipam_mode {
  my ( $self, $mode ) = @_;
  return unless defined $mode;
  die "ipam_mode must be 'kubernetes' or 'cluster-pool', got '$mode' (other "
    . "Cilium IPAM modes need more than a mode: set them in helm_values)\n"
    unless $mode eq 'kubernetes' || $mode eq 'cluster-pool';
  return $mode;
}

=method check_node_addresses

  my $ips = Rex::Rancher::Options->check_node_addresses(node_ip => $value);

The addresses of C<node_ip> or C<node_external_ip> (the option name comes
first, for the message) as an arrayref: C<$value> is one IPv4 or IPv6
address, a string of several separated by commas, or an arrayref of them,
one per element; for dual-stack one IPv4 and one IPv6 address. Returns
C<undef> for C<undef>, and dies naming the option for anything else: a
reference other than an arrayref, an element that is not a string, an empty
string or list, or something that is not an IP address (spaces included).
Only the syntax is checked: whether the host has the address, and which
combinations RKE2 and K3s take, is left to them.

=cut

sub check_node_addresses {
  my ( $self, $name, $value ) = @_;
  return unless defined $value;
  my $want = "$name must be an IP address, several separated by commas, or an "
    . "array reference of them (one IPv4 and one IPv6 for dual-stack)";
  die "$want, got a ".ref($value)." reference\n" if ref $value && ref $value ne 'ARRAY';
  my @ip = ref $value ? @{$value} : split /,/, $value, -1;
  die "$want, got an empty ".( ref $value ? 'list' : 'string' )."\n" unless @ip;
  for my $ip (@ip) {
    die "$want, got ".( defined $ip ? 'a '.ref($ip).' reference' : 'an undefined element' )."\n"
      if !defined $ip || ref $ip;
    die "$want, got '$ip'\n"
      unless defined inet_pton( AF_INET, $ip ) || defined inet_pton( AF_INET6, $ip );
  }
  return [@ip];
}

=method join_server_host

  my $host = Rex::Rancher::Options->join_server_host($server);
  # 'https://10.230.30.52:9345' => '10.230.30.52'
  # 'https://[fd00::1]:9345'    => 'fd00::1'
  # 'https://cp.example:9345'   => 'cp.example'

The host of the join URL C<server>, for C<node_ip_from_route>: an IPv4
address, an IPv6 address (in brackets in the URL, returned without them) or
a host name, as the URL has it. C<$server> is C<https://HOST> (the scheme
in any case) with an optional port, 1 to 65535, and an optional C</> at the
end. A host name has labels of letters, digits and hyphens, neither first
nor last in a label (RFC 1123), at most 253 characters and an optional dot
at the end; one of digits and dots only has to be an IPv4 address. Dies
naming C<node_ip_from_route> and the forms it takes for anything else: no
C<$server> or a reference, another scheme, a user, a path or a query, an
IPv6 address without brackets or with a zone (C<%eth0>), any other
character in a name. What it returns is safe as one shell word on the
host. Only the syntax is checked: a host name is resolved on the host, see
L<Rex::Rancher::Distribution/node_ip_from_route>.

=cut

sub join_server_host {
  my ( $self, $server ) = @_;
  my $want = 'node_ip_from_route needs server as https://HOST or https://HOST:PORT, HOST an '
    . 'IPv4 address, an IPv6 address in brackets or a host name';
  die "$want, got ".( ref $server ? 'a '.ref($server).' reference' : 'nothing' )."\n"
    if ref $server || !defined $server;
  my $bad = "$want, got '$server'\n";
  my ( $host, $port ) = $server =~ m{\A(?i:https)://(\[[^\]]*\]|[^/:\[\]]+)(?::([0-9]{1,5}))?/?\z}
    or die $bad;
  die $bad if defined $port && ( $port < 1 || $port > 65535 );
  if ( $host =~ /\A\[(.*)\]\z/s ) {
    my $v6 = $1;
    die $bad unless defined inet_pton( AF_INET6, $v6 );
    return $v6;
  }
  return $host if defined inet_pton( AF_INET, $host );
  my $label = qr/[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?/;
  ( my $name = $host ) =~ s/\.\z//;
  die $bad unless length $name <= 253 && $name =~ /\A$label(?:\.$label)*\z/
    && $name !~ /\A[0-9.]+\z/;
  return $host;
}

1;

=head1 SYNOPSIS

  use Rex::Rancher::Options;

  my $method = Rex::Rancher::Options->resolve_install_method($opts{install_method}, $opts{version});
  my $cidr   = Rex::Rancher::Options->check_cluster_cidr($opts{cluster_cidr});
  my $kcmode = Rex::Rancher::Options->check_kubeconfig_mode($opts{kubeconfig_mode});
  my $mode   = Rex::Rancher::Options->check_ipam_mode($opts{ipam_mode});
  my $ips    = Rex::Rancher::Options->check_node_addresses(node_ip => $opts{node_ip});
  my $host   = Rex::Rancher::Options->join_server_host($opts{server});

=head1 DESCRIPTION

Option checks that are the same for RKE2 and K3s and need no host: they
return the value to use or die with a message for the Rexfile author, before
L<Rex::Rancher::Server>, L<Rex::Rancher::Agent>, L<Rex::Rancher::Cilium> or
L<Rex::Rancher> touch anything. Class methods; nothing is exported.
L</resolve_install_method> and L</check_cluster_cidr> are still callable on
L<Rex::Rancher::Distribution>, which hands them on to this class.

=head1 SEE ALSO

L<Rex::Rancher::Distribution>, L<Rex::Rancher::Server>,
L<Rex::Rancher::Agent>

=cut
