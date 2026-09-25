# ABSTRACT: Pure checks of install options, before anything touches the host

package Rex::Rancher::Options;
our $VERSION = '0.003';
use v5.14.4;
use warnings;

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

1;

=head1 SYNOPSIS

  use Rex::Rancher::Options;

  my $method = Rex::Rancher::Options->resolve_install_method($opts{install_method}, $opts{version});
  my $cidr   = Rex::Rancher::Options->check_cluster_cidr($opts{cluster_cidr});

=head1 DESCRIPTION

Option checks that are the same for RKE2 and K3s and need no host: they
return the value to use or die with a message for the Rexfile author, before
L<Rex::Rancher::Server>, L<Rex::Rancher::Agent>, L<Rex::Rancher::Cilium> or
L<Rex::Rancher> touch anything. Class methods; nothing is exported. The
same methods are still callable on L<Rex::Rancher::Distribution>, which
hands them on to this class.

=head1 SEE ALSO

L<Rex::Rancher::Distribution>, L<Rex::Rancher::Server>,
L<Rex::Rancher::Agent>

=cut
