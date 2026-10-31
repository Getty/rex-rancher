#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# k61: _wait_for_gpu_resource swallowed every API error for two minutes and
# then only warned "check device plugin": a 403 or a dead API read the same
# as a plugin that had not reported yet. The warning now names the last
# attempt's error; nothing else changes (no die, same 24 polls). The API and
# sleep are faked: that a real 403 reads like this is only shown live.
#
# k95: the same loop waits for amd.com/gpu (deploy_amd_device_plugin) as for
# nvidia.com/gpu; the resource is the caller's, and the other vendor's
# resource on a node does not count.

my $slept = 0;
BEGIN { *CORE::GLOBAL::sleep = sub { $slept++ } }

use IO::K8s;
use Rex::Rancher::K8s;

my ( @info, @warn );
{
  no warnings 'redefine';
  *Rex::Logger::info = sub { push @{ ( $_[1] // '' ) eq 'warn' ? \@warn : \@info }, $_[0] };
}

# @answers: one per list call; a string dies with it, a number is the GPU
# capacity of the one node (0: none yet), advertised as $offered. The last
# answer repeats.
our ( @answers, $offered );
{
  package FakeAPI;
  sub new  { bless {}, shift }
  sub list {
    my $a = @main::answers > 1 ? shift @main::answers : $main::answers[0];
    die $a if $a =~ /\D/;
    my %status = ( status => { capacity => $a ? { $main::offered => $a } : {} } );
    return FakeList->new( IO::K8s->new->new_object( 'Node', metadata => { name => 'gpu1' }, %status ) );
  }
  package FakeList;
  sub new   { my ( $c, @i ) = @_; bless { items => \@i }, $c }
  sub items { $_[0]{items} }
}

for my $resource (qw( nvidia.com/gpu amd.com/gpu )) {
  my $wait_with = sub {
    local @answers = @_;
    ( @info, @warn ) = ();
    $slept = 0;
    return Rex::Rancher::K8s::_wait_for_gpu_resource( FakeAPI->new, $resource );
  };
  local $offered = $resource;
  my $r = quotemeta $resource;

  is( $wait_with->( "403 Forbidden: nodes is forbidden\n" ), 0, "$resource: API error throughout: 0, no die" );
  is( $slept, 24, "$resource: still 24 polls" );
  is_deeply( \@warn,
    [ "  $resource resource did not appear \x{e2}\x{80}\x{94} check device plugin "
      . "(last API error: 403 Forbidden: nodes is forbidden)" ],
    "$resource: the warning names the last error" );

  is( $wait_with->( 0 ), 0, "$resource: API answers, no GPU: 0" );
  is_deeply( \@warn,
    [ "  $resource resource did not appear \x{e2}\x{80}\x{94} check device plugin" ],
    "$resource: no error: the warning as before" );

  is( $wait_with->( ( "500 boom\n" ) x 3, 0 ), 0, "$resource: errors, then answers without GPU" );
  unlike( $warn[0], qr/last API error/, "$resource: an error of an earlier attempt is not named" );

  is( $wait_with->( "503 unavailable\n", 2 ), 1, "$resource: error, then GPU capacity: 1" );
  is_deeply( \@warn, [], "$resource: no warning" );
  like( $info[-1], qr/\[ok\] $r: 2 on gpu1/, "$resource: reports the node" );
}

# The other vendor's capacity is not the one waited for.
{
  local @answers = (4);
  local $offered = 'nvidia.com/gpu';
  ( @info, @warn ) = ();
  is( Rex::Rancher::K8s::_wait_for_gpu_resource( FakeAPI->new, 'amd.com/gpu' ), 0,
    'amd.com/gpu awaited, only nvidia.com/gpu on the node: 0' );
  like( $warn[0], qr/^  amd\.com\/gpu resource did not appear/, '... and says which resource' );
}

done_testing;
