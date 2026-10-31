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
#
# k101: with ROCm's mixed naming a partitioned GPU is amd.com/<compute>_<memory>
# (amd.com/cpx_nps4), so deploy_amd_device_plugin waits for the prefix
# amd.com/: a resource ending in / takes any resource under it. An exact name
# still takes only itself.

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
# answer repeats. A hashref answer is the node's whole capacity.
our ( @answers, $offered );
{
  package FakeAPI;
  sub new  { bless {}, shift }
  sub list {
    my $a = @main::answers > 1 ? shift @main::answers : $main::answers[0];
    die $a if !ref $a && $a =~ /\D/;
    my %status = ( status => { capacity => ref $a ? $a : $a ? { $main::offered => $a } : {} } );
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

# --- a prefix (k101) ---------------------------------------------------------------

sub wait_prefix {
  my ( $resource, @a ) = @_;
  local @answers = @a;
  ( @info, @warn ) = ();
  $slept = 0;
  return Rex::Rancher::K8s::_wait_for_gpu_resource( FakeAPI->new, $resource );
}

is( wait_prefix( 'amd.com/', { 'amd.com/cpx_nps4' => 8, cpu => 96 } ), 1, 'amd.com/: a partition resource counts' );
like( $info[-1], qr/\[ok\] amd\.com\/cpx_nps4: 8 on gpu1/, '... and is named' );
is( $slept, 0, '... at the first poll' );

is( wait_prefix( 'amd.com/', { 'amd.com/gpu' => 1 } ), 1, 'amd.com/: amd.com/gpu counts' );
like( $info[-1], qr/\[ok\] amd\.com\/gpu: 1 on gpu1/, '... and is named' );

is( wait_prefix( 'amd.com/', { 'amd.com/cpx_nps1' => 0, 'amd.com/spx_nps1' => 2 } ), 1,
  'amd.com/: one at 0, another above: found' );
like( $info[-1], qr/\[ok\] amd\.com\/spx_nps1: 2 on gpu1/, '... the one above 0' );

is( wait_prefix( 'amd.com/', { 'amd.com/cpx_nps4' => 0 } ), 0, 'amd.com/: only 0: not found' );
is( $slept, 24, '... 24 polls' );
is_deeply( \@warn, [ "  amd.com/* resource did not appear \x{e2}\x{80}\x{94} check device plugin" ],
  '... the warning names the prefix' );

is( wait_prefix( 'amd.com/', { 'nvidia.com/gpu' => 4, 'xamd.com/gpu' => 1 } ), 0,
  'amd.com/: another vendor, or a name only containing it: not found' );

is( wait_prefix( 'amd.com/', 0, { 'amd.com/cpx_nps4' => 8 } ), 1, 'amd.com/: none yet, then a partition: found' );
is( $slept, 1, '... at the second poll' );

is( wait_prefix( 'amd.com/', "403 Forbidden\n" ), 0, 'amd.com/: API error throughout: 0, no die' );
like( $warn[0], qr/^  amd\.com\/\* resource did not appear .* \(last API error: 403 Forbidden\)\z/,
  '... the warning names the last error' );

# An exact name stays exact: single naming does not take a partition.
is( wait_prefix( 'amd.com/gpu', { 'amd.com/cpx_nps4' => 8 } ), 0, 'amd.com/gpu: a partition resource does not count' );
like( $warn[0], qr/^  amd\.com\/gpu resource did not appear/, '... the warning names amd.com/gpu' );

done_testing;
