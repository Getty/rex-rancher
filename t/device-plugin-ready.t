#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# k110: deploy_nvidia_device_plugin and deploy_amd_device_plugin logged
# "... device plugin ready" after the wait for the GPU resource whether or
# not it had appeared: seen on amdlab (2026-10-31), the AMD plugin kept off
# the node by its affinity, the wait's "did not appear" warning was followed
# by "AMD GPU device plugin ready". They report ready now only when the wait
# found the resource; when it ran out, the wait's warning stays and a closing
# info line says the DaemonSet is applied but the resource did not appear.
# Still no die.
#
# Offline: the API and sleep are faked as in t/gpu-resource-wait.t. That a
# real plugin's resource shows up, or does not, is only shown by a deploy.

my $slept = 0;
BEGIN { *CORE::GLOBAL::sleep = sub { $slept++ } }

use IO::K8s;
use Rex::Rancher::K8s;

my ( @info, @warn );
{
  no warnings 'redefine';
  *Rex::Logger::info = sub { push @{ ( $_[1] // '' ) eq 'warn' ? \@warn : \@info }, $_[0] };
}

# %allocatable: what the one node offers.
our %allocatable;
{
  package FakeAPI;
  sub new        { bless {}, shift }
  sub new_object { shift; IO::K8s->new->new_object(@_) }
  sub create     { $_[1] }
  sub list {
    return FakeList->new( IO::K8s->new->new_object( 'Node', metadata => { name => 'gpu1' },
      status => { capacity => { %main::allocatable }, allocatable => { %main::allocatable } } ) );
  }
  package FakeList;
  sub new   { my ( $c, @i ) = @_; bless { items => \@i }, $c }
  sub items { $_[0]{items} }
}
{
  no warnings 'redefine';
  *Rex::Rancher::K8s::_api = sub { FakeAPI->new };
}

sub deploy {
  my ( $fn, %o ) = @_;
  ( @info, @warn ) = ();
  $slept = 0;
  my $code = Rex::Rancher::K8s->can($fn);
  return eval { $code->( kubeconfig => '/tmp/kc.yaml', %o ); 1 };
}

for my $case (
  [ deploy_nvidia_device_plugin => 'NVIDIA device plugin',  'nvidia.com/gpu' ],
  [ deploy_amd_device_plugin    => 'AMD GPU device plugin', 'amd.com/gpu' ],
) {
  my ( $fn, $plugin, $resource ) = @$case;
  my $r = quotemeta $resource;

  {
    local %allocatable = ( $resource => 2 );
    ok( deploy($fn), "$fn, $resource allocatable: deployed" ) or diag $@;
    is( $info[-1], "$plugin ready", '... ends with ready' );
    is_deeply( \@warn, [], '... no warning' );
  }
  {
    local %allocatable = ();
    ok( deploy($fn), "$fn, $resource never allocatable: deployed, no die" ) or diag $@;
    is( $slept, 24, '... after the full two minutes' );
    like( $warn[0], qr/^  $r resource did not appear/, "... the wait's warning stays" );
    is( scalar @warn, 1, '... the only warning' );
    ok( !grep( { /device plugin ready/ } @info ), '... no ready' );
    is( $info[-1], "$plugin DaemonSet applied, but $resource did not appear on any node",
      '... ends saying the DaemonSet is applied, the resource not there' );
  }
}

# ROCm's mixed naming waits for any amd.com/ resource; the closing line names
# the prefix the way the warning does.
{
  local %allocatable = ( 'amd.com/cpx_nps4' => 8 );
  ok( deploy( deploy_amd_device_plugin => resource_naming => 'mixed' ), 'mixed, a partition resource: deployed' )
    or diag $@;
  is( $info[-1], 'AMD GPU device plugin ready', '... ready' );
}
{
  local %allocatable = ( 'nvidia.com/gpu' => 1 );
  ok( deploy( deploy_amd_device_plugin => resource_naming => 'mixed' ), 'mixed, no amd.com/ resource: deployed' )
    or diag $@;
  is( $info[-1], 'AMD GPU device plugin DaemonSet applied, but amd.com/* did not appear on any node',
    '... the closing line names amd.com/*' );
}

# wait => 0 is unchanged: applied, no wait, no ready, no closing line.
ok( deploy( deploy_amd_device_plugin => wait => 0 ), 'AMD wait => 0: deployed' ) or diag $@;
is( $info[-1], '  DaemonSet applied, not waiting for GPU resources (wait => 0)', '... ends as before' );

done_testing;
