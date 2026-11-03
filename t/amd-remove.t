#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# k101: remove_amd_device_plugin and remove_amd_node_labeller delete exactly
# the objects deploy_amd_device_plugin and deploy_amd_node_labeller create,
# the labeller's DaemonSet first; idempotent: an object that is not there
# (404) is logged and skipped, any other error dies.
#
# Offline, but through the real Kubernetes::REST client: only its IO is
# faked, so the delete call form, the paths it builds for namespaced and
# cluster-scoped kinds, and the Kubernetes::REST::APIError a 404 or a 403
# becomes are the installed client's own. That an API server answers like
# this is only shown live.

use Kubernetes::REST;
use Kubernetes::REST::APIError;
use Kubernetes::REST::HTTPResponse;
use Rex::Rancher::K8s;

my ( @info, @warn );
{
  no warnings 'redefine';
  *Rex::Logger::info = sub { push @{ ( $_[1] // '' ) eq 'warn' ? \@warn : \@info }, $_[0] };
}

# %status: the HTTP status per path (default 200); @requests: "METHOD path"
# of each request the client sent.
our ( %status, @requests );
{
  package FakeIO;
  use Moo;
  with 'Kubernetes::REST::Role::IO';
  sub call {
    my ( $self, $req ) = @_;
    my $path = $req->url =~ s{^http://mock\.local}{}r;
    push @main::requests, $req->method . ' ' . $path;
    my $code   = $main::status{$path} // 200;
    my $reason = { 200 => 'Success', 403 => 'Forbidden', 404 => 'NotFound', 599 => 'Unreachable' }->{$code};
    return Kubernetes::REST::HTTPResponse->new(
      status  => $code,
      content => '{"kind":"Status","apiVersion":"v1","status":"'
        . ( $code == 200 ? 'Success' : 'Failure' ) . '","reason":"' . $reason . '","code":' . $code . '}',
    );
  }
  sub call_streaming { die "not used\n" }
}

my @api_for;
{
  no warnings 'redefine';
  *Rex::Rancher::K8s::_api = sub {
    push @api_for, $_[0];
    Kubernetes::REST->new(
      server                    => { endpoint => 'http://mock.local' },
      credentials               => { token => 'test' },
      resource_map_from_cluster => 0,
      io                        => FakeIO->new,
    );
  };
}

my $PLUGIN_DS = '/apis/apps/v1/namespaces/kube-system/daemonsets/amdgpu-device-plugin-daemonset';
my $LAB_DS    = '/apis/apps/v1/namespaces/kube-system/daemonsets/amdgpu-labeller-daemonset';
my $LAB_SA    = '/api/v1/namespaces/kube-system/serviceaccounts/node-labeller-sa';
my $LAB_CRB   = '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/labeller';
my $LAB_CR    = '/apis/rbac.authorization.k8s.io/v1/clusterroles/cr-node-labeller';

sub run_remove {
  my ( $what, %st ) = @_;
  local %status = %st;
  ( @requests, @api_for, @info, @warn ) = ();
  no strict 'refs';
  return eval { &{"Rex::Rancher::K8s::remove_amd_$what"}( kubeconfig => '/tmp/kc.yaml' ); 1 };
}

# --- the device plugin -------------------------------------------------------------

ok( run_remove('device_plugin'), 'plugin: removed' ) or diag $@;
is_deeply( \@api_for, ['/tmp/kc.yaml'], '... through the given kubeconfig' );
is_deeply( \@requests, ["DELETE $PLUGIN_DS"], '... exactly its DaemonSet, nothing of the labeller' );
like( $info[-1], qr{^  Removed DaemonSet/amdgpu-device-plugin-daemonset$}, '... and says so' );
is_deeply( \@warn, [], '... no warning' );

ok( run_remove( 'device_plugin', $PLUGIN_DS => 404 ), 'plugin, not there: no die' ) or diag $@;
is_deeply( \@requests, ["DELETE $PLUGIN_DS"], '... the one DELETE' );
like( $info[-1], qr{^  DaemonSet/amdgpu-device-plugin-daemonset not there, nothing to remove$},
  '... logged' );
is_deeply( \@warn, [], '... as info, not a warning' );

ok( !run_remove( 'device_plugin', $PLUGIN_DS => 403 ), 'plugin, 403: dies' );
my $err = $@;
ok( ref $err && $err->isa('Kubernetes::REST::APIError'), '... with the APIError' );
is( ref $err && $err->code, 403, '... the 403' );
like( "$err", qr/403/, '... which names it' );

ok( !run_remove( 'device_plugin', $PLUGIN_DS => 599 ), 'plugin, no connection (599): dies' );

{
  no warnings 'redefine';
  local *FakeIO::call = sub { die "boom\n" };
  ( @requests, @info, @warn ) = ();
  ok( !eval { Rex::Rancher::K8s::remove_amd_device_plugin( kubeconfig => '/tmp/kc.yaml' ); 1 },
    'plugin, a plain error from below: dies' );
  is( $@, "boom\n", '... with it' );
}

ok( !eval { Rex::Rancher::K8s::remove_amd_device_plugin(); 1 }, 'plugin, no kubeconfig: dies' );
like( $@, qr/^kubeconfig required/, '... saying so' );

# --- the node labeller ---------------------------------------------------------------

my @LABELLER = ( $LAB_DS, $LAB_SA, $LAB_CRB, $LAB_CR );

ok( run_remove('node_labeller'), 'labeller: removed' ) or diag $@;
is_deeply( \@requests, [ map { "DELETE $_" } @LABELLER ],
  '... DaemonSet first, then ServiceAccount, ClusterRoleBinding, ClusterRole; nothing of the plugin' );
is( scalar( grep { /^  Removed / } @info ), 4, '... each one said' );

ok( run_remove( 'node_labeller', map { $_ => 404 } @LABELLER ), 'labeller, nothing there: no die' ) or diag $@;
is_deeply( \@requests, [ map { "DELETE $_" } @LABELLER ], '... still asks for all four' );
is( scalar( grep { /not there, nothing to remove$/ } @info ), 4, '... each logged' );
is_deeply( \@warn, [], '... no warning' );

ok( run_remove( 'node_labeller', $LAB_DS => 404, $LAB_CR => 404 ), 'labeller, half there: no die' ) or diag $@;
is_deeply( [ grep { /^  (Removed|\S+ not there)/ } @info ],
  [ '  DaemonSet/amdgpu-labeller-daemonset not there, nothing to remove',
    '  Removed ServiceAccount/node-labeller-sa',
    '  Removed ClusterRoleBinding/labeller',
    '  ClusterRole/cr-node-labeller not there, nothing to remove' ],
  '... removes what is there, skips the rest' );

ok( !run_remove( 'node_labeller', $LAB_SA => 403 ), 'labeller, 403 on the ServiceAccount: dies' );
is( ref $@ && $@->code, 403, '... with the 403' );
is_deeply( \@requests, [ "DELETE $LAB_DS", "DELETE $LAB_SA" ], '... the DaemonSet gone, nothing after the error' );

ok( !run_remove( 'node_labeller', $LAB_DS => 403 ), 'labeller, 403 on the DaemonSet: dies' );
is_deeply( \@requests, ["DELETE $LAB_DS"], '... the RBAC left in place' );

# The paths are the ones the deploy's objects live at: derived from the same specs.
my @deployed = map { $_->[1]{metadata} } Rex::Rancher::K8s::_amd_node_labeller_specs('1.31.0.11');
is_deeply( [ map { $_->{name} } reverse @deployed ],
  [qw( amdgpu-labeller-daemonset node-labeller-sa labeller cr-node-labeller )],
  'labeller: the names the deploy uses, in reverse' );
is( Rex::Rancher::K8s::_amd_device_plugin_daemonset_spec( '1.31.0.11', 'mixed' )->{metadata}{name},
  'amdgpu-device-plugin-daemonset', 'plugin: the name the deploy uses, whatever the naming' );

ok( !eval { Rex::Rancher::K8s::remove_amd_node_labeller(); 1 }, 'labeller, no kubeconfig: dies' );
like( $@, qr/^kubeconfig required/, '... saying so' );

done_testing;
