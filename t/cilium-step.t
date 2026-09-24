use strict;
use warnings;
use Test::More;

use Rex::Rancher;

# Whether rancher_deploy_server runs install_cilium, and that cilium => 0
# with Cilium-only options dies before any remote step. Offline: every
# remote/API step is replaced by a fake that records the order.

my @ran;
no warnings 'redefine';
local *Rex::Rancher::_check_connection           = sub { push @ran, 'check_connection' };
local *Rex::Rancher::prepare_node                = sub { push @ran, 'prepare_node' };
local *Rex::Rancher::install_server              = sub { push @ran, 'install_server' };
local *Rex::Rancher::_save_kubeconfig_locally    = sub { push @ran, 'save_kubeconfig'; $_[1] };
our $api_up = 1;
our %cilium_opts;
local *Rex::Rancher::wait_for_api                = sub { push @ran, 'wait_for_api'; $api_up };
local *Rex::Rancher::install_cilium              = sub { push @ran, 'install_cilium'; %cilium_opts = @_ };
local *Rex::Rancher::deploy_nvidia_device_plugin = sub { push @ran, 'device_plugin' };
use warnings 'redefine';

my %server = ( kubeconfig_file => '/nonexistent/kc.yaml' );

@ran = ();
Rex::Rancher::rancher_deploy_server(%server);
is_deeply(\@ran,
  [qw( check_connection prepare_node install_server save_kubeconfig wait_for_api install_cilium )],
  'default: install_cilium runs');

@ran = ();
Rex::Rancher::rancher_deploy_server(%server, cilium => 1);
is($ran[-1], 'install_cilium', 'cilium => 1: install_cilium runs');

for my $dist (qw( rke2 k3s )) {
  @ran = ();
  Rex::Rancher::rancher_deploy_server(%server, distribution => $dist, cilium => 0);
  is_deeply(\@ran,
    [qw( check_connection prepare_node install_server save_kubeconfig wait_for_api )],
    $dist.', cilium => 0: no install_cilium, API still awaited');
}

# Harmless leftovers do not trip the check.
@ran = ();
Rex::Rancher::rancher_deploy_server(%server, cilium => 0, gateway_api => 0, cilium_version => undef);
ok(!grep({ $_ eq 'install_cilium' } @ran), 'cilium => 0 with gateway_api => 0 / undef version: runs');

my %contradiction = (
  gateway_api        => [ gateway_api => 1, gateway_api_version => 'v1.2.0' ],
  cilium_version     => [ cilium_version     => '1.16.5' ],
  cilium_cli_version => [ cilium_cli_version => 'v0.16.22' ],
  cilium_helm_values => [ cilium_helm_values => {} ]
);
for my $opt (sort keys %contradiction) {
  @ran = ();
  my $ok = eval {
    Rex::Rancher::rancher_deploy_server(%server, cilium => 0, @{ $contradiction{$opt} });
    1;
  };
  ok(!$ok, 'cilium => 0 + '.$opt.': dies');
  like($@, qr/cilium => 0 .*\b\Q$opt\E\b/, 'cilium => 0 + '.$opt.': names the option');
  is_deeply(\@ran, [], 'cilium => 0 + '.$opt.': before any remote step');
}

# The existing early validation still guards the Cilium case.
@ran = ();
ok(!eval { Rex::Rancher::rancher_deploy_server(%server, gateway_api => 1); 1 },
  'cilium on, gateway_api without version: dies');
is_deeply(\@ran, [], 'cilium on, invalid option: before any remote step');

# wait_for_api timed out with a saved kubeconfig: die naming the API, before
# Cilium and the device plugin. Same on both distributions.
for my $dist (qw( rke2 k3s )) {
  @ran = ();
  local $api_up = 0;
  ok(!eval {
    Rex::Rancher::rancher_deploy_server(%server, distribution => $dist,
      tls_san => ['cp.example.com'], gpu => 1, gpu_setup => 0);
    1;
  }, $dist.', API timeout: dies');
  like($@, qr/API at cp\.example\.com did not answer through \Q$server{kubeconfig_file}\E/,
    $dist.', API timeout: names address and kubeconfig');
  unlike($@, qr/gateway_api/, $dist.', API timeout: not the gateway_api message');
  is_deeply(\@ran,
    [qw( check_connection prepare_node install_server save_kubeconfig wait_for_api )],
    $dist.', API timeout: no Cilium, no device plugin');
}

# Without kubeconfig_file nothing is awaited; Cilium goes the remote-only way.
{
  @ran = ();
  local $api_up = 0;
  Rex::Rancher::rancher_deploy_server();
  is_deeply(\@ran, [qw( check_connection prepare_node install_server save_kubeconfig install_cilium )],
    'no kubeconfig_file: no wait, Cilium still installed');
  ok(!exists $cilium_opts{kubeconfig}, 'no kubeconfig_file: install_cilium without kubeconfig');
}

# API up: install_cilium gets the saved kubeconfig.
@ran = ();
Rex::Rancher::rancher_deploy_server(%server);
is($cilium_opts{kubeconfig}, $server{kubeconfig_file}, 'API up: install_cilium gets the kubeconfig');

done_testing;
