use strict;
use warnings;
use Test::More;

use Rex::Rancher;

# k95: which device plugins step 6 deploys, from what Rex::GPU's gpu_setup
# detected (its return value, the detect hashref) and whether that Rex::GPU
# sets up AMD GPUs (Rex::GPU->can('amd_class'), rex-gpu k1). The rule: every
# host deploys exactly as before, except one with a ROCm-capable AMD GPU
# (compute true) and a Rex::GPU that set it up: that one gets the AMD plugin,
# and the NVIDIA plugin only if it has an NVIDIA GPU too. A Rex::GPU without
# AMD support only warns about AMD GPUs, server and agent alike, and never
# dies (it reports every AMD GPU with compute 0, a Ryzen iGPU on a Hetzner AX
# host as well as a real one).
#
# Integrated AMD GPUs (rex-gpu k1: integrated => 1, the Radeon of a Ryzen
# CPU; gfx1103 on a Hetzner AX42 is ROCm-capable) count only with
# gpu_amd_integrated, which passes amd_integrated => 1 to gpu_setup and is
# otherwise not passed at all. Asked for with a Rex::GPU without AMD support,
# it dies before the host is touched. Without it, an integrated ROCm-capable
# one (the AX42's, synapse's gfx1151 APU) gets an info line naming
# gpu_amd_integrated: Rex::GPU's own warning names its amd_integrated, which
# rancher_deploy_* would silently ignore.
#
# Offline: Rex::GPU is a fake served through @INC, every host and API step a
# marker. This proves the decision and its place in the pipeline, not that
# Rex::GPU installs a driver or the plugin finds the GPU.

my @perl_warnings;
$SIG{__WARN__} = sub { push @perl_warnings, @_ };

my $NV     = { name => 'AD104GL [RTX 4000 SFF Ada Generation]', vendor => 'nvidia', compute => 1 };
my $KEPLER = { name => 'GK208B [GeForce GT 710]', vendor => 'nvidia', compute => 0 };
my $W7900  = { name => 'Navi 31 [Radeon Pro W7900]', vendor => 'amd', pci_class => '0300', compute => 1, integrated => 0 };
my $MI     = { name => 'Aqua Vanjaram [Instinct MI300X]', vendor => 'amd', pci_class => '1200', compute => 1, integrated => 0 };
my $MI300A = { name => 'Instinct MI300A', vendor => 'amd', pci_class => '1200', compute => 1, integrated => 0 };
my $IGPU0  = { name => 'Raphael', vendor => 'amd', pci_class => '0300', compute => 0 };
my $IGPUU  = { name => 'Phoenix1', vendor => 'amd', pci_class => '0300', compute => undef };
my $AX42   = { name => 'Phoenix1 [Radeon 780M]', vendor => 'amd', pci_class => '0300',
               gfx_target => 'gfx1103', compute => 1, integrated => 1 };
my $SYNAPSE = { name => 'AMD GPU [1002:1586]', vendor => 'amd', pci_class => '0380',
               gfx_target => 'gfx1151', compute => 1, integrated => 1 };

sub host { my (%g) = @_; return { nvidia => $g{nvidia} // [], amd => $g{amd} // [], nvswitch => [] } }

# --- the decision, a table -----------------------------------------------------
# [ device_plugin, gpus, amd_setup, gpu_amd_integrated ] => [ nvidia, amd, warns ]
my @table = (
  # What gpu_setup returned says nothing: as before, NVIDIA's plugin.
  [ 'nothing returned (gpu_setup did not run)', [ 1, undef, 1 ],                         [ 1, 0, 0 ] ],
  [ 'a number returned',                        [ 1, 3, 1 ],                             [ 1, 0, 0 ] ],
  [ 'a string returned',                        [ 1, 'ok', 0 ],                          [ 1, 0, 0 ] ],
  [ 'an arrayref returned',                     [ 1, [ $W7900 ], 1 ],                    [ 1, 0, 0 ] ],
  [ 'nothing returned, plugin off',             [ 0, undef, 1 ],                         [ 0, 0, 0 ] ],

  # Hosts that deploy today: unchanged, whatever the Rex::GPU.
  [ 'no GPU, AMD-capable Rex::GPU',             [ 1, host(), 1 ],                        [ 1, 0, 0 ] ],
  [ 'no GPU, old Rex::GPU',                     [ 1, host(), 0 ],                        [ 1, 0, 0 ] ],
  [ 'NVIDIA only, AMD-capable Rex::GPU',        [ 1, host( nvidia => [$NV] ), 1 ],       [ 1, 0, 0 ] ],
  [ 'NVIDIA only, old Rex::GPU',                [ 1, host( nvidia => [$NV] ), 0 ],       [ 1, 0, 0 ] ],
  [ 'Kepler only',                              [ 1, host( nvidia => [$KEPLER] ), 1 ],   [ 1, 0, 0 ] ],
  [ 'NVIDIA only, plugin off',                  [ 0, host( nvidia => [$NV] ), 1 ],       [ 0, 0, 0 ] ],

  # Hetzner AX: a Ryzen iGPU only, compute 0 or unknown -> NVIDIA plugin as today.
  [ 'AX iGPU compute 0, AMD-capable',           [ 1, host( amd => [$IGPU0] ), 1 ],       [ 1, 0, 0 ] ],
  [ 'AX iGPU compute undef, AMD-capable',       [ 1, host( amd => [$IGPUU] ), 1 ],       [ 1, 0, 0 ] ],
  [ 'AX iGPU compute 0, old Rex::GPU',          [ 1, host( amd => [$IGPU0] ), 0 ],       [ 1, 0, 1 ] ],
  [ 'AX iGPU compute undef, old Rex::GPU',      [ 1, host( amd => [$IGPUU] ), 0 ],       [ 1, 0, 1 ] ],
  [ 'iGPU + RTX, AMD-capable',                  [ 1, host( nvidia => [$NV], amd => [$IGPU0] ), 1 ], [ 1, 0, 0 ] ],

  # A ROCm-capable AMD GPU and a Rex::GPU that set it up.
  [ 'AMD compute only',                         [ 1, host( amd => [$W7900] ), 1 ],       [ 0, 1, 0 ] ],
  [ 'AMD compute + iGPU, no NVIDIA',            [ 1, host( amd => [ $IGPU0, $MI ] ), 1 ], [ 0, 1, 0 ] ],
  [ 'AMD compute only, plugin off',             [ 0, host( amd => [$W7900] ), 1 ],       [ 0, 0, 0 ] ],
  [ 'mixed NVIDIA + AMD compute',               [ 1, host( nvidia => [$NV], amd => [$MI] ), 1 ], [ 1, 1, 0 ] ],
  [ 'mixed Kepler + AMD compute',               [ 1, host( nvidia => [$KEPLER], amd => [$MI] ), 1 ], [ 1, 1, 0 ] ],
  [ 'mixed, plugin off',                        [ 0, host( nvidia => [$NV], amd => [$MI] ), 1 ], [ 0, 0, 0 ] ],
  [ 'AMD compute, no nvidia key',               [ 1, { amd => [$W7900] }, 1 ],           [ 0, 1, 0 ] ],

  # A Rex::GPU without AMD support: warn about any AMD GPU, otherwise as today.
  [ 'AMD compute only, old Rex::GPU',           [ 1, host( amd => [$W7900] ), 0 ],       [ 1, 0, 1 ] ],
  [ 'mixed, old Rex::GPU',                      [ 1, host( nvidia => [$NV], amd => [$MI] ), 0 ], [ 1, 0, 1 ] ],
  [ 'AMD only, old Rex::GPU, plugin off',       [ 0, host( amd => [$W7900] ), 0 ],       [ 0, 0, 1 ] ],

  # Integrated AMD GPUs: set up only with gpu_amd_integrated.
  [ 'AX42 iGPU (compute 1, integrated 1)',      [ 1, host( amd => [$AX42] ), 1 ],        [ 1, 0, 0 ] ],
  [ 'AX42 iGPU, gpu_amd_integrated',            [ 1, host( amd => [$AX42] ), 1, 1 ],     [ 0, 1, 0 ] ],
  [ 'AX42 iGPU, gpu_amd_integrated, plugin off', [ 0, host( amd => [$AX42] ), 1, 1 ],    [ 0, 0, 0 ] ],
  [ 'AX42 iGPU + RTX',                          [ 1, host( nvidia => [$NV], amd => [$AX42] ), 1 ],    [ 1, 0, 0 ] ],
  [ 'AX42 iGPU + RTX, gpu_amd_integrated',      [ 1, host( nvidia => [$NV], amd => [$AX42] ), 1, 1 ], [ 1, 1, 0 ] ],
  [ 'AX42 iGPU + MI300X',                       [ 1, host( amd => [ $AX42, $MI ] ), 1 ], [ 0, 1, 0 ] ],
  [ 'integrated, compute 0, gpu_amd_integrated', [ 1, host( amd => [ { %$IGPU0, integrated => 1 } ] ), 1, 1 ], [ 1, 0, 0 ] ],
  [ 'integrated undef: not integrated',         [ 1, host( amd => [ { %$W7900, integrated => undef } ] ), 1 ], [ 0, 1, 0 ] ],
  [ 'MI300A (class 1200, integrated 0)',        [ 1, host( amd => [$MI300A] ), 1 ],      [ 0, 1, 0 ] ],
  [ 'AX42 iGPU, old Rex::GPU, gpu_amd_integrated', [ 1, host( amd => [$AX42] ), 0, 1 ], [ 1, 0, 1 ] ],
);

for my $row (@table) {
  my ( $name, $in, $want ) = @$row;
  my ( $plugin, $gpus, $amd_setup, $amd_integrated ) = @$in;
  my $plan = Rex::Rancher::_gpu_vendor_plan( device_plugin => $plugin, gpus => $gpus,
    amd_setup => $amd_setup, amd_integrated => $amd_integrated, rex_gpu_version => '0.005' );
  is_deeply( [ @{$plan}{qw( nvidia amd )}, scalar @{ $plan->{warn} } ], $want, $name );
}

my $plan = Rex::Rancher::_gpu_vendor_plan( device_plugin => 1,
  gpus => host( nvidia => [$NV], amd => [ $IGPU0, $MI ] ), amd_setup => 0, rex_gpu_version => '0.005' );
like( $plan->{warn}[0], qr/^Rex::GPU 0\.005 does not set up AMD GPUs, so this deploy installs no driver and no amd\.com\/gpu device plugin for Raphael, Aqua Vanjaram \[Instinct MI300X\] and goes on as without it\. /,
  'the warning names the Rex::GPU and every AMD GPU' );
like( $plan->{warn}[0], qr/install a Rex-GPU that sets up AMD GPUs \(it has Rex::GPU->amd_class\), or provide the driver on the host and run deploy_amd_device_plugin\z/,
  '... and what to do' );
like( Rex::Rancher::_gpu_vendor_plan( device_plugin => 1, gpus => host( amd => [ {} ] ) )->{warn}[0],
  qr/^Rex::GPU does not set up AMD GPUs, .* for AMD GPU and goes on/, '... without a version or a name' );

# --- the hint: an integrated, ROCm-capable AMD GPU left alone --------------------
# Only with a Rex::GPU that sets up AMD GPUs (one without warns already), only
# for compute true and integrated true, and not with gpu_amd_integrated.
# [ gpus, amd_setup, gpu_amd_integrated, device_plugin ] => info lines
my @hints = (
  [ 'AX42 iGPU',                        [ host( amd => [$AX42] ), 1, 0, 1 ],    1 ],
  [ 'synapse APU',                      [ host( amd => [$SYNAPSE] ), 1, 0, 1 ], 1 ],
  [ 'AX42 iGPU + RTX',                  [ host( nvidia => [$NV], amd => [$AX42] ), 1, 0, 1 ], 1 ],
  [ 'AX42 iGPU + MI300X',               [ host( amd => [ $AX42, $MI ] ), 1, 0, 1 ], 1 ],
  [ 'AX42 iGPU, plugin off',            [ host( amd => [$AX42] ), 1, 0, 0 ],    1 ],
  [ 'AX42 iGPU, gpu_amd_integrated',    [ host( amd => [$AX42] ), 1, 1, 1 ],    0 ],
  [ 'synapse APU, gpu_amd_integrated',  [ host( amd => [$SYNAPSE] ), 1, 1, 1 ], 0 ],
  [ 'AX42 iGPU, old Rex::GPU',          [ host( amd => [$AX42] ), 0, 0, 1 ],    0 ],
  [ 'integrated, compute 0',            [ host( amd => [ { %$IGPU0, integrated => 1 } ] ), 1, 0, 1 ], 0 ],
  [ 'integrated, compute undef',        [ host( amd => [ { %$IGPUU, integrated => 1 } ] ), 1, 0, 1 ], 0 ],
  [ 'iGPU compute 0, integrated unset', [ host( amd => [$IGPU0] ), 1, 0, 1 ],   0 ],
  [ 'discrete W7900',                   [ host( amd => [$W7900] ), 1, 0, 1 ],   0 ],
  [ 'MI300A (integrated 0)',            [ host( amd => [$MI300A] ), 1, 0, 1 ],  0 ],
  [ 'nothing returned',                 [ undef, 1, 0, 1 ],                     0 ],
);
my $plan_for = sub {
  my ( $gpus, $amd_setup, $amd_integrated, $plugin ) = @_;
  return Rex::Rancher::_gpu_vendor_plan( device_plugin => $plugin // 1, gpus => $gpus,
    amd_setup => $amd_setup, amd_integrated => $amd_integrated, rex_gpu_version => '0.005' );
};
for my $row (@hints) {
  my ( $name, $in, $want ) = @$row;
  is( scalar @{ $plan_for->(@$in)->{info} }, $want, "hint: $name" );
}
is_deeply( $plan_for->( host( amd => [ { %$IGPU0, integrated => 1 }, $SYNAPSE ] ), 1, 0 )->{info},
  [ "AMD GPU [1002:1586] is an integrated, ROCm-capable AMD GPU left alone; pass "
    . "gpu_amd_integrated => 1 to set it up (gpu_setup's amd_integrated)" ],
  'the hint names the ROCm-capable integrated GPU only, and the option' );
is_deeply( $plan_for->( host( amd => [ $AX42, $SYNAPSE ] ), 1, 0 )->{info},
  [ "Phoenix1 [Radeon 780M], AMD GPU [1002:1586] are integrated, ROCm-capable AMD GPUs "
    . "left alone; pass gpu_amd_integrated => 1 to set them up (gpu_setup's amd_integrated)" ],
  '... both of two, in one line' );

# --- the feature check -----------------------------------------------------------
# A fake Rex::GPU, defined here; @INC serves it so nothing installed is loaded.
our ( @gpu_setup_calls, @ran, $detected );
{
  package Rex::GPU;
  our $VERSION = '0.005';
  sub import {}
  sub gpu_setup { push @main::gpu_setup_calls, {@_}; push @main::ran, 'gpu_setup'; $main::detected }
}
$INC{'Rex/GPU.pm'} = __FILE__;
# The glob is looked up at run time: a *Rex::GPU::amd_class compiled here
# would keep pointing at the glob the delete takes out of the stash.
sub amd_capable {
  my ($on) = @_;
  no strict 'refs';
  if ($on) { *{'Rex::GPU::amd_class'} = sub { 'Rex::GPU::AMD' } }
  else     { delete $Rex::GPU::{amd_class} }
}

amd_capable(0);
is( Rex::Rancher::_rex_gpu_sets_up_amd(), 0, 'Rex::GPU without amd_class: no AMD setup' );
amd_capable(1);
is( Rex::Rancher::_rex_gpu_sets_up_amd(), 1, 'Rex::GPU with amd_class: sets up AMD' );

# --- the pipelines ---------------------------------------------------------------
our ( %nvidia_args, %amd_args );
no warnings 'redefine';
local *Rex::Rancher::_check_connection           = sub { push @ran, 'check_connection' };
local *Rex::Rancher::prepare_node                = sub { push @ran, 'prepare_node' };
local *Rex::Rancher::install_server              = sub { push @ran, 'install_server' };
local *Rex::Rancher::install_agent               = sub { push @ran, 'install_agent' };
local *Rex::Rancher::Server::preflight_server    = sub { {} };
local *Rex::Rancher::Agent::preflight_agent      = sub { {} };
local *Rex::Rancher::_save_kubeconfig_locally    = sub { push @ran, 'save_kubeconfig'; $_[1] };
local *Rex::Rancher::wait_for_api                = sub { push @ran, 'wait_for_api'; 1 };
local *Rex::Rancher::install_cilium              = sub { push @ran, 'install_cilium' };
local *Rex::Rancher::deploy_nvidia_device_plugin = sub { push @ran, 'nvidia_plugin'; %nvidia_args = @_ };
local *Rex::Rancher::deploy_amd_device_plugin    = sub { push @ran, 'amd_plugin'; %amd_args = @_ };
my ( @warned, @hinted );
local *Rex::Logger::info = sub {
  if    ( ( $_[1] // '' ) eq 'warn' )          { push @ran, 'warn'; push @warned, $_[0] }
  elsif ( $_[0] =~ /pass gpu_amd_integrated/ ) { push @ran, 'hint'; push @hinted, $_[0] }
};
use warnings 'redefine';

sub on_host {
  my ( $gpus, $capable ) = @_;
  ( @ran, @gpu_setup_calls, @warned, @hinted ) = ();
  ( %nvidia_args, %amd_args ) = ();
  $detected = $gpus;
  amd_capable($capable);
}

my %server = ( kubeconfig_file => '/nonexistent/kc.yaml', tls_san => '10.0.0.1' );
my @server_head = qw( check_connection prepare_node gpu_setup );
my @server_tail = qw( install_server save_kubeconfig wait_for_api install_cilium );

for my $dist (qw( rke2 k3s )) {
  on_host( host( amd => [$W7900] ), 1 );
  Rex::Rancher::rancher_deploy_server( %server, distribution => $dist, gpu => 1 );
  is_deeply( \@ran, [ @server_head, @server_tail, 'amd_plugin' ],
    "server $dist, AMD compute only: the AMD plugin instead of NVIDIA's, after Cilium" );
  is_deeply( \%amd_args, { kubeconfig => '/nonexistent/kc.yaml' },
    '... through the saved kubeconfig, no labeller, no affinity' );
  is_deeply( \@gpu_setup_calls, [ { containerd_config => $dist, reboot => 0 } ],
    '... gpu_setup called as before' );
}

on_host( host( nvidia => [$NV], amd => [$MI] ), 1 );
Rex::Rancher::rancher_deploy_server( %server, gpu => 1 );
is_deeply( \@ran, [ @server_head, @server_tail, qw( nvidia_plugin amd_plugin ) ],
  'server, mixed: both plugins, NVIDIA first' );
is_deeply( \%nvidia_args, { kubeconfig => '/nonexistent/kc.yaml' }, '... the NVIDIA one as before' );

on_host( host( nvidia => [$NV], amd => [$MI] ), 1 );
Rex::Rancher::rancher_deploy_server( %server, gpu => 1, gpu_device_plugin => 0 );
is_deeply( \@ran, [ @server_head, @server_tail ], 'server, mixed, gpu_device_plugin => 0: no plugin' );

on_host( host( amd => [$W7900] ), 1 );
Rex::Rancher::rancher_deploy_server( tls_san => '10.0.0.1', gpu => 1 );
is_deeply( \@ran, [ @server_head, qw( install_server save_kubeconfig install_cilium ) ],
  'server, AMD compute only, no kubeconfig_file: no plugin' );

on_host( host( nvidia => [$NV] ), 1 );
Rex::Rancher::rancher_deploy_server( %server, gpu => 1 );
is_deeply( \@ran, [ @server_head, @server_tail, 'nvidia_plugin' ], 'server, NVIDIA only: as before' );

# Hetzner AX: Ryzen iGPU, no NVIDIA. Today's NVIDIA plugin, with any Rex::GPU.
for my $igpu ( $IGPU0, $IGPUU ) {
  my $c = $igpu->{compute} // 'undef';
  on_host( host( amd => [$igpu] ), 1 );
  ok( eval { Rex::Rancher::rancher_deploy_server( %server, gpu => 1 ); 1 }, "server, AX iGPU compute $c, AMD-capable: no die" )
    or diag $@;
  is_deeply( \@ran, [ @server_head, @server_tail, 'nvidia_plugin' ], '... NVIDIA plugin as today, no AMD plugin, no warning' );

  on_host( host( amd => [$igpu] ), 0 );
  ok( eval { Rex::Rancher::rancher_deploy_server( %server, gpu => 1 ); 1 }, "server, AX iGPU compute $c, old Rex::GPU: no die" )
    or diag $@;
  is_deeply( \@ran, [ @server_head, 'warn', @server_tail, 'nvidia_plugin' ],
    '... a warning before install_server, then as today' );
  like( $warned[0], qr/^Rex::GPU 0\.005 does not set up AMD GPUs, .* for \Q$igpu->{name}\E /, '... naming the GPU' );
}

on_host( host( amd => [$W7900] ), 0 );
ok( eval { Rex::Rancher::rancher_deploy_server( %server, gpu => 1 ); 1 }, 'server, AMD compute only, old Rex::GPU: no die' )
  or diag $@;
is_deeply( \@ran, [ @server_head, 'warn', @server_tail, 'nvidia_plugin' ], '... warns, then as today' );

on_host( 1, 1 );
Rex::Rancher::rancher_deploy_server( %server, gpu => 1 );
is_deeply( \@ran, [ @server_head, @server_tail, 'nvidia_plugin' ], 'server, gpu_setup returns no hashref: as before' );

on_host( host( amd => [$W7900] ), 1 );
Rex::Rancher::rancher_deploy_server( %server, gpu => 1, gpu_setup => 0 );
is_deeply( \@ran, [qw( check_connection prepare_node ), @server_tail, 'nvidia_plugin' ],
  'server, gpu_setup => 0: nothing detected, NVIDIA plugin as before' );
is_deeply( \@gpu_setup_calls, [], '... gpu_setup not called' );

on_host( host( amd => [$W7900] ), 1 );
Rex::Rancher::rancher_deploy_server(%server);
is_deeply( \@ran, [ qw( check_connection prepare_node ), @server_tail ], 'server, no gpu: nothing GPU-side' );

# The agent: no plugin step; only the old-Rex::GPU warning, also before the install.
my %agent = ( server => 'https://cp:9345', token => 't' );
for my $dist (qw( rke2 k3s )) {
  on_host( host( amd => [$IGPU0] ), 0 );
  ok( eval { Rex::Rancher::rancher_deploy_agent( %agent, distribution => $dist, gpu => 1 ); 1 },
    "agent $dist, AMD GPU, old Rex::GPU: no die" ) or diag $@;
  is_deeply( \@ran, [qw( check_connection prepare_node gpu_setup warn install_agent )],
    '... a warning before install_agent, which runs' );
}

on_host( host( amd => [$W7900] ), 1 );
Rex::Rancher::rancher_deploy_agent( %agent, gpu => 1 );
is_deeply( \@ran, [qw( check_connection prepare_node gpu_setup install_agent )],
  'agent, AMD compute only, AMD-capable: no plugin, no warning' );

on_host( host( nvidia => [$NV], amd => [$MI] ), 1 );
Rex::Rancher::rancher_deploy_agent( %agent, gpu => 1 );
is_deeply( \@ran, [qw( check_connection prepare_node gpu_setup install_agent )], 'agent, mixed: no plugin' );

# --- gpu_amd_integrated ---------------------------------------------------------
# Hetzner AX42 (a Ryzen iGPU, gfx1103) and synapse (a Strix Halo APU,
# gfx1151): ROCm-capable and integrated. Without the option, as today plus
# the hint before the install; gpu_setup gets no amd_integrated key at all.
for my $igpu ( $AX42, $SYNAPSE ) {
  my $g = $igpu->{gfx_target};
  for my $off ( [ 'no gpu_amd_integrated' ], [ 'gpu_amd_integrated => 0', gpu_amd_integrated => 0 ] ) {
    my ( $what, @o ) = @$off;
    on_host( host( amd => [$igpu] ), 1 );
    Rex::Rancher::rancher_deploy_server( %server, gpu => 1, @o );
    is_deeply( \@ran, [ @server_head, 'hint', @server_tail, 'nvidia_plugin' ],
      "server, $g, $what: the hint, then the NVIDIA plugin as today, no AMD plugin" );
    like( $hinted[0], qr/^\Q$igpu->{name}\E is an integrated, ROCm-capable AMD GPU left alone; pass gpu_amd_integrated => 1 /,
      '... the hint names the GPU and the option' );
    is_deeply( \@gpu_setup_calls, [ { containerd_config => 'rke2', reboot => 0 } ],
      '... gpu_setup without amd_integrated' );

    on_host( host( amd => [$igpu] ), 1 );
    Rex::Rancher::rancher_deploy_agent( %agent, gpu => 1, @o );
    is_deeply( \@ran, [qw( check_connection prepare_node gpu_setup hint install_agent )],
      "agent, $g, $what: the hint before install_agent" );
    is_deeply( \@gpu_setup_calls, [ { containerd_config => 'rke2', reboot => 0 } ],
      '... gpu_setup without amd_integrated' );
  }
}

for my $dist (qw( rke2 k3s )) {
  for my $igpu ( $AX42, $SYNAPSE ) {
    my $g = $igpu->{gfx_target};
    on_host( host( amd => [$igpu] ), 1 );
    Rex::Rancher::rancher_deploy_server( %server, distribution => $dist, gpu => 1, gpu_amd_integrated => 1 );
    is_deeply( \@ran, [ @server_head, @server_tail, 'amd_plugin' ],
      "server $dist, $g, gpu_amd_integrated: the AMD plugin, no NVIDIA plugin, no hint" );
    is_deeply( \@gpu_setup_calls, [ { containerd_config => $dist, reboot => 0, amd_integrated => 1 } ],
      '... gpu_setup gets amd_integrated => 1' );
  }

  on_host( host( amd => [$AX42] ), 1 );
  Rex::Rancher::rancher_deploy_agent( %agent, distribution => $dist, gpu => 1, gpu_amd_integrated => 1 );
  is_deeply( \@gpu_setup_calls, [ { containerd_config => $dist, reboot => 0, amd_integrated => 1 } ],
    "agent $dist, gpu_amd_integrated: gpu_setup gets amd_integrated => 1" );
  is_deeply( \@ran, [qw( check_connection prepare_node gpu_setup install_agent )], '... no warning, no hint' );
}

# A Rex::GPU without AMD support: its warning, no hint.
on_host( host( amd => [$SYNAPSE] ), 0 );
Rex::Rancher::rancher_deploy_server( %server, gpu => 1 );
is_deeply( \@ran, [ @server_head, 'warn', @server_tail, 'nvidia_plugin' ],
  'server, gfx1151, Rex::GPU without AMD support: the warning, no hint' );

on_host( host( nvidia => [$NV], amd => [$AX42] ), 1 );
Rex::Rancher::rancher_deploy_server( %server, gpu => 1, gpu_amd_integrated => 1 );
is_deeply( \@ran, [ @server_head, @server_tail, qw( nvidia_plugin amd_plugin ) ],
  'server, AX42 iGPU + RTX, gpu_amd_integrated: both plugins' );

# Asked for with a Rex::GPU that sets up no AMD GPU: dies before the host.
my %deploy = (
  server => sub { Rex::Rancher::rancher_deploy_server( %server, @_ ) },
  agent  => sub { Rex::Rancher::rancher_deploy_agent( %agent, @_ ) },
);
for my $role (qw( server agent )) {
  for my $dist (qw( rke2 k3s )) {
    on_host( host( amd => [$AX42] ), 0 );
    ok( !eval { $deploy{$role}->( distribution => $dist, gpu => 1, gpu_amd_integrated => 1 ); 1 },
      "$role $dist, gpu_amd_integrated, Rex::GPU without AMD support: dies" );
    is( $@, "gpu_amd_integrated requested but Rex::GPU 0.005 does not set up AMD GPUs "
      . "(it has no Rex::GPU->amd_class): install a Rex-GPU that does, or leave "
      . "gpu_amd_integrated off; nothing was done on the host\n", '... saying why and what to do' );
    is_deeply( \@ran, [], '... before the connection check and prepare_node' );
    is_deeply( \@gpu_setup_calls, [], '... gpu_setup not called' );
  }
}

# Without gpu_setup it is ignored with a warning, as reboot; Rex::GPU is not
# asked. Without gpu, ignored like every GPU option.
on_host( host( amd => [$AX42] ), 0 );
ok( eval { Rex::Rancher::rancher_deploy_server( %server, gpu => 1, gpu_setup => 0, gpu_amd_integrated => 1 ); 1 },
  'server, gpu_setup => 0, gpu_amd_integrated, Rex::GPU without AMD support: no die' ) or diag $@;
is_deeply( \@ran, [ qw( check_connection prepare_node warn ), @server_tail, 'nvidia_plugin' ],
  '... a warning, then as with gpu_setup => 0' );
is_deeply( \@warned, [ 'gpu_amd_integrated is ignored with gpu_setup => 0' ], '... saying it is ignored' );

on_host( host( amd => [$AX42] ), 0 );
ok( eval { Rex::Rancher::rancher_deploy_agent( %agent, gpu => 1, gpu_setup => 0, gpu_amd_integrated => 1 ); 1 },
  'agent, gpu_setup => 0, gpu_amd_integrated: no die' ) or diag $@;
is_deeply( \@ran, [qw( check_connection prepare_node warn install_agent )], '... the same warning' );

on_host( host( amd => [$AX42] ), 0 );
ok( eval { Rex::Rancher::rancher_deploy_server( %server, gpu_amd_integrated => 1 ); 1 },
  'server, no gpu, gpu_amd_integrated: no die' ) or diag $@;
is_deeply( \@ran, [ qw( check_connection prepare_node ), @server_tail ], '... nothing GPU-side' );

is_deeply( \@perl_warnings, [], 'no Perl warnings' );

done_testing;
