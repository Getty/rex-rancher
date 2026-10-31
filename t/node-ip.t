use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# node_ip and node_external_ip (k100): the addresses a node advertises as its
# InternalIP and ExternalIP, written as node-ip and node-external-ip to
# config.yaml, server and agent, rke2 and k3s alike. Without node-ip a
# multi-homed node registers with the address of its default route; on
# synapse (kubernetes-ocp k248) that was an address the control plane could
# not reach: Cilium's tunnel broke in one direction, nfd-worker could not
# deliver, pulls through the node-port mirror hung.
#
# - The value is one address, several separated by commas, or an arrayref,
#   and goes into config.yaml as a YAML list (like tls-san and node-label:
#   StringSlice flags in k3s, copied as they are by RKE2). Anything else dies
#   before the host is touched; unset, no key is written, as before.
# - config.yaml is written whole on every run. A re-run without the option
#   keeps what config.yaml holds, as a re-run keeps the hostname (Node.pm)
#   and the cluster token; one that changes it warns, naming both and the
#   Cilium agent pod that has to be restarted by hand.
#
# run, file and the logger are faked. This proves the option check, the
# config.yaml content and the re-run decision, not that a real node
# advertises the address or that Cilium follows it -- only a live run does.
# -----------------------------------------------------------------------------

use YAML::PP;
use Rex::Rancher::Agent;
use Rex::Rancher::Server;
use Rex::Rancher::Distribution;
use Rex::Rancher::Options;

my $D = 'Rex::Rancher::Distribution';

my @perl_warnings;
$SIG{__WARN__} = sub { push @perl_warnings, @_ };

# A fresh host: no service, no binary before the install, no state. %files
# is what `cat 'PATH' 2>/dev/null` finds (config.yaml of an earlier run).
my ( @log, @msg, %written, %files );
{
  no warnings 'redefine';
  my $run = sub {
    my ( $cmd ) = @_;
    push @log, $cmd;
    $? = 0;
    if ( $cmd =~ m{^cat '([^']+)' 2>/dev/null\z} ) {
      return $files{$1} if exists $files{$1};
      $? = 1 << 8;
      return '';
    }
    if ( $cmd =~ /^systemctl is-active --quiet / ) { $? = 3 << 8; return '' }
    return "active\n"               if $cmd =~ /^systemctl is-active /;
    return "MainPID=0\n"            if $cmd =~ /^systemctl show -p MainPID /;
    return "/usr/local/bin/rke2\n"  if $cmd =~ /^command -v rke2/;
    return "yes\n"                  if $cmd =~ /^test -f /;
    if ( $cmd =~ /^(?:test -[ed] |cat |curl -fsSL -o \/dev\/null |(?:rke2|k3s) --version)/ ) {
      $? = 1 << 8;
      return '';
    }
    return '';
  };
  *Rex::Commands::Run::run    = $run;
  *Rex::Rancher::Server::run  = $run;
  *Rex::Rancher::Agent::run   = $run;
  # One sub for both: Rex::Exporter aliases the whole glob.
  my $file = sub { my ( $p, %o ) = @_; push @log, "file $p"; $written{$p} = $o{content} if exists $o{content} };
  *Rex::Commands::File::file  = $file;
  *Rex::Rancher::Server::file = $file;
  *Rex::Commands::File::get_tmp_file_name = sub { '/tmp/.rex.tmp' };
  *Rex::Logger::info = sub { push @msg, [ $_[0], $_[1] // 'info' ] };
}

sub reset_host { @log = (); @msg = (); %written = (); %files = @_ }
sub logged     { my ( $level ) = @_; map { $_->[0] } grep { $_->[1] eq $level } @msg }
sub node_warnings { grep { /node-(?:external-)?ip/ } logged('warn') }

my %JOIN = ( rke2 => 'https://cp:9345', k3s => 'https://cp:6443' );

sub install {
  my ( $dist, $role, %opts ) = @_;
  return $role eq 'agent'
    ? Rex::Rancher::Agent::install_agent( distribution => $dist, server => $JOIN{$dist}, token => 't', %opts )
    : Rex::Rancher::Server::install_server( distribution => $dist, token => 't', cilium => 0, %opts );
}

sub config_of {
  my ( $dist ) = @_;
  my $text = $written{"/etc/rancher/$dist/config.yaml"};
  return defined $text ? YAML::PP->new->load_string($text) : undef;
}

# ---- the option check -------------------------------------------------------

subtest 'check_node_addresses' => sub {
  my $check = sub { Rex::Rancher::Options->check_node_addresses(@_) };
  is( scalar $check->( node_ip => undef ), undef, 'undef: none' );
  my %ok = (
    '10.230.30.50'              => ['10.230.30.50'],
    'fd00:30::50'               => ['fd00:30::50'],
    '10.230.30.50,fd00:30::50'  => [ '10.230.30.50', 'fd00:30::50' ],
  );
  is_deeply( $check->( node_ip => $_ ), $ok{$_}, "'$_'" ) for sort keys %ok;
  is_deeply( $check->( node_ip => [ '10.230.30.50', 'fd00:30::50' ] ), [ '10.230.30.50', 'fd00:30::50' ],
    'an arrayref, dual-stack' );
  my $given = ['203.0.113.7'];
  my $got   = $check->( node_external_ip => $given );
  push @{$got}, 'x';
  is_deeply( $given, ['203.0.113.7'], 'returns a copy: the caller\'s list is left alone' );

  my @bad = (
    [ { a => 1 },               qr/got a HASH reference\n\z/ ],
    [ \'10.0.0.1',              qr/got a SCALAR reference\n\z/ ],
    [ sub { },                  qr/got a CODE reference\n\z/ ],
    [ '',                       qr/got an empty string\n\z/ ],
    [ [],                       qr/got an empty list\n\z/ ],
    [ [undef],                  qr/got an undefined element\n\z/ ],
    [ [ ['10.0.0.1'] ],         qr/got a ARRAY reference\n\z/ ],
    [ 'eth0',                   qr/got 'eth0'\n\z/ ],
    [ 'cp.example.com',         qr/got 'cp\.example\.com'\n\z/ ],
    [ '10.0.0.256',             qr/got '10\.0\.0\.256'\n\z/ ],
    [ '10.0.0.0/24',            qr/got '10\.0\.0\.0\/24'\n\z/ ],
    [ 'fe80::1%eth0',           qr/got 'fe80::1%eth0'\n\z/ ],
    [ '10.0.0.1, fd00::1',      qr/got ' fd00::1'\n\z/ ],
    [ '10.0.0.1,',              qr/got ''\n\z/ ],
    [ ['10.0.0.1,fd00::1'],     qr/got '10\.0\.0\.1,fd00::1'\n\z/ ],
  );
  for my $case (@bad) {
    my ( $value, $why ) = @{$case};
    for my $name (qw( node_ip node_external_ip )) {
      ok( !eval { $check->( $name => $value ); 1 }, "$name: dies for $why" );
      like( $@, qr/\A\Q$name\E must be an IP address, several separated by commas, or an array reference of them \(one IPv4 and one IPv6 for dual-stack\), /,
        '  naming the option and the forms it takes' );
      like( $@, $why, '  and what it got' );
    }
  }
};

# ---- config.yaml ------------------------------------------------------------

subtest 'the builders: lists in, lists out, nothing unset' => sub {
  for my $dist (qw( rke2 k3s )) {
    my $d = $D->new_for($dist);
    my @base = ( $d, 't', undef, undef, undef, 1, undef, undef, undef, undef );
    my $c = Rex::Rancher::Server::_build_server_config( @base, [ '10.0.0.5', 'fd00::5' ], ['203.0.113.7'] );
    is_deeply( $c->{'node-ip'}, [ '10.0.0.5', 'fd00::5' ], "$dist server: node-ip" );
    is_deeply( $c->{'node-external-ip'}, ['203.0.113.7'], "$dist server: node-external-ip" );
    $c = Rex::Rancher::Server::_build_server_config(@base);
    ok( !exists $c->{'node-ip'} && !exists $c->{'node-external-ip'}, "$dist server: neither unset" );
  }
  my %join = ( server => 'https://cp:9345', token => 't' );
  my $c = Rex::Rancher::Agent::_build_agent_config( %join, node_ip => ['10.0.0.5'],
    node_external_ip => ['203.0.113.7'] );
  is_deeply( $c, { %join, 'node-ip' => ['10.0.0.5'], 'node-external-ip' => ['203.0.113.7'] },
    'agent: both, next to server and token' );
  $c = Rex::Rancher::Agent::_build_agent_config( %join, node_ip => undef, node_external_ip => undef );
  is_deeply( $c, \%join, 'agent: neither when undef' );
};

for my $dist (qw( rke2 k3s )) {
  for my $role (qw( server agent )) {
    my $cfg = "/etc/rancher/$dist/config.yaml";

    subtest "$dist $role: config.yaml" => sub {
      reset_host();
      ok( eval { install( $dist, $role ); 1 }, 'unset: installs' ) or diag $@;
      ok( defined $written{$cfg}, 'config.yaml written' );
      unlike( $written{$cfg} // '', qr/node-(?:external-)?ip/, 'neither key, as before' );
      ok( ( grep { $_ eq "cat '$cfg' 2>/dev/null" } @log ), 'config.yaml read over the exec channel' );

      reset_host();
      ok( eval { install( $dist, $role, node_ip => '10.230.30.50' ); 1 }, 'a string: installs' ) or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, ['10.230.30.50'], 'node-ip: a one-element list' );
      ok( !exists config_of($dist)->{'node-external-ip'}, 'no node-external-ip' );
      like( $written{$cfg}, qr/^node-ip:\n- /m, 'a YAML list in the file' );
      is_deeply( [ node_warnings() ], [], 'a fresh node: no warning' );

      reset_host();
      ok( eval { install( $dist, $role, node_ip => '10.230.30.50,fd00:30::50',
        node_external_ip => ['203.0.113.7'] ); 1 }, 'comma string and arrayref: installs' ) or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, [ '10.230.30.50', 'fd00:30::50' ], 'node-ip: both, in order' );
      is_deeply( config_of($dist)->{'node-external-ip'}, ['203.0.113.7'], 'node-external-ip' );

      for my $bad ( [ node_ip => { ip => '10.0.0.1' } ], [ node_external_ip => 'eth0' ] ) {
        reset_host();
        ok( !eval { install( $dist, $role, @{$bad} ); 1 }, "invalid $bad->[0]: dies" );
        like( $@, qr/\A\Q$bad->[0]\E must be an IP address/, '  naming it' );
        is_deeply( \@log, [], '  before any command ran on the host' );
      }
    };

    # ---- re-runs ------------------------------------------------------------

    my $service = $D->new_for( $dist, role => $role )->service;
    my $earlier = "token: t\nnode-ip:\n- 10.230.30.50\nnode-external-ip: 203.0.113.7\n";

    subtest "$dist $role: a re-run keeps what config.yaml holds" => sub {
      reset_host( $cfg => $earlier );
      ok( eval { install( $dist, $role ); 1 }, 'neither given: installs' ) or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, ['10.230.30.50'], 'node-ip kept' );
      is_deeply( config_of($dist)->{'node-external-ip'}, ['203.0.113.7'], 'node-external-ip kept, as a list' );
      is_deeply( [ grep { /^Keeping node-/ } logged('info') ],
        [ "Keeping node-ip 10.230.30.50 from $cfg (node_ip not given)",
          "Keeping node-external-ip 203.0.113.7 from $cfg (node_external_ip not given)" ],
        'says so, for each' );
      is_deeply( [ node_warnings() ], [], 'no warning' );

      reset_host( $cfg => "token: t\nnode-ip: 10.230.30.50,fd00:30::50\n" );
      ok( eval { install( $dist, $role ); 1 }, 'a comma string there: installs' ) or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, [ '10.230.30.50', 'fd00:30::50' ], 'kept, as a list' );

      reset_host( $cfg => $earlier );
      ok( eval { install( $dist, $role, node_ip => ['10.230.30.50'] ); 1 }, 'the same given: installs' )
        or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, ['10.230.30.50'], 'written' );
      is_deeply( [ node_warnings() ], [], 'no warning' );
    };

    subtest "$dist $role: a re-run that changes it warns" => sub {
      reset_host( $cfg => $earlier );
      ok( eval { install( $dist, $role, node_ip => '10.230.30.99' ); 1 }, 'another node_ip: installs' )
        or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, ['10.230.30.99'], 'the given one is written' );
      is_deeply( config_of($dist)->{'node-external-ip'}, ['203.0.113.7'], 'the other one is still kept' );
      is_deeply( [ node_warnings() ],
        [ "node-ip changes from 10.230.30.50 to 10.230.30.99 in $cfg: a node that already registered "
          . "takes it when $service restarts. With Cilium, restart its agent pod on this node then "
          . "as well, or its CiliumNode keeps the old address" ],
        'one warning: both values, the restart, the Cilium agent pod' );

      # The synapse case: a node that joined on its default route's address.
      reset_host( $cfg => "token: t\n" );
      ok( eval { install( $dist, $role, node_ip => '10.230.30.50' ); 1 }, 'set where there was none: installs' )
        or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, ['10.230.30.50'], 'written' );
      is( scalar( my @w = node_warnings() ), 1, 'one warning' );
      like( $w[0] // '', qr/\Anode-ip changes from none to 10\.230\.30\.50 in \Q$cfg\E: /, '  from none' );

      reset_host( $cfg => $earlier );
      ok( eval { install( $dist, $role, node_external_ip => '198.51.100.1' ); 1 },
        'another node_external_ip: installs' ) or diag $@;
      like( join( "\n", node_warnings() ), qr/\Anode-external-ip changes from 203\.0\.113\.7 to 198\.51\.100\.1 /,
        'warns for node-external-ip as well' );
    };
  }
}

# ---- a config.yaml that cannot be read as one --------------------------------

for my $dist (qw( rke2 k3s )) {
  subtest "$dist: config.yaml unreadable as YAML keeps nothing, and says so" => sub {
    my $d   = $D->new_for($dist);
    my $cfg = $d->config_file;
    my $secret = 'K10deadbeef::server:s3cr3t';

    reset_host( $cfg => "token: $secret\nnode-ip: [10.230.30.50\n" );
    my %got = $d->node_addresses;
    is_deeply( \%got, { node_ip => undef, node_external_ip => undef }, 'unparsable: nothing kept' );
    my @w = logged('warn');
    is( scalar @w, 1, 'one warning' );
    like( $w[0] // '', qr/\ACould not parse \Q$cfg\E as YAML.*, so a node-ip or node-external-ip in it is not kept: pass node_ip or node_external_ip to keep one\z/,
      '  names the file and the way out' );
    unlike( $w[0] // '', qr/s3cr3t|10\.230/, '  and none of its content: it holds the token' );

    reset_host( $cfg => "token: $secret\nnode-ip: [10.230.30.50\n" );
    %got = $d->node_addresses( node_ip => ['10.230.30.99'] );
    is_deeply( $got{node_ip}, ['10.230.30.99'], 'given: the given one' );
    is( scalar( () = logged('warn') ), 1, '  and only the parse warning' );

    reset_host( $cfg => "- a\n- b\n" );
    %got = $d->node_addresses;
    is_deeply( \%got, { node_ip => undef, node_external_ip => undef }, 'not a mapping: nothing kept' );
    like( join( '', logged('warn') ), qr/\A\Q$cfg\E is not a YAML mapping, so /, '  says so' );

    reset_host( $cfg => "token: t\nnode-ip:\n  a: b\nnode-external-ip: 203.0.113.7\n" );
    %got = $d->node_addresses;
    is( $got{node_ip}, undef, 'node-ip a mapping: not kept' );
    is_deeply( $got{node_external_ip}, ['203.0.113.7'], '  node-external-ip still is' );
    is_deeply( [ logged('warn') ], [ "$cfg: node-ip is neither a string nor a list of strings, so it is not kept" ],
      '  says so' );

    reset_host( $cfg => '' );
    %got = $d->node_addresses;
    is_deeply( \%got, { node_ip => undef, node_external_ip => undef }, 'an empty config.yaml: nothing' );
    is_deeply( [ logged('warn') ], [], '  and no warning' );
  };
}

is_deeply( \@perl_warnings, [], 'no Perl warnings' );

done_testing;
