#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# node_ip_from_route (k111, kubernetes-ocp k254): for a join -- an agent, or a
# server with `server` -- the node-ip is the source address the host uses to
# reach the join server, asked on the host: `ip -o route get ADDRESS`, a host
# name resolved there first with `getent ahosts NAME`. Opt-in.
#
# - The host of the join URL is parsed before the host is touched; anything
#   but an IPv4 address, an IPv6 address in brackets or an RFC 1123 name dies
#   there, and what goes on the host's command line is only what passed.
# - One family: the server address's. A name with A and AAAA takes its IPv4
#   address, one with AAAA only its IPv6 address.
# - Whatever cannot be answered (no resolution, no route, no src, a src of
#   the other family, loopback or unspecified) leaves node-ip out with a
#   warning, never a guess; config.yaml's node-ip is then kept as without
#   node_ip (node_addresses, k100).
# - The derived address counts as given: preflight_* return it as node_ip,
#   install_* write it, a change against config.yaml warns as one given does.
# - node_ip given wins, no route is asked. A first server (no `server`)
#   derives nothing, with an info line, and does not die.
# - Without the option nothing changes: config.yaml as before, no command.
#
# run, file and the logger are faked; the `ip` and `getent` output below is
# what iproute2 and glibc print, typed in. This proves the parse, the command
# lines and the decisions, not what a real host's routing table answers --
# only a live run does.
# -----------------------------------------------------------------------------

use YAML::PP;
use Rex::Rancher;
use Rex::Rancher::Agent;
use Rex::Rancher::Server;
use Rex::Rancher::Distribution;
use Rex::Rancher::Options;

my $D = 'Rex::Rancher::Distribution';

my @perl_warnings;
$SIG{__WARN__} = sub { push @perl_warnings, @_ };

# A fresh host. %files: what `cat 'PATH' 2>/dev/null` finds. %getent: NAME =>
# what `getent ahosts 'NAME'` prints (not there: exit 2, nothing). %route:
# ADDRESS => [ output, exit ] of `ip -o route get 'ADDRESS' 2>&1` (not there:
# the kernel has no route).
my ( @log, @msg, %written, %files, %getent, %route );
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
    if ( $cmd =~ m{^getent ahosts '([^']*)'\z} ) {
      return $getent{$1} if exists $getent{$1};
      $? = 2 << 8;
      return '';
    }
    if ( $cmd =~ m{^ip -o route get '([^']*)' 2>&1\z} ) {
      my ( $out, $exit ) = @{ $route{$1} // [ "RTNETLINK answers: Network is unreachable\n", 2 ] };
      $? = ( $exit // 0 ) << 8;
      return $out;
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
  my $file = sub { my ( $p, %o ) = @_; push @log, "file $p"; $written{$p} = $o{content} if exists $o{content} };
  *Rex::Commands::File::file  = $file;
  *Rex::Rancher::Server::file = $file;
  *Rex::Commands::File::get_tmp_file_name = sub { '/tmp/.rex.tmp' };
  *Rex::Logger::info = sub { push @msg, [ $_[0], $_[1] // 'info' ] };
}

sub reset_host { @log = (); @msg = (); %written = (); %getent = (); %route = (); %files = @_ }
sub logged     { my ( $level ) = @_; map { $_->[0] } grep { $_->[1] eq $level } @msg }
sub route_cmds { grep { /^(?:getent|ip) / } @log }
sub route_lines { my ( $level ) = @_; grep { /node_ip_from_route/ } logged($level) }
sub node_warnings { grep { /node-(?:external-)?ip/ } logged('warn') }

my %PORT = ( rke2 => 9345, k3s => 6443 );

sub install {
  my ( $dist, $role, %opts ) = @_;
  return $role eq 'agent'
    ? Rex::Rancher::Agent::install_agent( distribution => $dist, token => 't', %opts )
    : Rex::Rancher::Server::install_server( distribution => $dist, token => 't', cilium => 0, %opts );
}

sub preflight {
  my ( $dist, $role, %opts ) = @_;
  return $role eq 'agent'
    ? Rex::Rancher::Agent::preflight_agent( distribution => $dist, %opts )
    : Rex::Rancher::Server::preflight_server( distribution => $dist, cilium => 0, %opts );
}

sub config_of {
  my ( $dist ) = @_;
  my $text = $written{"/etc/rancher/$dist/config.yaml"};
  return defined $text ? YAML::PP->new->load_string($text) : undef;
}

# What iproute2 prints: IPv4 with -o (the cache line joined by a backslash),
# IPv6 with its `from ::`, which is not the source address.
my $V4_ROUTE = "10.230.30.52 dev vlan30 src 10.230.30.50 uid 0 \\    cache \n";
my $V6_ROUTE = "fd00:30::52 from :: dev vlan30 proto kernel src fd00:30::50 metric 256 pref medium\n";
# What glibc's getent prints for a name with AAAA and A, AAAA sorted first.
my $GETENT_BOTH = join '', map { "$_\n" }
  'fd00:30::52     STREAM cp.example', 'fd00:30::52     DGRAM  ', 'fd00:30::52     RAW    ',
  '10.230.30.52    STREAM ',           '10.230.30.52    DGRAM  ', '10.230.30.52    RAW    ';
my $GETENT_V6 = "fd00:30::52     STREAM cp6.example\nfd00:30::52     DGRAM  \nfd00:30::52     RAW    \n";

sub not_derived {
  my ( $dist ) = @_;
  return "node-ip is not derived: a node-ip in /etc/rancher/$dist/config.yaml is kept, else "
    . "$dist advertises the address of its default route. Pass node_ip to set one";
}

# A method missing from the lib under test fails the assertion it is in,
# not the whole file.
sub try_call { my ( $code ) = @_; my $r = eval { $code->() }; diag "died: $@" if $@; return $r }
my $from_route = sub { my ( $d, @a ) = @_; try_call( sub { $d->node_ip_from_route(@a) } ) };
my $route_host = sub { my ( $d, @a ) = @_; try_call( sub { $d->node_ip_route_host(@a) } ) };

# ---- the join URL ------------------------------------------------------------

subtest 'join_server_host: the host of the join URL, or a die before the host is touched' => sub {
  my $host = sub { Rex::Rancher::Options->join_server_host(@_) };
  my @ok = (
    [ 'https://10.230.30.52:9345'      => '10.230.30.52' ],
    [ 'https://10.230.30.52'           => '10.230.30.52' ],
    [ 'https://10.230.30.52:6443/'     => '10.230.30.52' ],
    [ 'https://[fd00::1]:9345'         => 'fd00::1' ],
    [ 'https://[fd00::1]'              => 'fd00::1' ],
    [ 'https://[2001:db8::10]:6443/'   => '2001:db8::10' ],
    [ 'https://cp.example:9345'        => 'cp.example' ],
    [ 'https://cp.example'             => 'cp.example' ],
    [ 'https://cp.example.:9345'       => 'cp.example.' ],
    [ 'https://cp:9345'                => 'cp' ],
    [ 'HTTPS://CP-1.Example:9345'      => 'CP-1.Example' ],
    [ 'https://1cp.example:9345'       => '1cp.example' ],
  );
  for my $case (@ok) {
    my ( $url, $want ) = @{$case};
    my $got = try_call( sub { $host->($url) } );
    is( $got, $want, "$url => $want" );
    like( $got // '', qr/\A[A-Za-z0-9.:-]+\z/, '  nothing the shell would act on' );
  }

  my $want = qr/\Anode_ip_from_route needs server as https:\/\/HOST or https:\/\/HOST:PORT, HOST an IPv4 address, an IPv6 address in brackets or a host name, got /;
  my @bad = (
    [ undef,                              'nothing' ],
    [ { url => 'https://cp:9345' },       'a HASH reference' ],
    [ [ 'https://cp:9345' ],              'a ARRAY reference' ],
    [ '',                                 "''" ],
    [ 'cp.example:9345',                  'no scheme' ],
    [ '10.230.30.52',                     'a bare address' ],
    [ 'http://10.230.30.52:9345',         'http' ],
    [ 'https://fd00::1:9345',             'IPv6 without brackets' ],
    [ 'https://[fd00::1%eth0]:9345',      'an IPv6 zone' ],
    [ 'https://[10.230.30.52]:9345',      'IPv4 in brackets' ],
    [ 'https://[cp.example]:9345',        'a name in brackets' ],
    [ 'https://cp:0',                     'port 0' ],
    [ 'https://cp:65536',                 'port 65536' ],
    [ 'https://cp:',                      'an empty port' ],
    [ 'https://cp:93a5',                  'a port that is no number' ],
    [ 'https://user@cp:9345',             'a user' ],
    [ 'https://cp:9345/path',             'a path' ],
    [ 'https://cp?x=1',                   'a query' ],
    [ 'https://10.0.0.256:9345',          'digits and dots that are no IPv4 address' ],
    [ 'https://10.0.0:9345',              'three parts' ],
    [ 'https://-cp:9345',                 'a leading hyphen (an option to getent)' ],
    [ 'https://cp-.example:9345',         'a trailing hyphen in a label' ],
    [ 'https://cp_1:9345',                'an underscore' ],
    [ 'https://cp..example:9345',         'an empty label' ],
    [ 'https://' . ( 'a' x 64 ) . ':9345', 'a label of 64' ],
    [ 'https://' . join( '.', ('abcdefghi') x 26 ),  'a name of 259' ],
    [ 'https://cp example:9345',          'a space' ],
    [ "https://cp\n:9345",                'a newline' ],
    [ "https://cp.example:9345\n",        'a trailing newline' ],
    [ 'https://cp;reboot:9345',           'a ;' ],
    [ 'https://$(reboot):9345',           'a $(...)' ],
    [ 'https://`reboot`:9345',            'backticks' ],
    [ "https://cp'x:9345",                'a single quote' ],
    [ 'https://cp*:9345',                 'a glob' ],
    [ 'https://cp|reboot:9345',           'a pipe' ],
  );
  for my $case (@bad) {
    my ( $value, $why ) = @{$case};
    ok( !eval { $host->($value); 1 }, "dies: $why" );
    like( $@, $want, '  naming the option and the forms it takes' );
    like( $@, ref $value ? qr/got a \Q${\ ref $value}\E reference\n\z/
      : defined $value ? qr/got '\Q$value\E'\n\z/ : qr/got nothing\n\z/, '  and what it got' );
  }
  my $long = join '.', ('abcdefghi') x 25;    # 249 characters
  is( try_call( sub { $host->("https://$long:9345") } ), $long, 'a name of 249 is fine' );
};

# ---- the host's answer -------------------------------------------------------

subtest 'node_ip_from_route: the command lines and their output' => sub {
  my $d = $D->new_for('rke2');

  reset_host();
  $route{'10.230.30.52'} = [$V4_ROUTE];
  is_deeply( $from_route->( $d, '10.230.30.52' ), ['10.230.30.50'], 'IPv4: the src' );
  is_deeply( \@log, ["ip -o route get '10.230.30.52' 2>&1"], '  one command, no resolution for an address' );
  is_deeply( [ route_lines('info') ],
    ['node_ip_from_route: node-ip 10.230.30.50, the source address of the route to 10.230.30.52'],
    '  logged' );
  is_deeply( [ logged('warn') ], [], '  no warning' );

  reset_host();
  $route{'fd00:30::52'} = [$V6_ROUTE];
  is_deeply( $from_route->( $d, 'fd00:30::52' ), ['fd00:30::50'], 'IPv6: the src, not the `from ::`' );
  is_deeply( \@log, ["ip -o route get 'fd00:30::52' 2>&1"], '  the address as it is, quoted' );

  reset_host();
  $route{'10.230.30.52'} = ["10.230.30.52 via 192.168.0.1 dev eno1 table 100 src 192.168.0.165 uid 0 \\    cache \n"];
  is_deeply( $from_route->( $d, '10.230.30.52' ), ['192.168.0.165'],
    'a route via a gateway, policy routing: its src, whatever the interface' );

  reset_host();
  $getent{'cp.example'} = $GETENT_BOTH;
  $route{'10.230.30.52'} = [$V4_ROUTE];
  is_deeply( $from_route->( $d, 'cp.example' ), ['10.230.30.50'],
    'a name with AAAA and A: its IPv4 address, though getent lists the IPv6 one first' );
  is_deeply( \@log, [ "getent ahosts 'cp.example'", "ip -o route get '10.230.30.52' 2>&1" ],
    '  resolved on the host, then its route' );
  is_deeply( [ route_lines('info') ],
    ['node_ip_from_route: node-ip 10.230.30.50, the source address of the route to 10.230.30.52 (cp.example)'],
    '  the name in the log line' );

  reset_host();
  $getent{'cp6.example'} = $GETENT_V6;
  $route{'fd00:30::52'} = [$V6_ROUTE];
  is_deeply( $from_route->( $d, 'cp6.example' ), ['fd00:30::50'], 'a name with AAAA only: its IPv6 address' );
  is_deeply( \@log, [ "getent ahosts 'cp6.example'", "ip -o route get 'fd00:30::52' 2>&1" ], '  and its route' );

  my $not = not_derived('rke2');
  my @fail = (
    [ 'a name that does not resolve', sub { }, 'cp.example',
      "node_ip_from_route: cp.example does not resolve to an IPv4 or IPv6 address on the host (getent ahosts), so $not",
      ["getent ahosts 'cp.example'"] ],
    [ 'getent printing no address', sub { $getent{'cp.example'} = "garbage STREAM cp.example\n" }, 'cp.example',
      "node_ip_from_route: cp.example does not resolve to an IPv4 or IPv6 address on the host (getent ahosts), so $not",
      ["getent ahosts 'cp.example'"] ],
    [ 'no route', sub { }, '10.230.30.52',
      "node_ip_from_route: ip -o route get 10.230.30.52 failed on the host (RTNETLINK answers: Network is unreachable), so $not",
      ["ip -o route get '10.230.30.52' 2>&1"] ],
    [ 'ip failing without a word', sub { $route{'10.230.30.52'} = [ '', 127 ] }, '10.230.30.52',
      "node_ip_from_route: ip -o route get 10.230.30.52 failed on the host, so $not",
      ["ip -o route get '10.230.30.52' 2>&1"] ],
    [ 'a route without src', sub { $route{'10.230.30.52'} = ["10.230.30.52 dev vlan30 uid 0 \\    cache \n"] },
      '10.230.30.52',
      "node_ip_from_route: the route to 10.230.30.52 names no source address (10.230.30.52 dev vlan30 uid 0 \\    cache), so $not",
      ["ip -o route get '10.230.30.52' 2>&1"] ],
    [ 'a src of the other family', sub { $route{'10.230.30.52'} = ["10.230.30.52 dev vlan30 src fd00:30::50 uid 0\n"] },
      '10.230.30.52',
      "node_ip_from_route: the route to 10.230.30.52 has the source address fd00:30::50, not an IPv4 address a node can advertise, so $not",
      ["ip -o route get '10.230.30.52' 2>&1"] ],
    [ 'a src that is no address', sub { $route{'fd00:30::52'} = ["fd00:30::52 dev vlan30 src eth0\n"] },
      'fd00:30::52',
      "node_ip_from_route: the route to fd00:30::52 has the source address eth0, not an IPv6 address a node can advertise, so $not",
      ["ip -o route get 'fd00:30::52' 2>&1"] ],
    [ 'IPv4 loopback (a server reached through a local tunnel)',
      sub { $route{'127.0.0.1'} = ["local 127.0.0.1 dev lo table local src 127.0.0.1 uid 0 \\    cache <local> \n"] },
      '127.0.0.1',
      "node_ip_from_route: the route to 127.0.0.1 has the source address 127.0.0.1, not an IPv4 address a node can advertise, so $not",
      ["ip -o route get '127.0.0.1' 2>&1"] ],
    [ 'IPv6 loopback', sub { $route{'::1'} = ["local ::1 dev lo table local proto kernel src ::1 metric 0 pref medium\n"] },
      '::1',
      "node_ip_from_route: the route to ::1 has the source address ::1, not an IPv6 address a node can advertise, so $not",
      ["ip -o route get '::1' 2>&1"] ],
    [ 'unspecified', sub { $route{'10.230.30.52'} = ["10.230.30.52 dev vlan30 src 0.0.0.0 uid 0\n"] },
      '10.230.30.52',
      "node_ip_from_route: the route to 10.230.30.52 has the source address 0.0.0.0, not an IPv4 address a node can advertise, so $not",
      ["ip -o route get '10.230.30.52' 2>&1"] ],
  );
  for my $case (@fail) {
    my ( $name, $setup, $host, $warning, $cmds ) = @{$case};
    reset_host();
    $setup->();
    is( $from_route->( $d, $host ), undef, "$name: no node-ip" );
    is_deeply( [ logged('warn') ], [$warning], '  one warning: what failed, and what happens instead' );
    is_deeply( \@log, $cmds, '  the commands asked' );
    is_deeply( [ route_lines('info') ], [], '  no address logged' );
  }
};

subtest 'node_ip_route_host: off, node_ip given, no server' => sub {
  my $d = $D->new_for('k3s');
  reset_host();
  is( $route_host->( $d, server => 'https://10.230.30.52:6443' ), undef, 'off: nothing' );
  is( $route_host->( $d, node_ip_from_route => 0, server => 'https://cp;reboot:6443' ), undef,
    '  and no parse of server' );
  is_deeply( \@msg, [], '  not a word' );

  is( $route_host->( $d, node_ip_from_route => 1, node_ip => ['10.230.30.99'],
    server => 'https://cp;reboot:6443' ), undef, 'node_ip given: nothing, server not parsed' );
  is_deeply( [ logged('info') ], ['node_ip 10.230.30.99 is given, so node_ip_from_route asks no route'],
    '  one info line' );

  reset_host();
  is( $route_host->( $d, node_ip_from_route => 1 ), undef, 'no server: nothing' );
  is_deeply( [ logged('info') ],
    [ 'node_ip_from_route: no server to join, so no route to one; ' . not_derived('k3s') ], '  one info line' );
  is_deeply( [ logged('warn') ], [], '  no warning' );

  reset_host();
  is( $route_host->( $d, node_ip_from_route => 1, server => 'https://[fd00::1]:6443' ), 'fd00::1',
    'on, with server: its host' );
  is_deeply( \@log, [], 'no command for any of it' );
};

# ---- install and preflight, server and agent, rke2 and k3s -------------------

for my $dist (qw( rke2 k3s )) {
  my $cfg  = "/etc/rancher/$dist/config.yaml";
  my $join = "https://10.230.30.52:$PORT{$dist}";
  for my $role (qw( agent server )) {
    my $name = "$dist $role" . ( $role eq 'server' ? ' joining' : '' );

    subtest "$name: the derived node-ip goes to config.yaml" => sub {
      reset_host();
      $route{'10.230.30.52'} = [$V4_ROUTE];
      ok( eval { install( $dist, $role, server => $join, node_ip_from_route => 1 ); 1 }, 'installs' ) or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, ['10.230.30.50'], 'node-ip: the src of the route to the server' );
      like( $written{$cfg}, qr/^node-ip:\n- 10\.230\.30\.50\n/m, '  a YAML list, as a given node_ip' );
      ok( !exists config_of($dist)->{'node-external-ip'}, '  node-external-ip untouched' );
      is( config_of($dist)->{server}, $join, '  server as given' );
      is_deeply( [ route_cmds() ], [ ("ip -o route get '10.230.30.52' 2>&1") x 1 ],
        '  the route asked once, by install_*\'s own preflight' );
      is_deeply( [ node_warnings() ], [], '  a fresh node: no warning' );

      reset_host();
      $route{'fd00:30::52'} = [$V6_ROUTE];
      ok( eval { install( $dist, $role, server => "https://[fd00:30::52]:$PORT{$dist}", node_ip_from_route => 1 ); 1 },
        'an IPv6 server: installs' ) or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, ['fd00:30::50'], '  node-ip: IPv6, one family' );

      reset_host();
      $getent{'cp.example'} = $GETENT_BOTH;
      $route{'10.230.30.52'} = [$V4_ROUTE];
      ok( eval { install( $dist, $role, server => "https://cp.example:$PORT{$dist}", node_ip_from_route => 1 ); 1 },
        'a server by name: installs' ) or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, ['10.230.30.50'], '  node-ip: from its IPv4 address' );
      is_deeply( [ route_cmds() ], [ "getent ahosts 'cp.example'", "ip -o route get '10.230.30.52' 2>&1" ],
        '  resolved on the host' );
    };

    subtest "$name: preflight returns what install writes, and only reads" => sub {
      reset_host();
      $route{'10.230.30.52'} = [$V4_ROUTE];
      my $checked = eval { preflight( $dist, $role, server => $join, node_ip_from_route => 1 ) };
      ok( $checked, 'preflight passes' ) or diag $@;
      is_deeply( $checked->{node_ip}, ['10.230.30.50'], 'node_ip: the derived address' );
      is( $checked->{node_external_ip}, undef, 'node_external_ip: none' );
      is( $log[-1], "ip -o route get '10.230.30.52' 2>&1", 'the route is the last thing read' );
      is_deeply( [ grep { /^file |^mkdir |\| *sh|^systemctl (?:enable|start|restart)/ } @log ], [],
        'nothing written, installed or started' );
      is_deeply( [ keys %written ], [], '  no file' );
    };

    subtest "$name: what cannot be derived is left out, with a warning" => sub {
      reset_host();
      ok( eval { install( $dist, $role, server => $join, node_ip_from_route => 1 ); 1 }, 'no route: installs' )
        or diag $@;
      ok( !exists config_of($dist)->{'node-ip'}, 'no node-ip in config.yaml' );
      is_deeply( [ logged('warn') ],
        [ "node_ip_from_route: ip -o route get 10.230.30.52 failed on the host (RTNETLINK answers: "
          . "Network is unreachable), so " . not_derived($dist) ],
        'one warning' );

      # The case the card is about, the other way round: the node was set up
      # on its cluster address, and today's route cannot be read.
      reset_host( $cfg => "token: t\nnode-ip:\n- 10.230.30.50\n" );
      ok( eval { install( $dist, $role, server => $join, node_ip_from_route => 1 ); 1 },
        'no route, config.yaml with a node-ip: installs' ) or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, ['10.230.30.50'], 'the node-ip config.yaml holds is kept' );
      ok( ( grep { $_ eq "Keeping node-ip 10.230.30.50 from $cfg (node_ip not given)" } logged('info') ),
        '  says so, as without node_ip' );
      is( scalar( () = route_lines('warn') ), 1, '  next to the warning' );
    };

    subtest "$name: a derived node-ip counts as given against config.yaml" => sub {
      reset_host( $cfg => "token: t\nnode-ip:\n- 10.230.30.50\n" );
      $route{'10.230.30.52'} = [$V4_ROUTE];
      ok( eval { install( $dist, $role, server => $join, node_ip_from_route => 1 ); 1 }, 'the same: installs' )
        or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, ['10.230.30.50'], 'written' );
      is_deeply( [ node_warnings() ], [], 'no warning' );

      # synapse: joined on its default route's address, the fix on its rejoin.
      reset_host( $cfg => "token: t\nnode-ip: 192.168.0.165\n" );
      $route{'10.230.30.52'} = [$V4_ROUTE];
      ok( eval { install( $dist, $role, server => $join, node_ip_from_route => 1 ); 1 }, 'another: installs' )
        or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, ['10.230.30.50'], 'the derived one is written' );
      my @w = node_warnings();
      is( scalar @w, 1, 'one warning' );
      like( $w[0] // '', qr/\Anode-ip changes from 192\.168\.0\.165 to 10\.230\.30\.50 in \Q$cfg\E: /,
        '  node_addresses\' warning, naming both' );
    };

    subtest "$name: node_ip given wins" => sub {
      reset_host();
      $route{'10.230.30.52'} = [$V4_ROUTE];
      ok( eval { install( $dist, $role, server => $join, node_ip => '10.230.30.99', node_ip_from_route => 1 ); 1 },
        'installs' ) or diag $@;
      is_deeply( config_of($dist)->{'node-ip'}, ['10.230.30.99'], 'node-ip: the given one' );
      is_deeply( [ route_cmds() ], [], 'no route asked' );
      is_deeply( [ route_lines('info') ], ['node_ip 10.230.30.99 is given, so node_ip_from_route asks no route'],
        'one info line' );
      is_deeply( [ route_lines('warn') ], [], 'no warning' );
    };

    subtest "$name: a server URL it cannot read dies before the host is touched" => sub {
      for my $bad ( "https://cp;reboot:$PORT{$dist}", "cp:$PORT{$dist}", "https://fd00::1:$PORT{$dist}" ) {
        reset_host();
        ok( !eval { install( $dist, $role, server => $bad, node_ip_from_route => 1 ); 1 }, "'$bad': dies" );
        like( $@, qr/\Anode_ip_from_route needs server as https:\/\/HOST/, '  naming the option' );
        is_deeply( \@log, [], '  before any command ran on the host' );
      }
    };
  }

  subtest "$dist first server: no server, nothing derived, no die" => sub {
    reset_host();
    $route{'10.230.30.52'} = [$V4_ROUTE];
    ok( eval { install( $dist, 'server', node_ip_from_route => 1 ); 1 }, 'installs' ) or diag $@;
    ok( !exists config_of($dist)->{'node-ip'}, 'no node-ip' );
    ok( !exists config_of($dist)->{server}, 'no server' );
    is_deeply( [ route_cmds() ], [], 'no route asked' );
    is_deeply( [ route_lines('info') ],
      [ 'node_ip_from_route: no server to join, so no route to one; ' . not_derived($dist) ], 'one info line' );
    is_deeply( [ logged('warn') ], [], 'no warning' );

    reset_host( $cfg => "token: t\nnode-ip:\n- 10.230.30.52\n" );
    ok( eval { install( $dist, 'server', node_ip_from_route => 1 ); 1 }, 'a re-run: installs' ) or diag $@;
    is_deeply( config_of($dist)->{'node-ip'}, ['10.230.30.52'], 'config.yaml\'s node-ip kept' );
  };
}

# ---- without the option, nothing changes -------------------------------------

my %GOLDEN = (
  'rke2 agent' => "---\nnode-name: w1\nserver: https://10.230.30.52:9345\ntoken: t\n",
  'k3s agent'  => "---\nnode-name: w1\nserver: https://10.230.30.52:6443\ntoken: t\n",
  'rke2 server' => "---\ncni: none\ndisable:\n- rke2-ingress-nginx\n- rke2-traefik\n- rke2-traefik-crd\n"
    . "disable-kube-proxy: true\nserver: https://10.230.30.52:9345\ntls-san:\n- cp.example\ntoken: t\n",
  'k3s server' => "---\ncluster-cidr: 10.42.0.0/16\ndisable:\n- traefik\n- servicelb\ndisable-kube-proxy: true\n"
    . "disable-network-policy: true\nflannel-backend: none\nserver: https://10.230.30.52:6443\ntls-san:\n"
    . "- cp.example\ntoken: t\n",
);

for my $dist (qw( rke2 k3s )) {
  my $cfg  = "/etc/rancher/$dist/config.yaml";
  my $join = "https://10.230.30.52:$PORT{$dist}";
  for my $role (qw( agent server )) {
    subtest "$dist $role: without node_ip_from_route config.yaml is as before" => sub {
      my %opts = ( server => $join,
        $role eq 'agent' ? ( node_name => 'w1' ) : ( tls_san => ['cp.example'], cilium => 1 ) );
      my %seen;
      for my $flag ( [ 'left out' ], [ '=> 0', node_ip_from_route => 0 ], [ '=> undef', node_ip_from_route => undef ] ) {
        my ( $how, @flag ) = @{$flag};
        reset_host();
        $route{'10.230.30.52'} = [$V4_ROUTE];
        ok( eval { install( $dist, $role, %opts, @flag ); 1 }, "node_ip_from_route $how: installs" ) or diag $@;
        is( $written{$cfg}, $GOLDEN{"$dist $role"}, '  config.yaml, line for line, as it was written before' );
        is_deeply( [ route_cmds() ], [], '  no route asked' );
        is_deeply( [ grep { /node_ip_from_route/ } map { $_->[0] } @msg ], [], '  and not a word about it' );
        $seen{ join "\n", @log } = 1;
      }
      is( scalar keys %seen, 1, 'the same commands on the host, flag or not' );
    };
  }
}

# ---- rancher_deploy_* hand it on ---------------------------------------------

subtest 'rancher_deploy_agent and rancher_deploy_server hand it to preflight and install' => sub {
  my %got;
  no warnings 'redefine';
  local *Rex::Rancher::_check_connection       = sub { };
  local *Rex::Rancher::prepare_node            = sub { };
  local *Rex::Rancher::_gpu_setup_if_requested = sub { };
  local *Rex::Rancher::install_agent           = sub { %got = @_ };
  local *Rex::Rancher::install_server          = sub { %got = @_ };

  reset_host();
  $route{'10.230.30.52'} = [$V4_ROUTE];
  ok( eval { Rex::Rancher::rancher_deploy_agent( server => 'https://10.230.30.52:9345', token => 't',
    node_ip_from_route => 1 ); 1 }, 'agent deploys' ) or diag $@;
  is( $got{node_ip_from_route}, 1, '  install_agent gets the option' );
  is_deeply( [ route_cmds() ], ["ip -o route get '10.230.30.52' 2>&1"], '  preflight_agent asked the route' );

  %got = ();
  reset_host();
  $route{'10.230.30.52'} = [$V4_ROUTE];
  ok( eval { Rex::Rancher::rancher_deploy_server( server => 'https://10.230.30.52:9345', token => 't',
    cilium => 0, node_ip_from_route => 1 ); 1 }, 'joining server deploys' ) or diag $@;
  is( $got{node_ip_from_route}, 1, '  install_server gets the option' );
  is_deeply( [ route_cmds() ], ["ip -o route get '10.230.30.52' 2>&1"], '  preflight_server asked the route' );

  reset_host();
  ok( !eval { Rex::Rancher::rancher_deploy_agent( server => 'https://cp;reboot:9345', token => 't',
    node_ip_from_route => 1 ); 1 }, 'a server URL it cannot read: dies' );
  like( $@, qr/\Anode_ip_from_route needs server/, '  in preflight_agent' );
  is_deeply( \@log, [], '  before any command ran on the host' );
};

is_deeply( \@perl_warnings, [], 'no Perl warnings' );

done_testing;
