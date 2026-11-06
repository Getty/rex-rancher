#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# k97 (from kubernetes-ocp k248): check_cilium_residue only offered a reboot.
# On a host that runs other services, the residue came out without one, after
# which a new RKE2 with Cilium came up cleanly: the pins in /sys/fs/bpf/cilium
# removed, the remaining cil_* programs detached from the cgroups with
# bpftool, the maps in /sys/fs/bpf/tc/globals/cilium_* removed, the
# /run/cilium/cgroupv2 mount and /run/cilium gone.
#
# The claims:
#   1. cilium_residue_cleanup_cmd is one /bin/sh -c word: the probe's own
#      guard (no distribution on the host), then exactly those four steps in
#      that order, and nothing the uninstall removes besides;
#   2. under /bin/sh -e against stubs: with a distribution on the host
#      nothing runs; without one the steps run, only cil_* programs are
#      detached, each from the cgroup bpftool lists it under, with the attach
#      type as bpftool printed it; no bpftool, or programs still listed after
#      the detach, is a marked warning; the line exits 0 whatever it found,
#      every step failing included, and on a clean host it detaches nothing,
#      warns nothing and does the same the second time;
#   3. check_cilium_residue without clean (or with clean => 0) dies as
#      before, its message now naming the call that clears the state as the
#      alternative to the reboot -- a call that does take the cleanup path --
#      and nothing but the probe runs;
#   4. with clean => 1: on a clean host (or one with a distribution) nothing
#      runs but the probe, twice alike; on a host with residue the line runs,
#      its warnings are logged, the probe runs again and decides: clean
#      returns 1, residue left dies naming it and asking for a reboot (not
#      for the cleanup again), a probe that cannot run then dies as well.
#
# Not claimed: that bpftool prints `cgroup tree` exactly as the stub here
# does (taken from bpftool's source, not from a host), nor that a real host
# is clean afterwards -- both are for a live run on a test host.
# -----------------------------------------------------------------------------

use File::Temp qw( tempdir );
use Rex::Rancher::Uninstall ();

my $U = 'Rex::Rancher::Uninstall';

my @perl_warnings;
$SIG{__WARN__} = sub { push @perl_warnings, @_ };

my $LINE  = $U->can('cilium_residue_cleanup_cmd') ? $U->cilium_residue_cleanup_cmd : undef;
my $PROBE = $U->cilium_residue_probe_cmd;

my $MARK = 'rex-rancher-uninstall-warning: ';
my $NO_BPFTOOL = 'bpftool is not installed: Cilium programs (cil_*) left on the cgroups below'
  . ' /sys/fs/cgroup were not checked or detached; a reboot clears them';
my $STILL_LISTED = 'bpftool still lists Cilium programs (cil_*) on the cgroups below /sys/fs/cgroup'
  . ' after detaching them; a reboot clears them';

# ---- 1. the line ----------------------------------------------------------------

ok( defined $LINE, 'cilium_residue_cleanup_cmd: a pure line for a caller with its own channel' );

subtest 'the line: the guard, then the four steps, in order' => sub {
  plan skip_all => 'no cleanup line' unless defined $LINE;
  my $line = $LINE;
  my @steps = (
    [ 'one /bin/sh -c command, the guard first: no distribution binary on PATH, no unit active' =>
      "/bin/sh -c 'if command -v rke2 >/dev/null 2>&1 || command -v k3s >/dev/null 2>&1"
      . ' || systemctl is-active --quiet rke2-server rke2-agent.service k3s k3s-agent.service 2>/dev/null;'
      . ' then :; else ' ],
    [ '1. the pin dir' => 'rm -rf /sys/fs/bpf/cilium 2>/dev/null || true ; ' ],
    [ '2. with bpftool there' => 'if command -v bpftool >/dev/null 2>&1; then' ],
    [ '2. ... the cil_* programs the cgroup tree lists' => 'bpftool cgroup tree /sys/fs/cgroup 2>/dev/null' ],
    [ '2. ... each detached from its cgroup, by attach type and id' =>
      'bpftool cgroup detach "$c" "$t" id "$i" 2>/dev/null || true' ],
    [ '2. ... one still listed: a warning that cannot fail the line' =>
      '[ -z "$(cil_progs)" ] || echo "' . $MARK . $STILL_LISTED . '" >&2 || true;' ],
    [ '2. without bpftool: a warning that cannot fail the line' =>
      ' else echo "' . $MARK . $NO_BPFTOOL . '" >&2 || true; fi ; ' ],
    [ '3. the tc globals maps' => 'rm -rf /sys/fs/bpf/tc/globals/cilium_* 2>/dev/null || true ; ' ],
    [ '4. the cgroup2 mount, lazily when busy' =>
      'umount /run/cilium/cgroupv2 2>/dev/null || umount -l /run/cilium/cgroupv2 2>/dev/null || true ; ' ],
    [ '4. then the runtime dir, never into a mount that stayed; the guard closes' =>
      "rm -rf --one-file-system /run/cilium 2>/dev/null || true ; fi'" ],
  );
  my $last = -1;
  for my $s (@steps) {
    my ( $what, $text ) = @$s;
    my $at = index $line, $text;
    ok( $at >= 0, "has: $what" ) or diag "missing: $text";
    ok( $at > $last, '... after the step before' );
    $last = $at if $at >= 0;
  }
  is( index( $line, $steps[0][1] ), 0, 'the guard is the start of the line' );
  ok( substr( $line, -length $steps[-1][1] ) eq $steps[-1][1], 'the closing fi is its end' );
  like( $line, qr{\A/bin/sh -c '[^']*'\z}, 'one single-quoted word: no login shell expands any of it' );
  is( $line, $U->_sh_c( $U->_cilium_residue_cleanup_script ), 'made by the same wrapper as the uninstall line' );
  # The guard is the probe's own: the same test, not a copy that can drift.
  like( $line, qr/\Q'if @{[ $U->_distribution_present_cmd ]}; then :; else \E/, 'the probe\'s distribution test' );
  like( $PROBE, qr/\Aif \Q@{[ $U->_distribution_present_cmd ]}\E; then :; else /, '... as the probe has it' );
  unlike( $line, qr/\bip (?:-6 )?(?:link|rule)\b|\btc (?:qdisc|filter)\b|iptables|uninstall\.sh/,
    'no device, ip rule, tc qdisc, iptables chain or uninstaller: only the four steps' );
  unlike( $line, qr/ \/sys\/fs\/bpf(?:\/?[ ;]|\/tc\/globals\/?[ ;])/, 'never bpffs, nor tc/globals, whole' );
  unlike( $_, qr/["\$`\\']/, 'the warning text is inert inside double quotes' ) for $NO_BPFTOOL, $STILL_LISTED;
};

# ---- 2. the line under /bin/sh -e, against stubs ------------------------------
#
# The line is destructive (rm -rf in bpffs, umount, bpftool detach). It runs
# here only with a PATH of nothing but stubs, and only when both hold: the
# tests do not run as root (a stub that is not picked up cannot do harm), and
# the shell verifiably runs the stub for `rm` instead of a builtin or a
# multi-call applet of its own. It needs no real tool: the rest is builtins.

sub spew {
  my ( $file, $content ) = @_;
  open my $fh, '>', $file or die "$file: $!";
  print {$fh} $content;
  close $fh;
}

sub slurp {
  my ( $file ) = @_;
  open my $fh, '<', $file or return '';
  local $/;
  my $content = <$fh>;
  return $content // '';
}

# A stub: logs "name args" to $STUB_LOG, then runs $body.
sub stub {
  my ( $bin, $name, $body ) = @_;
  spew( "$bin/$name", "#!/bin/sh\necho \"$name \$*\" >> \"\$STUB_LOG\"\n" . $body );
  chmod 0755, "$bin/$name";
}

sub stubs_are_used {
  my $bin = tempdir( CLEANUP => 1 );
  spew( "$bin/rm", "#!/bin/sh\necho stub-rm\n" );
  chmod 0755, "$bin/rm";
  my $out = do {
    local $ENV{PATH} = $bin;
    open my $fh, '-|', '/bin/sh', '-c', 'rm -rf /nonexistent/rex-rancher-canary' or return 0;
    local $/;
    my $o = <$fh>;
    close $fh;
    $o;
  };
  return ( $out // '' ) eq "stub-rm\n";
}

# bpftool: `cgroup tree` prints $STUB_DIR/tree-N on its Nth call, else
# $STUB_DIR/tree-after; `cgroup detach` exits $STUB_DIR/detach-exit (0).
# Builtins only, as the stubs get no PATH of real tools.
my $BPFTOOL = <<'STUB';
case "$1 $2" in
  "cgroup tree")
    n=0; [ -e "$STUB_DIR/trees" ] && read n < "$STUB_DIR/trees"
    n=$((n + 1)); echo $n > "$STUB_DIR/trees"
    f="$STUB_DIR/tree-$n"; [ -e "$f" ] || f="$STUB_DIR/tree-after"
    [ -e "$f" ] && while IFS= read -r l; do printf "%s\n" "$l"; done < "$f"
    exit 0;;
  "cgroup detach")
    e=0; [ -e "$STUB_DIR/detach-exit" ] && read e < "$STUB_DIR/detach-exit"
    exit $e;;
esac
exit 1
STUB

# What `bpftool cgroup tree /sys/fs/cgroup` prints, as its source has it: a
# header, then each cgroup with programs as its path and their lines, ID,
# attach type, attach flags (multi, override or none), name -- indented four
# spaces below the root, not at it. Older bpftools name the attach types
# connect4, sendmsg4 ...; newer ones cgroup_inet4_connect ... Here both, and
# programs that are not Cilium's: systemd's, and a name with cil_ inside it.
my $TREE_HEADER = "CgroupPath\nID       AttachType      AttachFlags     Name           \n";
my $TREE = $TREE_HEADER . <<'TREE';
/sys/fs/cgroup
4211     cgroup_inet4_connect multi           cil_sock4_connect
4215     cgroup_inet6_connect multi           cil_sock6_connect
4220     cgroup_inet_sock_release                 cil_sock_release
4230     sendmsg4                        cil_sock4_sendmsg
51       cgroup_inet_egress multi           sd_fw_egress
/sys/fs/cgroup/system.slice/systemd-udevd.service
    37       cgroup_device   multi           sd_devices
    38       cgroup_device   multi           my_cil_device
/sys/fs/cgroup/kubepods.slice
    4301     connect4                        cil_sock4_conne
TREE

my @DETACHED = (
  'bpftool cgroup detach /sys/fs/cgroup cgroup_inet4_connect id 4211',
  'bpftool cgroup detach /sys/fs/cgroup cgroup_inet6_connect id 4215',
  'bpftool cgroup detach /sys/fs/cgroup cgroup_inet_sock_release id 4220',
  'bpftool cgroup detach /sys/fs/cgroup sendmsg4 id 4230',
  'bpftool cgroup detach /sys/fs/cgroup/kubepods.slice connect4 id 4301',
);

# Runs the line under /bin/sh -e with a PATH of nothing but stubs. %args:
# stubs (name => body), files (name => content, into $STUB_DIR). The -e goes
# to the /bin/sh -c the line names, the one running the steps.
sub run_line {
  my ( %args ) = @_;
  ( my $line = $LINE ) =~ s{\A/bin/sh -c }{/bin/sh -e -c } or die "not a /bin/sh -c line: $LINE\n";
  my $dir = tempdir( CLEANUP => 1 );
  my $bin = "$dir/bin";
  mkdir $bin or die "$bin: $!";
  my %stubs = %{ $args{stubs} // {} };
  stub( $bin, $_, $stubs{$_} ) for sort keys %stubs;
  my %files = %{ $args{files} // {} };
  spew( "$dir/$_", $files{$_} ) for keys %files;
  my $status = do {
    local $ENV{PATH}     = $bin;
    local $ENV{STUB_LOG} = "$dir/log";
    local $ENV{STUB_DIR} = $dir;
    system( '/bin/sh', '-e', '-c', '{ ' . $line . ' ; } >' . $dir . '/stdout 2>' . $dir . '/stderr' );
  };
  my $log = slurp("$dir/log");
  return {
    status => $status,
    log    => $log,
    lines  => [ split /\n/, $log ],
    stdout => slurp("$dir/stdout"),
    stderr => slurp("$dir/stderr"),
  };
}

my %HOST = (
  rm        => "exit 0\n",
  umount    => "exit 0\n",
  bpftool   => $BPFTOOL,
  systemctl => "exit 3\n",
);

SKIP: {
  skip 'no cleanup line', 1 unless defined $LINE;
  skip 'needs a POSIX /bin/sh', 1 unless -x '/bin/sh';
  skip 'runs the destructive cleanup line against stubs: never as root', 1 if $> == 0;
  skip '/bin/sh does not run the stubs on PATH', 1 unless stubs_are_used();

  subtest 'the cleanup line under /bin/sh -e, against stubs' => sub {

    subtest 'a distribution on the host: nothing is cleared' => sub {
      for my $case (
        [ 'rke2 on PATH'          => { rke2 => "exit 0\n" } ],
        [ 'k3s on PATH'           => { k3s  => "exit 0\n" } ],
        [ 'a distribution unit active' => { systemctl => "exit 0\n" } ],
      ) {
        my ( $what, $stubs ) = @$case;
        my $r = run_line( stubs => { %HOST, %$stubs }, files => { 'tree-1' => $TREE } );
        is_deeply( [ grep { /^(?:rm|umount|bpftool) / } @{ $r->{lines} } ], [],
          "$what: no rm, no umount, no bpftool: the datapath is that cluster's" );
        is( $r->{stderr}, '', "$what: nothing on stderr" );
        is( $r->{status}, 0, "$what: exit 0" );
      }
    };

    subtest 'no distribution: the four steps, in order' => sub {
      my $r = run_line( stubs => \%HOST, files => { 'tree-1' => $TREE, 'tree-after' => $TREE_HEADER } );
      my @steps = grep { /^(?:rm|umount|bpftool) / } @{ $r->{lines} };
      # The tc globals pattern as /bin/sh hands it on: unexpanded, or the
      # maps should this machine have any (the stub removes nothing).
      my ( $globals ) = grep { m{^rm -rf /sys/fs/bpf/tc/globals/cilium_} } @steps;
      like( $globals // '', qr{\Arm -rf (?:/sys/fs/bpf/tc/globals/cilium_\S+ ?)+\z},
        '3. the tc globals maps, by their pattern' );
      is_deeply( \@steps, [
        'rm -rf /sys/fs/bpf/cilium',
        'bpftool cgroup tree /sys/fs/cgroup',
        @DETACHED,
        'bpftool cgroup tree /sys/fs/cgroup',
        $globals // 'rm -rf /sys/fs/bpf/tc/globals/cilium_*',
        'umount /run/cilium/cgroupv2',
        'rm -rf --one-file-system /run/cilium',
      ], '1. pins, 2. cil_* programs detached and listed again, 3. tc globals, 4. mount, then runtime dir' );
      is( $r->{stderr}, '', 'all of it detached: no warning' );
      is( $r->{stdout}, '', 'nothing on stdout' );
      is( $r->{status}, 0, 'exit 0' );
      is_deeply( [ $U->uninstall_warnings( $r->{stdout}, $r->{stderr} ) ], [], 'uninstall_warnings: none' );
    };

    subtest 'only cil_* programs are detached, from the cgroup they are listed under' => sub {
      my $r = run_line( stubs => \%HOST, files => { 'tree-1' => $TREE, 'tree-after' => $TREE_HEADER } );
      my @detach = grep { /^bpftool cgroup detach / } @{ $r->{lines} };
      is_deeply( \@detach, \@DETACHED, 'at the root and below it, each attach type as bpftool printed it' );
      unlike( $r->{log}, qr/ id (?:51|37|38)$/m, "systemd's programs and a name with cil_ inside stay" );
    };

    subtest 'no bpftool: a warning, the rest still runs' => sub {
      my %host = %HOST;
      delete $host{bpftool};
      my $r = run_line( stubs => \%host );
      is( $r->{stderr}, "$MARK$NO_BPFTOOL\n", 'one marked line on stderr' );
      is_deeply( [ $U->uninstall_warnings( $r->{stdout}, $r->{stderr} ) ], [$NO_BPFTOOL],
        'uninstall_warnings reads it: not checked, a reboot clears it' );
      like( $r->{log}, qr{^rm -rf /sys/fs/bpf/cilium$}m, 'the pins still go' );
      like( $r->{log}, qr{^umount /run/cilium/cgroupv2$}m, 'the mount still goes' );
      like( $r->{log}, qr{^rm -rf --one-file-system /run/cilium$}m, 'and the runtime dir' );
      is( $r->{status}, 0, 'exit 0: a warning is not a failure' );
    };

    subtest 'cil_* programs still listed after the detach: a warning' => sub {
      my $left = $TREE_HEADER . "/sys/fs/cgroup\n4220     cgroup_inet_sock_release                 cil_sock_release\n";
      for my $case (
        [ 'the detach fails' => { 'tree-1' => $TREE, 'tree-after' => $TREE, 'detach-exit' => "255\n" } ],
        [ 'one stays attached' => { 'tree-1' => $TREE, 'tree-after' => $left } ],
      ) {
        my ( $what, $files ) = @$case;
        my $r = run_line( stubs => \%HOST, files => $files );
        is( $r->{stderr}, "$MARK$STILL_LISTED\n", "$what: one marked line on stderr" );
        is_deeply( [ $U->uninstall_warnings( $r->{stderr} ) ], [$STILL_LISTED], "$what: uninstall_warnings reads it" );
        like( $r->{log}, qr{^rm -rf --one-file-system /run/cilium$}m, "$what: the steps after it still run" );
        is( $r->{status}, 0, "$what: exit 0" );
      }
      my $r = run_line( stubs => \%HOST, files => { 'tree-1' => $TREE,
        'tree-after' => $TREE_HEADER . "/sys/fs/cgroup/system.slice/systemd-udevd.service\n    37       cgroup_device   multi           sd_devices\n" } );
      is( $r->{stderr}, '', 'programs that are not Cilium\'s still listed: no warning' );
    };

    subtest 'a clean host: nothing detached, no warning, the same the second time' => sub {
      my @runs = map {
        run_line( stubs => { %HOST, umount => "exit 32\n" }, files => { 'tree-1' => $TREE_HEADER } )
      } 1 .. 2;
      for my $n ( 0, 1 ) {
        my $r = $runs[$n];
        my $which = $n ? 'second run' : 'first run';
        is_deeply( [ grep { /^bpftool cgroup detach / } @{ $r->{lines} } ], [], "$which: nothing detached" );
        is( $r->{stderr}, '', "$which: nothing on stderr" );
        is( $r->{status}, 0, "$which: exit 0, nothing mounted is no failure" );
      }
      is_deeply( $runs[1]{lines}, $runs[0]{lines}, 'the second run issues exactly what the first did' );
    };

    subtest 'every step failing does not fail the line' => sub {
      my $r = run_line(
        stubs => { rm => "exit 1\n", umount => "exit 1\n", bpftool => "exit 1\n", systemctl => "exit 1\n" },
      );
      like( $r->{log}, qr{^umount -l /run/cilium/cgroupv2$}m, 'a mount that will not go is detached lazily' );
      like( $r->{log}, qr{^rm -rf --one-file-system /run/cilium$}m, 'the last step is still reached' );
      is( $r->{stderr}, '', 'a bpftool that lists nothing: no warning' );
      is( $r->{status}, 0, 'runs to completion under set -e' );
    };
  };
}

# ---- 3./4. check_cilium_residue over Rex -----------------------------------------

# @probes: what each probe answers in turn, [ exit, output ]; a host past
# them is clean. %cleanup: the cleanup line's exit, stdout and stderr.
my ( @ran, @logged, @probes, %cleanup );
{
  no warnings 'redefine';
  *Rex::Commands::Run::run = sub {
    my ( $c, @rest ) = @_;
    my $code = ref $rest[0] eq 'CODE' ? shift @rest : undef;
    push @ran, [ $c, {@rest} ];
    if ( $c eq $PROBE ) {
      my ( $exit, $out ) = @{ shift @probes // [ 0, '' ] };
      $? = $exit << 8;
      return $out;
    }
    if ( defined $LINE && $c eq $LINE ) {
      $? = ( $cleanup{exit} // 0 ) << 8;
      my ( $out, $err ) = ( $cleanup{stdout} // '', $cleanup{stderr} // '' );
      return $code ? $code->( $out, $err ) : $out;
    }
    $? = 0;
    return '';
  };
  *Rex::Logger::info = sub { push @logged, [ $_[0], $_[1] // 'info' ] };
}

# Sets up the host and calls check_cilium_residue(@args): true when it
# returned 1, its error in $@ otherwise.
sub check {
  my ( $host, @args ) = @_;
  @probes  = @{ $host->{probes} // [] };
  %cleanup = %{ $host->{cleanup} // {} };
  @ran = @logged = ();
  my $ret = eval { $U->check_cilium_residue(@args) };
  return defined $ret && $ret == 1;
}

sub ran    { map { $_->[0] eq $PROBE ? 'probe' : defined $LINE && $_->[0] eq $LINE ? 'cleanup' : $_->[0] } @ran }
sub warned { map { $_->[0] } grep { $_->[1] eq 'warn' } @logged }
sub said   { map { $_->[0] } grep { $_->[1] eq 'info' } @logged }

my $RESIDUE = { probes => [ [ 0, "/sys/fs/bpf/cilium\ncilium_host\n" ] ] };

my $CONSEQUENCE = "Until the host is rebooted, Cilium's socket load balancer keeps translating the old"
  . " cluster's service addresses to pods that are gone: connections to them hang instead of being"
  . " refused, a registry mirror among them, so every image pull of the new install stalls and it does"
  . " not come up in time.";

# What the refusal said before k97, up to the reboot it asked for.
my $BEFORE = "This host still carries Cilium datapath state from an earlier cluster (/sys/fs/bpf/cilium,"
  . " cilium_host), and no RKE2/K3s is installed on it. $CONSEQUENCE Nothing was written or installed."
  . ' Reboot the host';

subtest 'without clean: dies as before, naming the cleanup as the other way out' => sub {
  for my $args ( [], [ clean => 0 ] ) {
    my $how = @$args ? 'clean => 0' : 'no arguments';
    ok( !check( $RESIDUE, @$args ), "$how: dies" );
    my $err = $@;
    is( $err, "$BEFORE, or clear that state without a reboot with"
      . ' Rex::Rancher::Uninstall->check_cilium_residue(clean => 1) in a task on this host,'
      . " then run the install again.\n", "$how: the message" );
    is( substr( $err, 0, length $BEFORE ), $BEFORE, "$how: as before, up to the reboot it asks for" );
    is_deeply( [ ran() ], ['probe'], "$how: the probe is the only command that ran" );
  }
};

subtest 'the call the message names is one that clears the state' => sub {
  ok( !check($RESIDUE), 'dies' );
  my ( $class, $method, $key, $value ) = $@ =~ /\b([\w:]+)->(\w+)\((\w+) => (\w+)\)/;
  is( $class, 'Rex::Rancher::Uninstall', 'a class method of this module' );
  ok( $class && $class->can( $method // '' ), 'Rex::Rancher::Uninstall->' . ( $method // '?' ) . ' exists' );
  SKIP: {
    skip 'no call named', 2 unless $class && $method && $class->can($method);
    ok( check( { probes => [ @{ $RESIDUE->{probes} }, [ 0, '' ] ] }, $key => $value ), 'called as named: returns 1' )
      or diag $@;
    is_deeply( [ ran() ], [qw( probe cleanup probe )], 'it ran the cleanup and checked again' );
  }
};

subtest 'clean => 1 on a clean host, or one with a distribution: only the probe, twice alike' => sub {
  for my $n ( 1, 2 ) {
    ok( check( { probes => [ [ 0, '' ] ] }, clean => 1 ), "call $n: returns 1" ) or diag $@;
    is_deeply( [ ran() ], ['probe'], "call $n: nothing but the probe ran" );
    is_deeply( [ warned() ], [], "call $n: no warning" );
  }
};

subtest 'clean => 1 when the probe cannot run: warns as before, clears nothing' => sub {
  ok( check( { probes => [ [ 127, '' ] ] }, clean => 1 ), 'returns 1' ) or diag $@;
  is_deeply( [ ran() ], ['probe'], 'the cleanup did not run' );
  like( join( "\n", warned() ), qr/Could not check this host for Cilium datapath state .*exited 127/,
    'says the host was not checked' );
};

SKIP: {
  skip 'no cleanup line', 4 unless defined $LINE;

  subtest 'clean => 1 on a host with residue: cleared, checked again, returns 1' => sub {
    ok( check( { probes => [ @{ $RESIDUE->{probes} }, [ 0, '' ] ] }, clean => 1 ), 'returns 1' ) or diag $@;
    is_deeply( [ ran() ], [qw( probe cleanup probe )], 'probe, cleanup line, probe' );
    is( $ran[1][0], $LINE, 'the cleanup is cilium_residue_cleanup_cmd' );
    is( $ran[1][1]{auto_die}, 0, 'auto_die => 0: the second probe decides, not the exit status' );
    is_deeply( [ said() ], [
      'Clearing the Cilium datapath state an earlier cluster left on this host (/sys/fs/bpf/cilium,'
        . ' cilium_host) without a reboot',
      'Cleared the Cilium datapath state an earlier cluster left on this host, none is left',
    ], 'says what it clears, then that none is left' );
    is_deeply( [ warned() ], [], 'no warning' );
  };

  subtest 'clean => 1: the cleanup\'s warnings are logged and do not fail it' => sub {
    ok( check( { probes => [ @{ $RESIDUE->{probes} }, [ 0, '' ] ],
        cleanup => { stdout => "$MARK$STILL_LISTED\n", stderr => "sh: 1: noise\n$MARK$NO_BPFTOOL\n" } },
      clean => 1 ), 'returns 1' ) or diag $@;
    is_deeply( [ warned() ], [ $STILL_LISTED, $NO_BPFTOOL ], 'each marked line as warn, stdout before stderr' );
  };

  subtest 'clean => 1, residue left: dies naming it, asking for a reboot' => sub {
    ok( !check( { probes => [ @{ $RESIDUE->{probes} }, [ 0, "cilium_host\n" ] ],
        cleanup => { stderr => "$MARK$NO_BPFTOOL\n" } }, clean => 1 ), 'dies' );
    is( $@, "This host still carries Cilium datapath state from an earlier cluster (cilium_host) after"
      . " clearing it without a reboot, and no RKE2/K3s is installed on it. $CONSEQUENCE Nothing was"
      . " installed. Reboot the host, then run the install again.\n", 'what is left, and the reboot' );
    unlike( $@, qr/clean =>/, 'not the cleanup again' );
    is_deeply( [ ran() ], [qw( probe cleanup probe )], 'after one cleanup' );
    is_deeply( [ warned() ], [$NO_BPFTOOL], 'the warning was logged before it died' );
  };

  subtest 'clean => 1, the second probe cannot run: dies' => sub {
    ok( !check( { probes => [ @{ $RESIDUE->{probes} }, [ 255, '' ] ] }, clean => 1 ), 'dies' );
    is( $@, "Cleared the Cilium datapath state an earlier cluster left on this host (/sys/fs/bpf/cilium,"
      . " cilium_host) without a reboot, but could not check the host afterwards (the probe exited 255)."
      . " Nothing was installed. Reboot the host, then run the install again.\n",
      'nothing shows the state gone: not taken for a clean host' );
  };
}

is_deeply( \@perl_warnings, [], 'no Perl warnings' );

done_testing;
