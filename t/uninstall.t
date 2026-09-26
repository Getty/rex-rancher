use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# k71 (from kubernetes-ocp k196/k190/k175): uninstall_node takes RKE2/K3s off a
# host and clears what Cilium left in the kernel, which the vendor uninstallers
# do not: pins in bpffs (unpinning a link no agent holds any more is its
# detach), legacy tc attachments, cilium_* devices, CILIUM_* iptables chains,
# the cgroup2 mount and /run/cilium, Cilium's ip rules. Then it checks its own
# outcome: RKE2/K3s still on PATH, or Cilium state that survived, fails it,
# the latter asking for a reboot.
#
# The claims here:
#   1. uninstall_cmd is made of every vendor uninstaller, the leftover paths,
#      the datapath cleanup, the ip rules in a safe order and the outcome
#      check, in that order;
#   2. run under /bin/sh -e against stubs, every step is guarded and does
#      what it says (a port of kubernetes-ocp's t/190);
#   3. uninstall_node runs exactly that line over Rex and turns a failed
#      outcome into a clear message.
#
# Whether the kernel really detaches the programs when the pins go is a live
# question (Cilium's own detach does exactly that for its bpf_links), NOT
# claimed here; nor that a real host ends up clean.
# -----------------------------------------------------------------------------

use File::Temp qw( tempdir );
use Rex::Rancher::Distribution;
use Rex::Rancher::Uninstall;

my $U = 'Rex::Rancher::Uninstall';
my $D = 'Rex::Rancher::Distribution';

my @perl_warnings;
$SIG{__WARN__} = sub { push @perl_warnings, @_ };

my $cmd = $U->uninstall_cmd;

# ---- the vendor uninstallers are the distributions' ---------------------------

subtest 'uninstall_scripts: per distribution, the same for either role' => sub {
  for my $role (qw( server agent )) {
    is_deeply( [ $D->new_for( 'rke2', role => $role )->uninstall_scripts ], ['rke2-uninstall.sh'],
      "rke2 $role: one script for both roles" );
    is_deeply( [ $D->new_for( 'k3s', role => $role )->uninstall_scripts ],
      [qw( k3s-uninstall.sh k3s-agent-uninstall.sh )], "k3s $role: named after the service" );
  }
};

# ---- 1. what the line is made of ----------------------------------------------

subtest 'the line: every step, in order' => sub {
  my @steps = (
    [ 'every vendor uninstaller that is there; a failing one does not stop the next' =>
      'for u in rke2-uninstall.sh k3s-uninstall.sh k3s-agent-uninstall.sh; do'
      . ' if command -v $u >/dev/null 2>&1; then $u 2>/dev/null || true; fi; done' ],
    [ 'the Cilium CLI, the CNI dir, the shared runtime dir' =>
      'rm -rf /usr/local/bin/cilium /opt/cni /run/k3s 2>/dev/null || true' ],
    [ 'legacy tc: clsact off every device with a Cilium program' =>
      'for d in /sys/class/net/*; do d=${d##*/};' ],
    [ 'the pins' => 'rm -rf /sys/fs/bpf/cilium /sys/fs/bpf/tc/globals/cilium_* 2>/dev/null || true' ],
    [ 'the devices' => 'for l in cilium_host cilium_net cilium_vxlan cilium_geneve cilium_wg0;'
      . ' do ip link del dev $l 2>/dev/null || true; done' ],
    [ 'the iptables chains in every backend' =>
      'for ipt in iptables ip6tables iptables-legacy ip6tables-legacy iptables-nft ip6tables-nft; do' ],
    [ 'every table' => 'for tb in filter nat mangle raw; do' ],
    [ 'one restore per table, every other rule kept' => '$ipt-restore --noflush 2>/dev/null || true' ],
    [ 'the cgroup2 mount' =>
      'umount /run/cilium/cgroupv2 2>/dev/null || umount -l /run/cilium/cgroupv2 2>/dev/null || true' ],
    [ 'then the runtime dir, never into a mount that stayed' =>
      'rm -rf --one-file-system /run/cilium 2>/dev/null || true' ],
    [ "Cilium's proxy route tables" =>
      'for t in 2004 2005; do while ip rule del lookup $t 2>/dev/null; do :; done; done' ],
    [ 'the local lookup put back at priority 0 first' =>
      'ip rule list 2>/dev/null | grep -qE "^0:[[:space:]].*lookup local"'
      . ' || ip rule add from all lookup local priority 0 2>/dev/null || true' ],
    [ 'then the one at 100 removed, only with one at 0 there' =>
      'ip rule list 2>/dev/null | grep -qE "^0:[[:space:]].*lookup local"'
      . ' && ip rule del from all lookup local priority 100 2>/dev/null || true' ],
    [ 'outcome: a distribution binary still on PATH' =>
      'for b in rke2 k3s; do p=$(command -v $b 2>/dev/null) && still="$still $p"; done' ],
    [ '... fails the line' =>
      'if [ -n "$still" ]; then echo "RKE2/K3s is still installed after the uninstall:$still'
      . ' -- its uninstall script is missing or failed" >&2; exit 1; fi' ],
    [ 'outcome: Cilium residue fails the line, asking for a reboot' =>
      'if [ -n "$left" ]; then echo "Cilium datapath state is still on the host after the uninstall:$left'
      . ' -- reboot the host before RKE2/K3s is installed on it again" >&2; exit 1; fi' ],
  );
  my $last = -1;
  for my $s (@steps) {
    my ( $what, $text ) = @$s;
    my $at = index $cmd, $text;
    ok( $at >= 0, "has: $what" ) or diag "missing: $text";
    ok( $at > $last, "... after the step before" );
    $last = $at if $at >= 0;
  }
  like( $cmd, qr/\$ipt-save -t \$tb/, 'reads each table with the backend\'s own -save' );
  like( $cmd, qr/-j \(OLD_\)\?CILIUM_/, 'jumps into CILIUM_ and OLD_CILIUM_ chains are deleted' );
  like( $cmd, qr/umount -l /, 'a busy cgroup2 mount is detached lazily' );
};

subtest 'uninstall_failure: the message' => sub {
  is( $U->uninstall_failure( 0, "anything\n" ), undef, 'exit 0: none' );
  is( $U->uninstall_failure( 255, '' ), "Uninstall of RKE2/K3s failed (exit 255)\n", 'no stderr: the exit' );
  is( $U->uninstall_failure( 1, "RKE2/K3s is still installed after the uninstall: /usr/local/bin/rke2"
      . " -- its uninstall script is missing or failed\n\n" ),
    "Uninstall of RKE2/K3s failed (exit 1): RKE2/K3s is still installed after the uninstall:"
    . " /usr/local/bin/rke2 -- its uninstall script is missing or failed\n", 'the reason, trimmed' );
};

# ---- 2. the line under /bin/sh -e, against stubs -----------------------------
#
# The line is destructive (rm -rf, ip link del, iptables-restore, umount). It
# runs here only with a PATH of nothing but stubs, and only when both hold:
# the tests do not run as root (a stub that is not picked up cannot do harm),
# and the shell verifiably runs the stub for `rm` instead of a builtin or a
# multi-call applet of its own.

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
  spew( "$bin/$name", "#!/bin/sh\necho \"$name \$*\" >> \"\$STUB_LOG\"\n".$body );
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

# Cilium state on the machine running the tests shows in the outcome check.
sub machine_has_residue {
  return 1 if -e '/sys/fs/bpf/cilium';
  return slurp('/proc/mounts') =~ m{ /run/cilium/cgroupv2 } ? 1 : 0;
}

# Runs the line under /bin/sh -e with a PATH of nothing but stubs. A stub body
# gets $STUB_LOG (one line per call: name and args) and $STUB_DIR. Real tools
# the logic needs (grep, sed) are linked in by name.
sub run_uninstall {
  my ( %stubs ) = @_;
  my $dir = tempdir( CLEANUP => 1 );
  my $bin = "$dir/bin";
  mkdir $bin or die "$bin: $!";
  for my $real (qw( grep sed )) {
    my ( $path ) = grep { -x } map { "$_/$real" } qw( /usr/bin /bin );
    symlink $path, "$bin/$real" if $path;
  }
  stub( $bin, $_, $stubs{$_} ) for sort keys %stubs;
  my $status = do {
    local $ENV{PATH}     = $bin;
    local $ENV{STUB_LOG} = "$dir/log";
    local $ENV{STUB_DIR} = $dir;
    system('/bin/sh', '-e', '-c', '{ '.$cmd.' ; } 2>'.$dir.'/stderr');
  };
  return {
    status => $status,
    exit   => $status >> 8,
    log    => slurp("$dir/log"),
    stderr => slurp("$dir/stderr"),
    dir    => $dir,
    bin    => $bin,
  };
}

SKIP: {
  skip 'needs a POSIX /bin/sh', 1 unless -x '/bin/sh';
  skip 'runs the destructive uninstall line against stubs: never as root', 1 if $> == 0;
  skip '/bin/sh does not run the stubs on PATH', 1 unless stubs_are_used();

  subtest 'the uninstall line under /bin/sh -e, against stubs' => sub {

    subtest 'pins, devices, mount and runtime dir are removed' => sub {
      my $r = run_uninstall(
        ( map { $_ => "exit 0\n" } qw( rm tc umount ) ),
        # deleting a device works; nothing is left to show, no rule to drain
        ip => "case \"\$1 \$2\" in \"link del\") exit 0;; esac\nexit 1\n",
      );
      my $log = $r->{log};
      like( $log, qr{^rm -rf /usr/local/bin/cilium /opt/cni /run/k3s$}m, 'the leftover paths go' );
      like( $log, qr{^rm -rf /sys/fs/bpf/cilium /sys/fs/bpf/tc/globals/cilium_\*}m,
        'the pinned links and maps go -- unpinning a link Cilium no longer holds detaches its program' );
      for my $l (qw( cilium_host cilium_net cilium_vxlan cilium_geneve cilium_wg0 )) {
        like( $log, qr/^ip link del dev $l$/m, "device $l is deleted" );
      }
      like( $log, qr{^umount /run/cilium/cgroupv2$}m, "Cilium's cgroup2 mount is unmounted" );
      like( $log, qr{^rm -rf --one-file-system /run/cilium$}m,
        'the runtime dir goes, never recursing into a mount that stayed' );
      my $umount = index $log, 'umount /run/cilium/cgroupv2';
      my $rmrun  = index $log, 'rm -rf --one-file-system /run/cilium';
      ok( $umount >= 0 && $umount < $rmrun, 'unmounted before the runtime dir is removed' );
      SKIP: {
        skip 'this machine carries Cilium state itself', 1 if machine_has_residue();
        is( $r->{status}, 0, 'a host the cleanup leaves clean: the uninstall succeeds' )
          or diag $r->{stderr};
      }
    };

    subtest 'every vendor uninstaller there runs, a failing one does not stop the next' => sub {
      my $r = run_uninstall(
        'rke2-uninstall.sh'      => "exit 1\n",
        'k3s-uninstall.sh'       => "exit 0\n",
        'k3s-agent-uninstall.sh' => "exit 0\n",
        ( map { $_ => "exit 0\n" } qw( rm tc umount ) ),
        ip => "exit 1\n",
      );
      like( $r->{log}, qr/^\Q$_\E $/m, "$_ ran" ) for qw( rke2-uninstall.sh k3s-uninstall.sh k3s-agent-uninstall.sh );
      my $none = run_uninstall( ( map { $_ => "exit 0\n" } qw( rm tc umount ) ), ip => "exit 1\n" );
      unlike( $none->{log}, qr/uninstall\.sh/, 'none there: none run, no failure for it' );
    };

    subtest 'a device carrying a legacy tc program loses its clsact qdisc' => sub {
      opendir my $dh, '/sys/class/net' or plan skip_all => 'no /sys/class/net here';
      my @devs = grep { !/\A\./ } readdir $dh;
      closedir $dh;
      plan skip_all => 'no devices in /sys/class/net' unless @devs;
      my $dev = $devs[0];
      my $r = run_uninstall(
        rm => "exit 0\n",
        ip => "exit 1\n",
        tc => "case \"\$*\" in \"filter show dev $dev ingress\") echo 'filter protocol all pref 1 bpf chain 0 handle 0x1 cil_from_netdev direct-action';; esac\nexit 0\n",
      );
      like( $r->{log}, qr/^tc qdisc del dev \Q$dev\E clsact$/m, "clsact removed from $dev" );
      for my $o (grep { $_ ne $dev } @devs) {
        unlike( $r->{log}, qr/^tc qdisc del dev \Q$o\E /m, "$o without a Cilium program is left alone" );
      }
    };

    subtest 'CILIUM_* iptables chains: jumps deleted, chains flushed and removed' => sub {
      my $save = <<'SAVE';
# Generated by iptables-save
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:CILIUM_POST_nat - [0:0]
:OLD_CILIUM_POST_nat - [0:0]
:KUBE-SERVICES - [0:0]
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_nat" -j CILIUM_POST_nat
-A PREROUTING -j KUBE-SERVICES
-A CILIUM_POST_nat -s 10.42.0.0/16 -j MASQUERADE
COMMIT
SAVE
      my $dir = tempdir( CLEANUP => 1 );
      spew( "$dir/save", $save );
      my $r = run_uninstall(
        rm                 => "exit 0\n",
        ip                 => "exit 1\n",
        'iptables-save'    => "case \"\$*\" in \"-t nat\") cat $dir/save;; *) echo '*filter'; echo ':INPUT ACCEPT [0:0]'; echo COMMIT;; esac\n",
        'iptables-restore' => "cat >> \"\$STUB_DIR/restore\"\n",
        # a backend without its -restore is not read at all
        'ip6tables-save'   => "echo '*nat'; echo ':CILIUM_POST_nat - [0:0]'; echo COMMIT\n",
        cat                => "exec /bin/cat \"\$@\"\n",
      );
      my $restore = "$r->{dir}/restore";
      ok( -e $restore, 'iptables-restore was fed' );
      my $in = slurp($restore);
      is( $in, join( "\n",
        '*nat',
        '-D POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_nat" -j CILIUM_POST_nat',
        '-F CILIUM_POST_nat',
        '-F OLD_CILIUM_POST_nat',
        '-X CILIUM_POST_nat',
        '-X OLD_CILIUM_POST_nat',
        'COMMIT',
      )."\n", 'one transaction for the nat table, nothing for a table without Cilium' );
      like( $r->{log}, qr/^iptables-restore --noflush$/m, 'restored with --noflush: every other rule stays' );
      unlike( $in, qr/KUBE-/, 'rules of anyone else are not touched' );
      unlike( $r->{log}, qr/^ip6tables-save/m, 'a backend without both -save and -restore is skipped' );
    };

    # ip: two rules each in 2004/2005 until drained; `rule list` shows the
    # local lookup at 100, and at 0 once `rule add` succeeded ($1 = add result).
    my $ip_rules = sub {
      my ( $add_exit ) = @_;
      return join "\n",
        'case "$1 $2" in',
        '  "rule del")',
        '    case "$3" in',
        '      lookup) n="$STUB_DIR/drained-$4"; c=$(cat "$n" 2>/dev/null || echo 0);'
          . ' [ "$c" -ge 2 ] && exit 2; echo $((c + 1)) > "$n"; exit 0;;',
        '    esac; exit 0;;',
        "  \"rule add\") [ $add_exit -eq 0 ] && : > \"\$STUB_DIR/local0\"; exit $add_exit;;",
        '  "rule list") [ -e "$STUB_DIR/local0" ] && printf "0:\tfrom all lookup local\n";'
          . ' printf "100:\tfrom all lookup local\n"; exit 0;;',
        'esac',
        'exit 1',
        '';
    };

    subtest "Cilium's ip rules: tables drained, the local lookup back at 0 before 100 goes" => sub {
      my $r = run_uninstall(
        ( map { $_ => "exit 0\n" } qw( rm tc umount ) ),
        cat => "exec /bin/cat \"\$@\"\n",
        ip  => $ip_rules->(0),
      );
      my @rule = grep { /^ip rule / } split /\n/, $r->{log};
      is_deeply( \@rule, [
        ( 'ip rule del lookup 2004' ) x 3,
        ( 'ip rule del lookup 2005' ) x 3,
        'ip rule list',
        'ip rule add from all lookup local priority 0',
        'ip rule list',
        'ip rule del from all lookup local priority 100',
      ], 'each table drained until empty; local put back at 0, then the one at 100 removed' );
    };

    subtest 'the local lookup at 100 stays when 0 cannot be put back' => sub {
      my $r = run_uninstall(
        ( map { $_ => "exit 0\n" } qw( rm tc umount ) ),
        cat => "exec /bin/cat \"\$@\"\n",
        ip  => $ip_rules->(2),
      );
      like( $r->{log}, qr/^ip rule add from all lookup local priority 0$/m, 'tried' );
      unlike( $r->{log}, qr/^ip rule del from all lookup local priority 100$/m,
        'never left without a local-table lookup' );
    };

    subtest 'every step failing does not abort the chain' => sub {
      my $r = run_uninstall(
        map { $_ => "exit 1\n" }
          qw( rke2-uninstall.sh rm ip tc umount iptables-save iptables-restore )
      );
      like( $r->{log}, qr/^umount /m, 'the unmount is still attempted' );
      like( $r->{log}, qr/^rm -rf --one-file-system /m, 'and the runtime dir' );
      SKIP: {
        skip 'this machine carries Cilium state itself', 1 if machine_has_residue();
        is( $r->{status}, 0, 'runs to completion under set -e' ) or diag $r->{stderr};
      }
    };

    subtest 'outcome: Cilium state that survived fails the line, asking for a reboot' => sub {
      my $r = run_uninstall(
        rm => "exit 0\n",
        ip => "case \"\$*\" in \"link show dev cilium_host\") exit 0;; esac\nexit 1\n",
      );
      is( $r->{exit}, 1, 'exit 1' );
      like( $r->{stderr}, qr/^Cilium datapath state is still on the host after the uninstall:.* cilium_host -- reboot the host before RKE2\/K3s is installed on it again$/m,
        'naming what is left and what to do' );
      like( $U->uninstall_failure( $r->{exit}, $r->{stderr} ), qr/\AUninstall of RKE2\/K3s failed \(exit 1\): Cilium datapath state .*reboot the host.*\n\z/s,
        'uninstall_failure makes it the message' );
    };

    subtest 'outcome: a distribution still on PATH fails the line' => sub {
      my $r = run_uninstall(
        'rke2-uninstall.sh' => "exit 1\n",
        rke2                => "exit 0\n",
        ( map { $_ => "exit 0\n" } qw( rm tc umount ) ),
        ip => "exit 1\n",
      );
      my $rke2 = "$r->{bin}/rke2";
      is( $r->{exit}, 1, 'exit 1' );
      is( $r->{stderr}, "RKE2/K3s is still installed after the uninstall: $rke2 -- its uninstall script is missing or failed\n",
        'naming the binary left and the likely cause' );
      is( $U->uninstall_failure( $r->{exit}, $r->{stderr} ),
        "Uninstall of RKE2/K3s failed (exit 1): RKE2/K3s is still installed after the uninstall: $rke2 -- its uninstall script is missing or failed\n",
        'uninstall_failure makes it the message' );
    };
  };
}

# ---- 3. uninstall_node over Rex -------------------------------------------------

my ( @ran, $exit, $stderr );
{
  no warnings 'redefine';
  *Rex::Commands::Run::run = sub {
    my ( $c, @rest ) = @_;
    my $code = ref $rest[0] eq 'CODE' ? shift @rest : undef;
    push @ran, [ $c, {@rest} ];
    $? = $exit << 8;
    return $code ? $code->( "stdout of the uninstallers\n", $stderr ) : "stdout of the uninstallers\n";
  };
  *Rex::Logger::info = sub { };
}

sub uninstall { ( $exit, $stderr, @ran ) = @_; return eval { uninstall_node(); 1 } }

subtest 'uninstall_node: exported, runs exactly the line' => sub {
  ok( defined &main::uninstall_node, 'use Rex::Rancher::Uninstall exports uninstall_node' );
  ok( uninstall( 0, '' ), 'a clean outcome: no die' ) or diag $@;
  is( scalar @ran, 1, 'one command' );
  is( $ran[0][0], $cmd, 'the uninstall line' );
  is( $ran[0][1]{auto_die}, 0, 'auto_die => 0: exit status and stderr make the message' );
  is( uninstall_node(), 1, 'returns 1' );
};

subtest 'uninstall_node: a failed outcome dies with a clear message' => sub {
  ok( !uninstall( 1, "RKE2/K3s is still installed after the uninstall: /usr/local/bin/rke2"
      . " -- its uninstall script is missing or failed\n" ), 'still installed: dies' );
  is( $@, "Uninstall of RKE2/K3s failed (exit 1): RKE2/K3s is still installed after the uninstall:"
    . " /usr/local/bin/rke2 -- its uninstall script is missing or failed\n", 'naming what is left' );

  ok( !uninstall( 1, "Cilium datapath state is still on the host after the uninstall: /sys/fs/bpf/cilium"
      . " cilium_host -- reboot the host before RKE2/K3s is installed on it again\n" ), 'residue: dies' );
  like( $@, qr/\AUninstall of RKE2\/K3s failed \(exit 1\): Cilium datapath state is still on the host after the uninstall: \/sys\/fs\/bpf\/cilium cilium_host -- reboot the host/,
    'naming the residue and the reboot' );

  ok( !uninstall( 255, '' ), 'a refused login: dies' );
  is( $@, "Uninstall of RKE2/K3s failed (exit 255)\n", 'with the exit status' );
  unlike( $@, qr/stdout of the uninstallers/, 'the uninstallers\' output is not the reason' );
};

is_deeply( \@perl_warnings, [], 'no Perl warnings' );

done_testing;
