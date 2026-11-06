#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# k114 (found checking k105): the uninstall steps lean on POSIX sh handing a
# pattern that matches nothing on as it is, so that rm -f ignores it:
# /sys/fs/bpf/tc/globals/cilium_*, /var/run/cdi/k8s.gpu.amd.com-gpu_*. A command
# sent over SSH runs under the login shell of the user, though: sshd runs it as
# `$SHELL -c LINE`. Rex puts no sh of its own in between (Rex::Interface::Exec::
# SSH and Rex::LibSSH's Exec pick a shell class by `echo $SHELL` -- for zsh
# Rex::Interface::Shell::Zsh, a Bash prefix of LC_ALL and PATH -- and only
# Rex::Interface::Exec::Sudo wraps in sh -c), nor does kubernetes-ocp's SSH
# provider. Under zsh (NOMATCH) such a pattern is an error that ends the whole
# line, || true or not.
#
# The claims:
#   1. uninstall_cmd is `/bin/sh -c ` and one word of nothing but single-quoted
#      text: no login shell expands or runs anything of it;
#   2. that word, as /bin/sh reads it, is exactly the script of the steps (the
#      one t/uninstall.t takes apart); a single quote in a script is carried
#      through as well;
#   3. the wrapper hands on the script's exit status, stdout and stderr;
#   4. with zsh as the login shell: a pattern without a match ends a line
#      that is not wrapped (the hazard, so this test can see it), a wrapped
#      one goes on past it, and zsh hands the uninstall script to /bin/sh as
#      it is.
#
# Nothing of the uninstall line runs here: only printf over its one quoted
# word, and only once claim 1 holds for that word.
# -----------------------------------------------------------------------------

use File::Temp qw( tempdir );
use Rex::Rancher::Uninstall;

my $U = 'Rex::Rancher::Uninstall';

my $QUOTED = qr/(?:'[^']*'|\\')+/;

# What follows "/bin/sh -c " when it is one word made only of '...' pieces
# and \' -- or undef.
sub quoted_word {
  my ( $line ) = @_;
  return $line =~ m{\A/bin/sh -c ($QUOTED)\z} ? $1 : undef;
}

# The text the shell (an argv) reads out of such a word: printf %s prints it
# as it came. Refuses anything else, so nothing of a line can run.
sub read_back {
  my ( $shell, $word ) = @_;
  die "not one quoted word\n" unless $word =~ /\A$QUOTED\z/;
  open my $fh, '-|', @$shell, '-c', "printf %s $word" or die "@$shell: $!";
  local $/;
  my $text = <$fh>;
  close $fh;
  return $text // '';
}

sub slurp {
  my ( $file ) = @_;
  open my $fh, '<', $file or return '';
  local $/;
  my $content = <$fh>;
  return $content // '';
}

# A harmless line under the shell (an argv), the way a login shell runs a
# command: { LINE ; } with stdout and stderr into files.
sub run_under {
  my ( $shell, $line ) = @_;
  my $dir = tempdir( CLEANUP => 1 );
  my $status = system( @$shell, '-c', '{ ' . $line . ' ; } >' . "$dir/out" . ' 2>' . "$dir/err" );
  return { exit => $status >> 8, out => slurp("$dir/out"), err => slurp("$dir/err") };
}

my $cmd  = $U->uninstall_cmd;
my $word = quoted_word($cmd);

# ---- 1. one /bin/sh -c command --------------------------------------------------

is( substr( $cmd, 0, 12 ), "/bin/sh -c '", 'uninstall_cmd starts as a /bin/sh -c command' );
ok( defined $word, '... and the rest is one single-quoted word: nothing in it for a login shell to expand' );

# ---- 2. /bin/sh reads back the script -------------------------------------------

SKIP: {
  skip 'needs a POSIX /bin/sh', 4 unless -x '/bin/sh';
  skip 'not one quoted word: not handed to a shell', 4 unless defined $word;
  my $script = $U->_uninstall_script;
  like( $script, qr/\Afor u in rke2-uninstall\.sh /, 'the script starts with the vendor uninstallers' );
  is( read_back( ['/bin/sh'], $word ), $script, '/bin/sh reads back exactly the script of the steps' );

  my $tricky = q{printf '%s\n' "it's" $HOME `id` \\ /none/x_* ; echo 'a''b' "'"};
  my $w = quoted_word( $U->_sh_c($tricky) );
  ok( defined $w, 'a script with single quotes in it: still one quoted word' );
  SKIP: {
    skip 'not one quoted word: not handed to a shell', 1 unless defined $w;
    is( read_back( ['/bin/sh'], $w ), $tricky, '... read back as it was' );
  }
}

# ---- 3. exit status and output pass through -------------------------------------

SKIP: {
  skip 'needs a POSIX /bin/sh', 3 unless -x '/bin/sh';
  my $r = run_under( ['/bin/sh'], $U->_sh_c(q{echo out; echo "err: it's" >&2; exit 3}) );
  is( $r->{exit}, 3,              'the exit status of the script' );
  is( $r->{out},  "out\n",        'its stdout' );
  is( $r->{err},  "err: it's\n",  'its stderr' );
}

# ---- 4. zsh as the login shell --------------------------------------------------

my ( $zsh ) = grep { -x } map { "$_/zsh" } grep { length } split /:/, $ENV{PATH} // '';

SKIP: {
  skip 'zsh is not installed', 4 unless $zsh;
  my $dir  = tempdir( CLEANUP => 1 );
  my $none = "$dir/none_*";    # the directory is empty: matches nothing
  my $list = "echo $none 2>/dev/null || true; echo reached";

  # -f: no startup files, so no setopt of the machine's changes NOMATCH.
  my $bare = run_under( [ $zsh, '-f' ], $list );
  unlike( $bare->{out}, qr/^reached$/m, 'zsh: a pattern without a match ends a bare line, || true or not' )
    or diag explain $bare;

  my $wrapped = run_under( [ $zsh, '-f' ], $U->_sh_c($list) );
  is( $wrapped->{out}, "$none\nreached\n", 'wrapped: /bin/sh hands the pattern on as it is and goes on' )
    or diag explain $wrapped;
  is( $wrapped->{exit}, 0, '... exit 0' );

  SKIP: {
    skip 'not one quoted word: not handed to a shell', 1 unless defined $word;
    is( read_back( [ $zsh, '-f' ], $word ), $U->_uninstall_script,
      'zsh hands the uninstall script to /bin/sh as it is' );
  }
}

done_testing;
