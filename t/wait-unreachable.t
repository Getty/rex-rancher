use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# An agent whose server address is unreachable is not waited on for the full
# timeout: wait_for_service reads the unit's journal along and dies once it
# has shown nothing but 'Failed to validate connection to cluster' for the
# threshold (120 s, rke2 and k3s alike). Any other line resets the count.
#
# Time is the journal's own timestamps (journalctl -o short-unix); interval is
# 0, so nothing waits. run is faked: this proves the decision, not a deploy.
# -----------------------------------------------------------------------------

use Rex::Rancher::Distribution;

$Rex::Logger::silent = 1;

my $D = 'Rex::Rancher::Distribution';
my $T0 = 1761000000;

my ( $journal, @cmds );
my $fake = sub {
  my ( $cmd ) = @_;
  push @cmds, $cmd;
  $? = 0;
  return "activating\n" if $cmd =~ /^systemctl is-active/;
  return $journal       if $cmd =~ /-o short-unix/;
  return "final journal\n" if $cmd =~ /^journalctl/;
  return '';
};
{
  no warnings 'redefine';
  *Rex::Commands::Run::run = $fake;
}

sub fail_line {
  my ( $t, $dist ) = @_;
  my $svc = $dist eq 'rke2' ? 'rke2[1]' : 'k3s[1]';
  return sprintf "%d.%06d host %s: level=error msg=\"Failed to validate connection to cluster at https://10.9.9.9:%d: failed to get CA certs\"\n",
    $T0 + $t, 123, $svc, $dist eq 'rke2' ? 9345 : 6443;
}
sub other_line { sprintf "%d.000001 host x[1]: level=info msg=\"Running load balancer\"\n", $T0 + $_[0] }
sub failing_for { my ( $dist, @t ) = @_; join '', map { fail_line( $_, $dist ) } @t }

for my $dist (qw( rke2 k3s )) {
  my $agent = $D->new_for( $dist, role => 'agent' );
  my $hint  = "It joins the cluster via https://10.9.9.9 -- check that this node can reach that address";

  @cmds = ();
  $journal = failing_for( $dist, 0, 30, 60, 90, 120 );
  ok( !eval { $agent->wait_for_service( attempts => 60, interval => 0, hint => $hint ); 1 },
    "$dist: 120 s of join failures only dies early" );
  like( $@, qr/cannot reach its server: the journal shows only 'Failed to validate connection to cluster' for 120s \(last state: activating\)\n\Q$hint\E\n--- journalctl.*final journal/s,
    "$dist: reason, hint, journal" );
  is( scalar( grep { /^systemctl is-active/ } @cmds ), 1, "$dist: stops at the first poll that sees it" );

  @cmds = ();
  $journal = failing_for( $dist, 0, 60, 119 );
  ok( !eval { $agent->wait_for_service( attempts => 3, interval => 0 ); 1 }, "$dist: 119 s: not yet" );
  like( $@, qr/did not become active within 0s/, "$dist: ends in the ordinary timeout" );
  is( scalar( grep { /^systemctl is-active/ } @cmds ), 3, "$dist: kept polling" );

  $journal = failing_for( $dist, 0, 60 ) . other_line(70) . failing_for( $dist, 80, 150 );
  ok( !eval { $agent->wait_for_service( attempts => 2, interval => 0 ); 1 }, "$dist: other line resets" );
  like( $@, qr/did not become active/, "$dist: 70 s since the other line is no early exit" );

  $journal = failing_for( $dist, 0, 600 );
  ok( !eval { $agent->wait_for_service( attempts => 2, interval => 0, unreachable_after => 0 ); 1 }, "$dist: switched off" );
  like( $@, qr/did not become active/, "$dist: unreachable_after => 0 never exits early" );

  $journal = failing_for( $dist, 0, 40 );
  ok( !eval { $agent->wait_for_service( attempts => 2, interval => 0, unreachable_after => 30 ); 1 }, "$dist: threshold is a parameter" );
  like( $@, qr/cannot reach its server/, "$dist: lower threshold exits early" );
}

is( $D->join_failure_span(undef), 0, 'no journal: 0' );
is( $D->join_failure_span(''), 0, 'empty journal: 0' );
is( $D->join_failure_span( failing_for( 'rke2', 5 ) ), 0, 'a single line is no span' );
is( $D->join_failure_span( failing_for( 'rke2', 0, 60, 120 ) ), 120, 'span first to last' );
is( $D->join_failure_span( other_line(0) . failing_for( 'k3s', 10, 70 ) ), 60,
  'k3s alike; the run starts after the other line' );
is( $D->join_failure_span( failing_for( 'rke2', 0, 100 ) . other_line(110) ), 0,
  'a journal that ends in another line is not a run' );
is( $D->join_failure_span( failing_for( 'rke2', 0, 100 ) . other_line(105) . failing_for( 'rke2', 110, 130 ) ), 20,
  'another line in between starts the count over' );


done_testing;
