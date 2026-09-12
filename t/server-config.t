use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# Unit test for the server config.yaml builder (Rex::Rancher::Server).
#
# Regression guard for karr #5: with cilium enabled the config wrote
# `cni: none` + `disable-kube-proxy: true` for BOTH distributions, but Cilium's
# kube-proxy replacement (kubeProxyReplacement/k8sServiceHost/Port) is only
# wired for rke2 (see Rex::Rancher::Cilium). On k3s that left kube-proxy
# disabled with nothing replacing it -> Service/ClusterIP routing dead.
#
# The rke2-specific keys must be gated to rke2. k3s keeps its own kube-proxy
# and default CNI. _build_server_config is pure (no file/YAML I/O), so it is
# unit-testable offline; the actual write stays in _write_config.
# -----------------------------------------------------------------------------

use Rex::Rancher::Server;

sub cfg { Rex::Rancher::Server::_build_server_config(@_) }
#          ($distribution, $token, $server, $tls_san, $node_labels, $cilium)

subtest 'rke2 + cilium: kube-proxy replacement config present' => sub {
  my $c = cfg('rke2', 'tok', undef, undef, undef, 1);
  is($c->{token}, 'tok',   'token set');
  is($c->{cni},   'none',  'cni:none — Cilium owns the CNI');
  ok($c->{'disable-kube-proxy'}, 'disable-kube-proxy true (Cilium replaces it on rke2)');
  is_deeply($c->{disable}, ['rke2-ingress-nginx'], 'rke2 ingress disabled');
};

subtest 'k3s + cilium: no rke2-only kube-proxy override (karr #5)' => sub {
  my $c = cfg('k3s', 'tok', undef, undef, undef, 1);
  is($c->{token}, 'tok', 'token set');
  ok(!exists $c->{'disable-kube-proxy'},
    'k3s keeps its own kube-proxy — Cilium replacement is rke2-only');
  ok(!exists $c->{cni},     'no cni:none on k3s');
  ok(!exists $c->{disable}, 'no rke2-specific disable list on k3s');
};

subtest 'rke2 without cilium: no kube-proxy override, ingress still disabled' => sub {
  my $c = cfg('rke2', 'tok', undef, undef, undef, 0);
  ok(!exists $c->{'disable-kube-proxy'}, 'no disable-kube-proxy without cilium');
  ok(!exists $c->{cni},                  'no cni:none without cilium');
  is_deeply($c->{disable}, ['rke2-ingress-nginx'], 'rke2 ingress still disabled');
};

subtest 'server / tls_san / node_labels passthrough' => sub {
  my $c = cfg('rke2', 'tok', 'https://api:6443', ['lb.example.com'], ['role=cp'], 1);
  is($c->{server}, 'https://api:6443', 'server set');
  is_deeply($c->{'tls-san'},    ['lb.example.com'], 'tls-san array');
  is_deeply($c->{'node-label'}, ['role=cp'],        'node-label array');
};

done_testing;
