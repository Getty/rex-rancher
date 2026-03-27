# Hetzner bare-metal GPU server → single-node RKE2 cluster
#
# Usage:
#   rex -f eg/hetzner-gpu-rke2.Rexfile -H <IP> deploy
#   rex -f eg/hetzner-gpu-rke2.Rexfile -H <IP> status
#   rex -f eg/hetzner-gpu-rke2.Rexfile -H <IP> get_kubeconfig > ~/.kube/rexdemo.yaml
#
# Prerequisites:
#   - Fresh Debian on Hetzner dedicated server with NVIDIA GPU
#   - SSH root access (key-based)
#   - cpanm Rex::GPU Rex::Rancher (or -Ilib paths for dev)
#
# For development (both repos checked out):
#   rex -f eg/hetzner-gpu-rke2.Rexfile \
#       -I ../rex-gpu/lib -I lib \
#       -H <IP> deploy

use Rex -feature => ['1.4'];
use Rex::Commands::Run;
use Rex::Commands::File;

use Rex::Rancher::Node;
use Rex::Rancher::Server;
use Rex::Rancher::Cilium;
use Rex::GPU;

# --- Configuration ---

my $HOSTNAME = 'rexdemo';
my $DOMAIN   = 'internal';
my $TIMEZONE = 'Europe/Berlin';

# Override via environment if needed
my $TOKEN   = $ENV{RKE2_TOKEN}   || '';
my $TLS_SAN = $ENV{RKE2_TLS_SAN} || '';

# --- Connection ---

set connection => 'OpenSSH';
user 'root';

Rex::Config->set_openssh_opt(
  StrictHostKeyChecking => 'no',
  UserKnownHostsFile    => '/dev/null',
  IdentitiesOnly        => 'yes',
  initialize_options    => {
    master_opts => [
      '-F', '/dev/null',
      '-o', 'StrictHostKeyChecking=no',
      '-o', 'UserKnownHostsFile=/dev/null',
      '-o', 'IdentitiesOnly=yes',
      '-o', 'LogLevel=QUIET',
      '-o', 'ConnectTimeout=20',
    ],
  },
);

if ($ENV{REX_PRIVATE_KEY}) {
  private_key $ENV{REX_PRIVATE_KEY};
  public_key $ENV{REX_PUBLIC_KEY} if $ENV{REX_PUBLIC_KEY};
  key_auth;
}

# ============================================================
#  Main deployment
# ============================================================

desc "Full deployment: prepare → GPU → RKE2 → Cilium";
task "deploy", sub {
  my $host = connection->server;

  say "=== [1/4] Preparing node $HOSTNAME.$DOMAIN ===";
  prepare_node(
    hostname => $HOSTNAME,
    domain   => $DOMAIN,
    timezone => $TIMEZONE,
  );

  say "=== [2/4] GPU detection and driver setup ===";
  my $gpus = gpu_setup(containerd_config => 'rke2');
  _report_gpus($gpus);

  say "=== [3/4] Installing RKE2 server ===";
  install_server(
    distribution => 'rke2',
    ($TOKEN   ? (token   => $TOKEN)   : ()),
    ($TLS_SAN ? (tls_san => $TLS_SAN) : (tls_san => $host)),
  );

  say "=== [4/4] Installing Cilium CNI ===";
  install_cilium(distribution => 'rke2');

  _untaint_control_plane();

  say "";
  say "Done! Fetch kubeconfig:";
  say "  rex -f eg/hetzner-gpu-rke2.Rexfile -H $host get_kubeconfig > ~/.kube/rexdemo.yaml";
  say "  export KUBECONFIG=~/.kube/rexdemo.yaml";
  say "  kubectl get nodes";
};

# ============================================================
#  Individual steps (for debugging / re-running)
# ============================================================

desc "Step 1: Prepare node only";
task "prepare", sub {
  prepare_node(
    hostname => $HOSTNAME,
    domain   => $DOMAIN,
    timezone => $TIMEZONE,
  );
};

desc "Step 2: GPU detect + install only";
task "gpu", sub {
  my $gpus = gpu_setup(containerd_config => 'rke2');
  _report_gpus($gpus);
};

desc "Step 3+4: RKE2 + Cilium only (node must be prepared)";
task "rke2", sub {
  my $host = connection->server;
  install_server(
    distribution => 'rke2',
    ($TOKEN   ? (token   => $TOKEN)   : ()),
    ($TLS_SAN ? (tls_san => $TLS_SAN) : (tls_san => $host)),
  );
  install_cilium(distribution => 'rke2');
  _untaint_control_plane();
};

# ============================================================
#  Post-deploy: registry update
# ============================================================

desc "Update registries.yaml (after deploying registry into cluster)";
task "add_registry", sub {
  my $registry_ip = $ENV{REGISTRY_IP} or die "Set REGISTRY_IP env var\n";

  update_registries(
    distribution => 'rke2',
    registries   => {
      mirrors => {
        'docker.io' => {
          endpoint => ["http://$registry_ip:5000"],
        },
        'registry.internal' => {
          endpoint => ["http://$registry_ip:5000"],
        },
      },
    },
  );
  say "Registries updated — docker.io and registry.internal → $registry_ip:5000";
};

# ============================================================
#  Info / status tasks
# ============================================================

desc "Fetch kubeconfig (pipe to file)";
task "get_kubeconfig", sub {
  my $kubeconfig = get_kubeconfig('rke2');
  my $host = connection->server;
  $kubeconfig =~ s/127\.0\.0\.1/$host/g;
  $kubeconfig =~ s/localhost/$host/g;
  $kubeconfig =~ s/^\s*certificate-authority-data:.*\n//mg;
  $kubeconfig =~ s/(server: https:\/\/[^\n]+)/$1\n    insecure-skip-tls-verify: true/g;
  print $kubeconfig;
};

desc "Get node join token";
task "get_token", sub {
  say get_token('rke2');
};

desc "Check GPU status";
task "gpu_status", sub {
  say "=== nvidia-smi ===";
  say run("nvidia-smi 2>&1", auto_die => 0) || "(not available)";

  say "\n=== Kernel modules ===";
  say run("lsmod | grep nvidia", auto_die => 0) || "(none loaded)";

  say "\n=== Container toolkit ===";
  say run("nvidia-ctk --version 2>&1", auto_die => 0) || "(not installed)";

  say "\n=== containerd nvidia config ===";
  say run("cat /etc/containerd/conf.d/99-nvidia.toml 2>/dev/null || echo '(not configured)'", auto_die => 0);
};

desc "Check cluster + GPU status";
task "status", sub {
  my $kubectl = '/var/lib/rancher/rke2/bin/kubectl';
  my $kc = '/etc/rancher/rke2/rke2.yaml';

  say "=== Nodes ===";
  say run("$kubectl --kubeconfig=$kc get nodes -o wide 2>&1", auto_die => 0);

  say "\n=== GPU allocatable ===";
  say run("$kubectl --kubeconfig=$kc get nodes -o jsonpath='{range .items[*]}{.metadata.name}{\"\\t\"}{.status.allocatable.nvidia\\.com/gpu}{\"\\n\"}{end}' 2>/dev/null", auto_die => 0)
    || "(no GPU resources)";

  say "\n=== Cilium ===";
  say run("KUBECONFIG=$kc cilium status 2>/dev/null || echo '(cilium not ready)'", auto_die => 0);

  say "\n=== Registries ===";
  my $reg = run("cat /etc/rancher/rke2/registries.yaml 2>/dev/null || echo '(not configured)'", auto_die => 0);
  say $reg;
};

# ============================================================
#  Helpers
# ============================================================

sub _report_gpus {
  my ($gpus) = @_;
  if ($gpus->{nvidia} && @{$gpus->{nvidia}}) {
    my @compute = grep { $_->{compute} } @{$gpus->{nvidia}};
    if (@compute) {
      say "  Found " . scalar(@compute) . " compute-capable NVIDIA GPU(s):";
      say "    - $_->{name}" for @compute;
    }
  } else {
    say "  No NVIDIA GPU detected — continuing without GPU support";
  }
}

sub _untaint_control_plane {
  say "Removing control plane taints (single-node)...";
  my $kubectl = '/var/lib/rancher/rke2/bin/kubectl';
  my $kc = '/etc/rancher/rke2/rke2.yaml';

  run "timeout 60 bash -c 'while ! $kubectl --kubeconfig=$kc get nodes 2>/dev/null; do sleep 2; done'",
    auto_die => 0;

  my $node = run "$kubectl --kubeconfig=$kc get nodes -o jsonpath='{.items[0].metadata.name}'",
    auto_die => 0;
  chomp $node;
  return unless $node;

  run "$kubectl --kubeconfig=$kc taint nodes $node node-role.kubernetes.io/control-plane:NoSchedule- 2>/dev/null || true",
    auto_die => 0;
  run "$kubectl --kubeconfig=$kc taint nodes $node node-role.kubernetes.io/master:NoSchedule- 2>/dev/null || true",
    auto_die => 0;

  say "  Untainted: $node";
}

1;
