# Example: Deploy RKE2 + GPU on a Hetzner bare-metal server via SSH
#
# Usage:
#   rex -f eg/hetzner-gpu-rke2.Rexfile -H <IP> deploy_single
#
# Prerequisites:
#   - Hetzner dedicated/bare-metal server with Debian installed
#   - SSH root access (key-based)
#   - NVIDIA GPU in the server
#   - Rex::GPU and Rex::Rancher installed
#
# This sets up a single-node RKE2 cluster with:
#   - Node preparation (hostname, NTP, sysctl, swap off)
#   - NVIDIA GPU drivers + container toolkit
#   - RKE2 control plane (Cilium CNI, no kube-proxy)
#   - Control plane untainted so workloads can run on it

use Rex -feature => ['1.4'];
use Rex::Commands::Run;
use Rex::Commands::File;
use Rex::Commands::Fs;

use Rex::Rancher::Node;
use Rex::Rancher::Server;
use Rex::Rancher::Cilium;
use Rex::GPU;

# --- Configuration ---

# Change these to match your setup
my $HOSTNAME     = $ENV{RKE2_HOSTNAME}     || 'gpu-01';
my $DOMAIN       = $ENV{RKE2_DOMAIN}       || 'k8s.example.com';
my $TIMEZONE     = $ENV{RKE2_TIMEZONE}     || 'Europe/Berlin';
my $TOKEN        = $ENV{RKE2_TOKEN}        || '';  # auto-generated if empty
my $TLS_SAN      = $ENV{RKE2_TLS_SAN}     || '';  # external IP/hostname

# --- Connection ---

set connection => 'OpenSSH';

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

user 'root';

# SSH key from environment or default
if ($ENV{REX_PRIVATE_KEY}) {
  private_key $ENV{REX_PRIVATE_KEY};
  public_key $ENV{REX_PUBLIC_KEY} if $ENV{REX_PUBLIC_KEY};
  key_auth;
}

# --- Tasks ---

desc "Full single-node deployment: node prep + GPU + RKE2 + Cilium";
task "deploy_single", sub {

  say "=== Step 1/4: Prepare node ===";
  prepare_node(
    hostname => $HOSTNAME,
    domain   => $DOMAIN,
    timezone => $TIMEZONE,
  );

  say "=== Step 2/4: GPU detection and driver setup ===";
  my $gpus = gpu_setup(containerd_config => 'rke2');

  if ($gpus->{nvidia} && @{$gpus->{nvidia}}) {
    my @compute = grep { $_->{compute} } @{$gpus->{nvidia}};
    say "  Found " . scalar(@compute) . " compute-capable NVIDIA GPU(s)";
  } else {
    say "  No NVIDIA GPU detected — continuing without GPU support";
  }

  say "=== Step 3/4: Install RKE2 server ===";
  install_server(
    distribution => 'rke2',
    ($TOKEN   ? (token   => $TOKEN)   : ()),
    ($TLS_SAN ? (tls_san => $TLS_SAN) : ()),
  );

  say "=== Step 4/4: Install Cilium CNI ===";
  install_cilium(distribution => 'rke2');

  # Untaint control plane for single-node setup
  _untaint_control_plane();

  say "";
  say "=== Deployment complete! ===";
  say "Fetch kubeconfig with:  rex -f eg/hetzner-gpu-rke2.Rexfile -H <IP> get_kubeconfig";
};

desc "Prepare node only (hostname, NTP, sysctl, kernel modules)";
task "prepare", sub {
  prepare_node(
    hostname => $HOSTNAME,
    domain   => $DOMAIN,
    timezone => $TIMEZONE,
  );
  say "Node preparation complete";
};

desc "Detect and install GPU drivers only";
task "gpu", sub {
  my $gpus = gpu_setup(containerd_config => 'rke2');

  if ($gpus->{nvidia} && @{$gpus->{nvidia}}) {
    my @compute = grep { $_->{compute} } @{$gpus->{nvidia}};
    say "Compute GPUs: " . scalar(@compute);
    for my $gpu (@compute) {
      say "  - $gpu->{name} (PCI class $gpu->{pci_class})";
    }
  } else {
    say "No compute-capable GPUs found";
  }
};

desc "Install RKE2 server only (assumes node is already prepared)";
task "rke2", sub {
  install_server(
    distribution => 'rke2',
    ($TOKEN   ? (token   => $TOKEN)   : ()),
    ($TLS_SAN ? (tls_san => $TLS_SAN) : ()),
  );
  install_cilium(distribution => 'rke2');
  _untaint_control_plane();
  say "RKE2 + Cilium installed";
};

desc "Fetch kubeconfig from server";
task "get_kubeconfig", sub {
  my $kubeconfig = get_kubeconfig('rke2');
  # Replace localhost with actual host
  my $host = connection->server;
  $kubeconfig =~ s/127\.0\.0\.1/$host/g;
  $kubeconfig =~ s/localhost/$host/g;
  # Skip TLS verify (cert uses short hostname)
  $kubeconfig =~ s/^\s*certificate-authority-data:.*\n//mg;
  $kubeconfig =~ s/(server: https:\/\/[^\n]+)/$1\n    insecure-skip-tls-verify: true/g;
  print $kubeconfig;
};

desc "Get node join token";
task "get_token", sub {
  my $token = get_token('rke2');
  say $token;
};

desc "Check GPU status on remote host";
task "gpu_status", sub {
  say "=== nvidia-smi ===";
  my $smi = run "nvidia-smi 2>&1", auto_die => 0;
  say $smi || "(not available)";

  say "\n=== Kernel modules ===";
  my $lsmod = run "lsmod | grep nvidia", auto_die => 0;
  say $lsmod || "(none loaded)";

  say "\n=== Container toolkit ===";
  my $ctk = run "nvidia-ctk --version 2>&1", auto_die => 0;
  say $ctk || "(not installed)";

  say "\n=== Containerd nvidia config ===";
  my $cfg = run "cat /etc/containerd/conf.d/99-nvidia.toml 2>/dev/null || echo '(not configured)'",
    auto_die => 0;
  say $cfg;
};

desc "Check cluster status";
task "status", sub {
  my $kubectl = '/var/lib/rancher/rke2/bin/kubectl';
  my $kubeconfig = '/etc/rancher/rke2/rke2.yaml';

  say "=== Nodes ===";
  run "$kubectl --kubeconfig=$kubeconfig get nodes -o wide", auto_die => 0;

  say "\n=== GPU Resources ===";
  my $gpus = run "$kubectl --kubeconfig=$kubeconfig get nodes -o jsonpath='{range .items[*]}{.metadata.name}{\"\\t\"}{.status.allocatable.nvidia\\.com/gpu}{\"\\n\"}{end}' 2>/dev/null",
    auto_die => 0;
  say $gpus || "(no GPU resources)";

  say "\n=== Cilium ===";
  run "cilium status 2>/dev/null || echo '(cilium CLI not installed)'",
    env => { KUBECONFIG => $kubeconfig },
    auto_die => 0;
};

# --- Helpers ---

sub _untaint_control_plane {
  say "Removing control plane taints for single-node setup...";

  my $kubectl = '/var/lib/rancher/rke2/bin/kubectl';
  my $kubeconfig = '/etc/rancher/rke2/rke2.yaml';

  # Wait for node registration
  run "timeout 60 bash -c 'while ! $kubectl --kubeconfig=$kubeconfig get nodes 2>/dev/null; do sleep 2; done'",
    auto_die => 0;

  my $node = run "$kubectl --kubeconfig=$kubeconfig get nodes -o jsonpath='{.items[0].metadata.name}'",
    auto_die => 0;
  chomp $node;

  return unless $node;

  run "$kubectl --kubeconfig=$kubeconfig taint nodes $node node-role.kubernetes.io/control-plane:NoSchedule- 2>/dev/null || true",
    auto_die => 0;
  run "$kubectl --kubeconfig=$kubeconfig taint nodes $node node-role.kubernetes.io/master:NoSchedule- 2>/dev/null || true",
    auto_die => 0;

  say "  Control plane untainted: $node";
}

1;
