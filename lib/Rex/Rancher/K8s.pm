# ABSTRACT: Kubernetes API operations for Rex::Rancher (device plugin, readiness)

package Rex::Rancher::K8s;
our $VERSION = '0.005';
use v5.14.4;
use warnings;

use JSON::MaybeXS qw( JSON );
use Kubernetes::REST::Kubeconfig;
use Rex::Logger;
use Rex::Rancher::Distribution;
use Scalar::Util qw( blessed );

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  control_plane_version
  deploy_amd_device_plugin
  deploy_amd_dra_driver
  deploy_amd_metrics_exporter
  deploy_amd_node_labeller
  deploy_nvidia_device_plugin
  remove_amd_device_plugin
  remove_amd_dra_driver
  remove_amd_metrics_exporter
  remove_amd_node_labeller
  wait_for_api
  untaint_node
);

use constant DEVICE_PLUGIN_VERSION => 'v0.17.0';

# ROCm's Kubernetes device plugin, release v1.31.0.11 (2026-09-14):
# https://github.com/ROCm/k8s-device-plugin/releases/tag/v1.31.0.11
# The DaemonSets are built after the manifests at that tag:
# https://github.com/ROCm/k8s-device-plugin/blob/v1.31.0.11/k8s-ds-amdgpu-dp.yaml
# https://github.com/ROCm/k8s-device-plugin/blob/v1.31.0.11/k8s-ds-amdgpu-labeller.yaml
# the device plugin's securityContext after the Helm chart of the same repo,
# amd-gpu-helm 0.22.0 (values.yaml securityContext):
# https://github.com/ROCm/k8s-device-plugin/releases/tag/amd-gpu-helm-0.22.0
# Images on Docker Hub, amd64 only: rocm/k8s-device-plugin:<version> and
# rocm/k8s-device-plugin:labeller-<version> (the manifests use them untagged
# and as labeller-latest).
use constant AMD_DEVICE_PLUGIN_VERSION => '1.31.0.11';

# The plugin's -resource_naming_strategy, as ParseStrategy in
# cmd/k8s-device-plugin/main.go at that tag knows it (anything else: exit 1).
# The flag came with release v1.31.0.7.
use constant AMD_RESOURCE_NAMINGS => qw( single mixed );

# ROCm's driver for Dynamic Resource Allocation of AMD GPUs, release v1.0.1
# (2026-07-22, commit 9eb4e2ea386e34581524b0110e24769654fcb8d2):
# https://github.com/ROCm/k8s-gpu-dra-driver/releases/tag/v1.0.1
# https://github.com/ROCm/k8s-gpu-dra-driver/commit/9eb4e2ea386e34581524b0110e24769654fcb8d2
# The objects are built after its Helm chart at that tag, as it renders with
# its default values:
# https://github.com/ROCm/k8s-gpu-dra-driver/tree/v1.0.1/helm-charts-k8s
# The tag carries a v, unlike the device plugin's. The chart in git names
# appVersion v0.1.0 (only the packaged chart of the release gets v1.0.1), a
# tag the image does not have, and the image's latest is v1.0.0, without
# v1.0.1's fix for amdgpu 6.19.14 and later: the image tag is always spelled
# out. docker.io/rocm/k8s-gpu-dra-driver is amd64 only.
use constant AMD_DRA_DRIVER_VERSION => 'v1.0.1';

# ROCm's device metrics exporter, release v1.5.3 (2026-10-07, commit
# 3b3c7f0bd5c0ec0bf00b9960d1b736258b7190eb):
# https://github.com/ROCm/device-metrics-exporter/releases/tag/v1.5.3
# https://github.com/ROCm/device-metrics-exporter/commit/3b3c7f0bd5c0ec0bf00b9960d1b736258b7190eb
# The objects are built after its Helm chart at that tag, as it renders with
# its default values:
# https://github.com/ROCm/device-metrics-exporter/tree/v1.5.3/helm-charts
# and the config.json after the packaged chart of the release, which alone
# carries it (git has no helm-charts/config.json; the Makefile's helm-lint
# writes it from example/config-gpu.json):
# https://rocm.github.io/device-metrics-exporter/charts/device-metrics-exporter-charts-v1.5.3.tgz
# (sha256 c653e9918a1f1d4d2021e775d3e2b3c953d686fcffd55f865e7562f5b76a7634, as
# the repository's index.yaml has it). The tag carries a v, as the chart's
# image tag does. docker.io/rocm/device-metrics-exporter is amd64 only.
use constant AMD_METRICS_EXPORTER_VERSION => 'v1.5.3';

=method wait_for_api(%opts)

Wait for the Kubernetes API server to become reachable by polling
C<list(Node)> via L<Kubernetes::REST>. Runs from the local machine — no
SSH connection to the cluster is needed.

Polls up to 60 times with a 5-second delay between attempts (5-minute
total timeout). Returns C<1> as soon as the API responds, or C<0> if it
does not respond within the timeout.

Required options:

=over

=item C<kubeconfig>

Path to the kubeconfig file saved locally. This file must have the
real server address (not C<127.0.0.1>) — L<Rex::Rancher/rancher_deploy_server>
patches the address automatically.

=back

  wait_for_api(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

=cut

sub wait_for_api {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";

  Rex::Logger::info("Waiting for Kubernetes API server...");

  for my $i (1..60) {
    my $up = eval {
      my $api = _api($kubeconfig);
      $api->list('Node');
      1;
    };
    if ($up) {
      Rex::Logger::info("  API server is up");
      return 1;
    }
    Rex::Logger::info("  Not responding yet, waiting... ($i/60)");
    sleep 5;
  }

  Rex::Logger::info("Kubernetes API server did not respond in time", "warn");
  return 0;
}

=method deploy_nvidia_device_plugin(%opts)

Deploy the NVIDIA Kubernetes device plugin DaemonSet to C<kube-system> and
wait for C<nvidia.com/gpu> capacity to appear on at least one node.

All operations run locally via L<Kubernetes::REST> — no C<kubectl> or SSH
to the cluster is needed.

The DaemonSet is created with:

=over

=item * C<runtimeClassName: nvidia> — uses the NVIDIA container runtime to
enumerate devices. With L<Rex::GPU>'s C<gpu_setup> it is registered by
L<Rex::GPU::NVIDIA/configure_containerd>; with C<gpu_setup =E<gt> 0> it must
come from the host (a preinstalled toolkit, see C<nvidia_runtime_path> in
L<Rex::Rancher/rancher_deploy_server>) or the GPU Operator's toolkit, which
RKE2/K3s pick up at service start along with the C<nvidia> RuntimeClass.

=item * C<priorityClassName: system-node-critical> — ensures the plugin
pod is scheduled even under resource pressure.

=item * A C<nvidia.com/gpu:NoSchedule> toleration — allows the pod to run
on nodes that still have the GPU taint.

=item * C<FAIL_ON_INIT_ERROR=false> — the plugin starts even if CDI or
driver initialisation fails, reporting partial GPU availability rather
than crash-looping.

=back

If the DaemonSet already exists it is updated (C<resourceVersion> is
fetched from the cluster before the update to satisfy the optimistic
concurrency requirement).

After applying, polls up to 24 times (2-minute timeout) for
C<nvidia.com/gpu> capacity to appear in any node's C<status.capacity>.
When it does not, a warning says so (no die), naming the API error of the
last attempt if that one failed (a 403, no connection).

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

Optional options:

=over

=item C<version>

NVIDIA device plugin image tag. Default: C<v0.17.0>.

=back

  deploy_nvidia_device_plugin(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

=cut

sub deploy_nvidia_device_plugin {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";
  my $version    = $opts{version} // DEVICE_PLUGIN_VERSION;

  Rex::Logger::info("Deploying NVIDIA device plugin $version...");

  my $api = _api($kubeconfig);

  _create_or_update($api, DaemonSet => _nvidia_device_plugin_daemonset_spec($version));

  Rex::Logger::info("  DaemonSet applied, waiting for GPU resources...");
  _wait_for_gpu_resource($api, 'nvidia.com/gpu');

  Rex::Logger::info("NVIDIA device plugin ready");
}

=method deploy_amd_device_plugin(%opts)

Deploy ROCm's Kubernetes device plugin for AMD GPUs
(L<https://github.com/ROCm/k8s-device-plugin>) as a DaemonSet to
C<kube-system> and wait for C<amd.com/gpu> capacity to appear on at least one
node. The counterpart of L</deploy_nvidia_device_plugin>, run the same way:
locally via L<Kubernetes::REST>, no C<kubectl> or SSH to the cluster.

The DaemonSet is upstream's C<k8s-ds-amdgpu-dp.yaml> of the pinned release,
with the image tag pinned instead of left out and the security context of
upstream's Helm chart (C<amd-gpu-helm> 0.22.0) instead of a privileged
container:

=over

=item * C<rocm/k8s-device-plugin:VERSION> with C<allowPrivilegeEscalation:
false> and all capabilities dropped, the kubelet's C<device-plugins>
directory and the host's C</sys> mounted.

=item * The image's start command spelled out: C<./k8s-device-plugin> in
C</root> with its C<-logtostderr=true -stderrthreshold=INFO -v=5>, followed
by C<-resource_naming_strategy=NAMING> (see C<resource_naming> below). The
image has no entrypoint, only that command, so arguments alone would replace
the program.

=item * C<nodeSelector> C<kubernetes.io/arch: amd64>, as upstream ships it
(the images are amd64 only).

=item * C<priorityClassName: system-node-critical> and a
C<CriticalAddonsOnly> toleration.

=back

B<It runs on every amd64 node>, and on one without the C<amdgpu> driver
loaded the plugin exits, so its pod there stays in C<CrashLoopBackOff>. On a
cluster with such nodes pass C<affinity> (below).

Not on the nodes of L</deploy_amd_dra_driver>: a node's AMD GPUs are
allocated either by this plugin or by DRA, not both (ROCm's device metrics
exporter,
L<https://github.com/ROCm/device-metrics-exporter/blob/v1.5.3/pkg/exporter/scheduler/k8s.go#L94-L97>);
keep the two apart with C<affinity>.

No runtime class, CDI or containerd change is involved: the plugin hands the
kubelet C</dev/kfd> and the GPU's C</dev/dri/cardN> and C</dev/dri/renderDN>
for the pods that request C<amd.com/gpu> (one resource per GPU; ROCm's
C<single> naming), and the container images bring their own ROCm. The host
needs the C<amdgpu> kernel driver (L<Rex::GPU>'s C<gpu_setup>, when it sets
up AMD GPUs; see L<Rex::Rancher/GPU hardware support>). The device nodes keep
their host owner and group (C<video>, C<render>), so a pod that does not run
as root needs those groups as C<supplementalGroups>, or the nodes need K3s'
and RKE2's C<nonroot-devices> option, which Rex::Rancher does not set.

Every object already in the cluster is updated (C<resourceVersion> is
fetched before the update), as in L</deploy_nvidia_device_plugin>. Then,
unless C<wait =E<gt> 0>, it polls up to 24 times (2-minute timeout) for
C<amd.com/gpu> capacity in any node's C<status.capacity> (with
C<resource_naming =E<gt> 'mixed'>, for any C<amd.com/> resource); when none
appears, a warning says so (no die), naming the API error of the last
attempt if that one failed.

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

Optional options:

=over

=item C<version>

Image tag of the device plugin, and of the node labeller as
C<labeller-VERSION>. Default: C<1.31.0.11>. The plugin's arguments need
1.31.0.7 or later: an older plugin does not know
C<-resource_naming_strategy> and exits.

=item C<resource_naming>

ROCm's resource naming strategy, C<single> or C<mixed>, passed as
C<-resource_naming_strategy>. Default: C<single>, every GPU an
C<amd.com/gpu> (the plugin exits on a node whose GPUs are partitioned in
different ways). C<mixed> advertises a partitioned GPU by its partition type,
C<amd.com/COMPUTE_MEMORY> such as C<amd.com/cpx_nps4> (an Instinct in CPX
mode), and one without partitions still as C<amd.com/gpu>; the wait then
takes any C<amd.com/> resource. Anything else dies before the cluster is
touched.

=item C<wait>

Default: C<1>, the wait for the GPU resource described above. With C<0> it
returns once the objects are applied: for a caller with a readiness check of
its own, or a cluster where no node is to offer C<amd.com/gpu> (its AMD GPUs
allocated through DRA, for instance), which would only wait out the two
minutes and warn.

=item C<node_labeller>

If true, also deploy upstream's node labeller exactly as
L</deploy_amd_node_labeller> does, with this call's C<version> and
C<affinity>. Default: C<0>; L<Rex::Rancher/rancher_deploy_server> deploys
the plugin without it. A labeller meant for other nodes than the plugin —
every AMD GPU node, the plugin only on some — is deployed with
L</deploy_amd_node_labeller> and its own C<affinity> instead.

=item C<affinity>

A pod C<affinity> (hashref, as in a pod spec) for the plugin's DaemonSet
(and, with C<node_labeller>, the labeller's), on top of the C<amd64>
C<nodeSelector>. Default: none, which is upstream's behaviour (every amd64
node, see above). With Node Feature Discovery in the cluster, the nodes with
an AMD GPU carry one of its PCI labels for vendor C<1002>; the terms of
C<nodeSelectorTerms> are alternatives:

  # 0300 a Radeon, 0302 a 3D controller, 0380 an APU's GPU (e.g. gfx1151),
  # 1200 an Instinct MI355X (other Instinct models unverified)
  my @terms = map {
    +{ matchExpressions => [{
      key      => "feature.node.kubernetes.io/pci-${_}_1002.present",
      operator => 'In',
      values   => ['true'],
    }] }
  } qw( 0300 0302 0380 1200 );

  deploy_amd_device_plugin(
    kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml",
    affinity   => { nodeAffinity => {
      requiredDuringSchedulingIgnoredDuringExecution => { nodeSelectorTerms => \@terms },
    } },
  );

B<These labels select the hardware, not the GPUs you set up>: the integrated
Radeon of a Ryzen CPU carries them too (a Hetzner AX42, with a Phoenix iGPU,
has C<pci-0300_1002.present>), and so the plugin lands on nodes whose GPU
was left alone (see C<gpu_amd_integrated> in L<Rex::Rancher>) and crash-loops
there. A node label of your own, set only on the nodes whose GPU you
accepted — by the step that joins them, say — selects more safely; one
setup uses C<ocp.internal/amd-gpu.present=true> for that:

  affinity => { nodeAffinity => {
    requiredDuringSchedulingIgnoredDuringExecution => { nodeSelectorTerms => [
      { matchExpressions => [{
        key => 'ocp.internal/amd-gpu.present', operator => 'In', values => ['true'],
      }] },
    ] },
  } },

Anything but a hashref dies before the cluster is touched.

=back

  deploy_amd_device_plugin(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

=cut

sub deploy_amd_device_plugin {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";
  my $version    = $opts{version} // AMD_DEVICE_PLUGIN_VERSION;
  my $naming     = _check_amd_resource_naming($opts{resource_naming});
  my $affinity   = _check_affinity($opts{affinity});
  my $wait       = $opts{wait} // 1;

  Rex::Logger::info("Deploying AMD GPU device plugin $version...");

  my $api = _api($kubeconfig);

  _create_or_update($api, DaemonSet => _amd_device_plugin_daemonset_spec($version, $naming, $affinity));
  if ($opts{node_labeller}) {
    Rex::Logger::info("  Deploying the AMD GPU node labeller...");
    _deploy_amd_node_labeller($api, $version, $affinity);
  }

  unless ($wait) {
    Rex::Logger::info("  DaemonSet applied, not waiting for GPU resources (wait => 0)");
    return;
  }

  # mixed: a partitioned GPU is amd.com/<compute>_<memory>, an unpartitioned
  # one still amd.com/gpu; the prefix takes either.
  Rex::Logger::info("  DaemonSet applied, waiting for GPU resources...");
  _wait_for_gpu_resource($api, $naming eq 'mixed' ? 'amd.com/' : 'amd.com/gpu');

  Rex::Logger::info("AMD GPU device plugin ready");
}

=method deploy_amd_node_labeller(%opts)

Deploy upstream's node labeller from ROCm's device plugin project
(C<k8s-ds-amdgpu-labeller.yaml> of the release
L</deploy_amd_device_plugin> pins) on its own, without the device plugin:
the ClusterRole C<cr-node-labeller> (C<get>, C<list>, C<watch>, C<update> on
nodes), the ClusterRoleBinding C<labeller>, the ServiceAccount
C<node-labeller-sa> and the DaemonSet C<amdgpu-labeller-daemonset> in
C<kube-system>. Each of its pods labels its node with the AMD GPUs' VRAM,
compute unit and SIMD count, device ID, family and product name. Objects
already in the cluster are updated, as for the plugin. There is no wait: the
labeller adds no capacity to wait for. Locally via L<Kubernetes::REST>, like
the rest of this module.

C<deploy_amd_device_plugin(node_labeller =E<gt> 1)> deploys the same objects
with the plugin's C<affinity>; this function is for a labeller that runs on
other nodes than the plugin.

The labeller runs privileged, with the host's C</dev> and C</sys>
(read-only) mounted, as upstream's manifest has it: it opens the GPU's
C</dev/dri/cardN>, and unprivileged the device cgroup refuses that
("operation not permitted"), leaving only the device ID labelled — seen on
an RKE2 1.36 node with a Ryzen AI Max (gfx1151). It does not ask for the
driver version label (nor does upstream's manifest); that one would stay
empty with the kernel's own C<amdgpu> driver anyway, which has no
C</sys/module/amdgpu/version>.

Like the plugin it runs on every amd64 node unless C<affinity> says
otherwise.

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

Optional options:

=over

=item C<version>

The release; the image is C<rocm/k8s-device-plugin:labeller-VERSION>.
Default: C<1.31.0.11>, as for the plugin.

=item C<affinity>

A pod C<affinity> (hashref, as in a pod spec) for the labeller's DaemonSet,
on top of the C<amd64> C<nodeSelector>; see L</deploy_amd_device_plugin> for
an example and why a label of your own selects more safely than Node Feature
Discovery's. Anything but a hashref dies before the cluster is touched.

=back

  # the labeller on every AMD GPU node, the plugin only where it allocates
  deploy_amd_node_labeller(
    kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml",
    affinity   => $every_amd_gpu_node,
  );
  deploy_amd_device_plugin(
    kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml",
    affinity   => $device_plugin_nodes,
  );

=cut

sub deploy_amd_node_labeller {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";
  my $version    = $opts{version} // AMD_DEVICE_PLUGIN_VERSION;
  my $affinity   = _check_affinity($opts{affinity});

  Rex::Logger::info("Deploying AMD GPU node labeller $version...");

  my $api = _api($kubeconfig);
  _deploy_amd_node_labeller($api, $version, $affinity);

  Rex::Logger::info("AMD GPU node labeller applied");
}

=method remove_amd_device_plugin(%opts)

Delete what L</deploy_amd_device_plugin> deploys for the plugin itself: the
DaemonSet C<amdgpu-device-plugin-daemonset> in C<kube-system> (its pods go
with it). The node labeller is left alone; see
L</remove_amd_node_labeller>.

Idempotent: an object that is not there (the API answers 404) is logged and
skipped. Any other error (a 403, no connection) dies. Locally via
L<Kubernetes::REST>.

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

  remove_amd_device_plugin(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

=cut

sub remove_amd_device_plugin {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";

  Rex::Logger::info("Removing AMD GPU device plugin...");

  # The name and namespace from the spec the deploy sends; version and naming
  # do not reach the metadata.
  my $api = _api($kubeconfig);
  _delete_if_present($api, DaemonSet =>
    _amd_device_plugin_daemonset_spec(AMD_DEVICE_PLUGIN_VERSION, 'single')->{metadata});
}

=method remove_amd_node_labeller(%opts)

Delete what L</deploy_amd_node_labeller> deploys, the DaemonSet first so no
labeller pod runs on without its rights: the DaemonSet
C<amdgpu-labeller-daemonset> and the ServiceAccount C<node-labeller-sa> in
C<kube-system>, then the ClusterRoleBinding C<labeller> and the ClusterRole
C<cr-node-labeller>. The labels it set on the nodes are not removed. The
device plugin is left alone.

Idempotent like L</remove_amd_device_plugin>: an object that is not there is
logged and skipped, any other error dies (and leaves the objects after it in
place).

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

  remove_amd_node_labeller(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

=cut

sub remove_amd_node_labeller {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";

  Rex::Logger::info("Removing AMD GPU node labeller...");

  # The objects the deploy sends, in reverse: DaemonSet, ServiceAccount,
  # ClusterRoleBinding, ClusterRole.
  my $api = _api($kubeconfig);
  _delete_if_present($api, $_->[0] => $_->[1]{metadata})
    for reverse _amd_node_labeller_specs(AMD_DEVICE_PLUGIN_VERSION);
}

=method deploy_amd_dra_driver(%opts)

Deploy ROCm's driver for Dynamic Resource Allocation (DRA) of AMD GPUs
(L<https://github.com/ROCm/k8s-gpu-dra-driver>), the objects upstream's
Helm chart installs with its default values, in this order: the
ServiceAccount C<k8s-gpu-dra-driver-service-account> in C<kube-system>, the
ClusterRole C<k8s-gpu-dra-driver-role> and its ClusterRoleBinding
C<k8s-gpu-dra-driver-role-binding>, the ValidatingAdmissionPolicy
C<resourceslices-policy-k8s-gpu-dra-driver> and its binding of the same
name, the DeviceClass C<gpu.amd.com> and the DaemonSet
C<k8s-gpu-dra-driver-kubeletplugin> in C<kube-system>. Objects already in
the cluster are updated, as for L</deploy_amd_device_plugin>. Locally via
L<Kubernetes::REST>, like the rest of this module.

Instead of a count such as C<amd.com/gpu> in the node's capacity, the plugin
on each node publishes that node's GPUs as devices in a ResourceSlice whose
C<spec.driver> is C<gpu.amd.com>, and a pod gets one through a
ResourceClaim of the DeviceClass C<gpu.amd.com>, as in upstream's
C<example/example.yaml>:

  apiVersion: resource.k8s.io/v1
  kind: ResourceClaimTemplate
  metadata:
    name: single-gpu
  spec:
    spec:
      devices:
        requests:
        - name: gpu
          exactly:
            deviceClassName: gpu.amd.com

with C<resourceClaims: [{name: gpu, resourceClaimTemplateName: single-gpu}]>
in the pod spec and C<resources: {claims: [{name: gpu}]}> on the container.

There is no wait. That a node's GPUs arrived shows as a ResourceSlice with
C<spec.driver> C<gpu.amd.com> and that node's C<spec.nodeName>
(C<kubectl get resourceslices>, or C<list('ResourceSlice')> through
L<Kubernetes::REST>).

The DaemonSet is the chart's:

=over

=item * C<docker.io/rocm/k8s-gpu-dra-driver:VERSION>, privileged, running
C<gpu-kubeletplugin> with the kubelet's C<plugins> and C<plugins_registry>
directories, C</var/run/cdi> (where it writes the CDI specs of the devices
it prepares) and the host's C</dev> and C</sys> mounted, and a gRPC
liveness probe on port 51515.

=item * An init container (C<docker.io/busybox:1.36>, privileged) that
waits until C</sys/class/kfd> and C</sys/module/amdgpu/drivers/> exist, that
is until the C<amdgpu> kernel driver is loaded.

=item * C<priorityClassName: system-node-critical>.

=back

What differs from the chart: the namespace is C<kube-system>, not
upstream's C<kube-amd-gpu>, so there is no namespace to create or remove;
the image tag is always given (the chart's own default from git is a tag the
image does not have, and C<latest> is v1.0.0); a C<nodeSelector>
C<kubernetes.io/arch: amd64>, as the image is amd64 only; and no Helm
labels. Not next to a Helm install of the chart: the DeviceClass has the
same name in every install, the other cluster-scoped objects those of a
release named C<k8s-gpu-dra-driver>, and this function would take them over.

B<It runs on every amd64 node>, and on one without the C<amdgpu> driver
loaded its pod stays in C<Init:0/1> for good: no crash loop and no error,
a pod that never starts. On a cluster with such nodes pass C<affinity>
(below).

B<DRA and the device plugin exclude each other per node>: ROCm's device
metrics exporter takes the GPU pods of a node to be served by one of the
two, not both
(L<https://github.com/ROCm/device-metrics-exporter/blob/v1.5.3/pkg/exporter/scheduler/k8s.go#L94-L97>),
and each would hand out the node's GPUs on its own. L</deploy_amd_device_plugin>
runs on every amd64 node unless its C<affinity> says otherwise: give the two
separate nodes.

What the cluster needs:

=over

=item * Kubernetes 1.34 or later: the DeviceClass is created in
C<resource.k8s.io/v1>. A cluster whose API does not serve it dies here,
saying so, before any object is created. (Upstream's chart falls back to
C<v1beta2> or C<v1beta1> on 1.32 and 1.33; this function does not.)

=item * containerd with CDI enabled, reading C</var/run/cdi>: the devices of
a claim reach the container as CDI devices. Rex::Rancher changes nothing
about containerd for this.

=item * The node name in the plugin's service account token (feature gate
C<ServiceAccountTokenPodNodeInfo>, on by default since Kubernetes 1.30 and
stable since 1.32, so on unless switched off): the admission policy lets the
plugin of a node change only that node's ResourceSlices, and without the
node name it refuses every change, so no GPU appears.

=back

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

Optional options:

=over

=item C<version>

Image tag of the driver, C<docker.io/rocm/k8s-gpu-dra-driver:VERSION>, with
its C<v>. Default: C<v1.0.1>. The objects stay those of v1.0.1's chart, and
the init container's C<busybox:1.36> stays as upstream has it.

=item C<affinity>

A pod C<affinity> (hashref, as in a pod spec) for the DaemonSet, on top of
the C<amd64> C<nodeSelector>; see L</deploy_amd_device_plugin> for an
example and why a node label of your own selects more safely than Node
Feature Discovery's. Default: none, every amd64 node, as upstream. Anything
but a hashref dies before the cluster is touched.

=back

  # DRA on the nodes labelled for it, the device plugin elsewhere
  deploy_amd_dra_driver(
    kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml",
    affinity   => $dra_nodes,
  );

=cut

sub deploy_amd_dra_driver {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";
  my $version    = $opts{version} // AMD_DRA_DRIVER_VERSION;
  my $affinity   = _check_affinity($opts{affinity});

  Rex::Logger::info("Deploying AMD GPU DRA driver $version...");

  my $api = _api($kubeconfig);
  die "The cluster does not serve DeviceClass in resource.k8s.io/v1:"
    . " the AMD GPU DRA driver needs Kubernetes 1.34 or later; nothing deployed\n"
    unless _serves_dra_v1($api);

  _create_or_update($api, @$_) for _amd_dra_driver_specs($version, $affinity);

  Rex::Logger::info("AMD GPU DRA driver applied; its GPUs show as ResourceSlices of driver gpu.amd.com");
}

=method remove_amd_dra_driver(%opts)

Delete what L</deploy_amd_dra_driver> deploys, in reverse order, the
DaemonSet first so no plugin runs on without its rights: the DaemonSet, the
DeviceClass C<gpu.amd.com>, the admission policy's binding and the policy,
the ClusterRoleBinding, the ClusterRole and the ServiceAccount.

Idempotent like L</remove_amd_device_plugin>: an object that is not there is
logged and skipped, any other error dies (and leaves the objects after it in
place). On a cluster that does not serve C<resource.k8s.io/v1> the
DeviceClass counts as not there. Locally via L<Kubernetes::REST>.

It does not remove:

=over

=item * The ResourceSlices the plugins published.

=item * What the plugin left on the nodes: the CDI specs in C</var/run/cdi>
(C<k8s.gpu.amd.com-gpu_*>), its checkpoint in
C</var/lib/kubelet/plugins/gpu.amd.com/> and its registration in
C</var/lib/kubelet/plugins_registry>.

=back

Pods whose claims are allocated keep their GPUs; a new claim of the
DeviceClass C<gpu.amd.com> is not allocated any more.

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

  remove_amd_dra_driver(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

=cut

sub remove_amd_dra_driver {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";

  Rex::Logger::info("Removing AMD GPU DRA driver...");

  # The objects the deploy sends, in reverse. A DeviceClass on a cluster
  # without resource.k8s.io/v1 is not asked for: there it is not there, and
  # asking would depend on how the client resolves a Kind the cluster lacks.
  my $api = _api($kubeconfig);
  my $dra = _serves_dra_v1($api);
  for (reverse _amd_dra_driver_specs(AMD_DRA_DRIVER_VERSION)) {
    my ($kind, $metadata) = ($_->[0], $_->[1]{metadata});
    if ($kind eq 'DeviceClass' && !$dra) {
      Rex::Logger::info("  $kind/$metadata->{name} not there"
        . " (the cluster does not serve resource.k8s.io/v1), nothing to remove");
      next;
    }
    _delete_if_present($api, $kind => $metadata);
  }
}

=method deploy_amd_metrics_exporter(%opts)

Deploy ROCm's device metrics exporter for AMD GPUs
(L<https://github.com/ROCm/device-metrics-exporter>), the objects upstream's
Helm chart installs with its default values, in this order: the
ServiceAccount, the ClusterRole and its ClusterRoleBinding, the ConfigMap
C<amdgpu-metrics-exporter-config> with the exporter's C<config.json>, the
DaemonSet and the Service. All but the ConfigMap are named
C<amdgpu-metrics-exporter>; ServiceAccount, ConfigMap, DaemonSet and Service
are in C<kube-system>. Objects already in the cluster are updated, as for
L</deploy_amd_device_plugin>. Locally via L<Kubernetes::REST>, like the rest
of this module.

Each of its pods serves the GPU metrics of its node in Prometheus format at
C</metrics> on port 5000, named with the prefix C<amd_>
(C<amd_gpu_edge_temperature>, ...), with the pod, namespace and container a
GPU is allocated to among the labels. The Service
C<amdgpu-metrics-exporter> (ClusterIP, port 5000, named C<http>, selecting
the pod label C<app: amdgpu-metrics-exporter>) has upstream's
C<internalTrafficPolicy: Local>: a client in the cluster reaches the
exporter of its own node only. To collect every node, scrape the pods (the
Service's endpoints); the pods also carry upstream's label
C<app.kubernetes.io/name: metrics-exporter>. There is no wait.

B<Upstream supports the exporter on Instinct MI2xx and MI3xx (ROCm 6.2 or
later) and on MI350P and Radeon AI (ROCm 7.13 or later), not on APUs such as
the Ryzen AI Max (Strix Halo) and not on consumer Radeons>: there metrics are
missing or stay 0
(L<https://github.com/ROCm/device-metrics-exporter/issues/281>,
L<https://github.com/ROCm/device-metrics-exporter/issues/353>; the platforms
as C<docs/index.md> at v1.5.3 lists them).

It allocates no GPUs and runs next to L</deploy_amd_device_plugin> or
L</deploy_amd_dra_driver>: it finds the pods of a node's GPUs through the
kubelet, whether the device plugin (C<amd.com/> resources) or the DRA driver
(claims of driver C<gpu.amd.com>, which upstream calls beta, Kubernetes 1.34
on) allocated them
(L<https://github.com/ROCm/device-metrics-exporter/blob/v1.5.3/docs/installation/kubernetes-helm.md#enabling-dra-beta-for-gpu-monitoring>).

The DaemonSet is the chart's:

=over

=item * C<docker.io/rocm/device-metrics-exporter:VERSION>, privileged, with
C<-monitor-gpu=true -monitor-nic=false> and C<METRICS_EXPORTER_PORT> 5000,
the chart's resources (requests 500m CPU and 512M memory, limits 2 CPUs and
4Gi), the host's C</dev> and C</sys> and the kubelet's
C</var/lib/kubelet/pod-resources> mounted, C</var/lib/amd-metrics-exporter>
(the exporter's health socket) and C</var/run/exporter> mounted from the
host and created there where missing, and the ConfigMap at C</etc/metrics/>.

=item * An init container (C<busybox:1.36>, privileged) that waits until
C</sys/class/kfd> and C</sys/module/amdgpu/drivers> exist, that is until the
C<amdgpu> kernel driver is loaded.

=item * A rolling update one node at a time; no priority class and no
tolerations, as the chart has none by default.

=back

The exporter labels its node C<metricsexporter.amd.com.gpu.ID.state> for
each GPU it finds unhealthy (by the config's thresholds), which is why its
ClusterRole may update nodes; it may also read pods and create events.

The ConfigMap holds the chart's C<config.json>: the metric prefix C<amd_>;
the chart's labels (GPU UUID, serial number, pod, namespace, container, card
model, driver version and more) with C<CLUSTER_NAME>
C<amdgpu-k8s-metrics-exporter>; health thresholds of 0 uncorrectable ECC
errors; profiler metrics off. Only the chart's list of fields is left out: at
v1.5.3 it names every field the exporter knows, and without a list the
exporter exports every field, so the metrics are the same; with another
C<version> its fields not in v1.5.3 are exported too. There is no option for
the config, and a change made to the ConfigMap by hand is overwritten by the
next run of this function.

What differs from the chart: the namespace is C<kube-system>, not
upstream's C<kube-amd-gpu>, so there is no namespace to create or remove;
the names carry no Helm release (above); the image tag is always given and
pulled only when missing (no C<imagePullPolicy: Always>); a C<nodeSelector>
C<kubernetes.io/arch: amd64>, as the image is amd64 only; no Helm labels;
the config without its list of fields (above). The chart's ServiceMonitor is
left out: the chart renders it only with C<serviceMonitor.enabled>, off by
default, and the Prometheus Operator's C<monitoring.coreos.com/v1> API in the
cluster. With a Prometheus Operator, a ServiceMonitor of your own for the
Service's port C<http> does that job.

Not next to a Helm install of the chart: that one's objects have other names
(its ServiceAccount the same name, in its own namespace), so both would run,
two exporters on each node reporting the same GPUs twice and both labelling
the node.

B<It runs on every amd64 node>, and on one without the C<amdgpu> driver
loaded its pod stays in C<Init:0/1> for good: no crash loop and no error,
a pod that never starts. On a cluster with such nodes pass C<affinity>
(below).

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

Optional options:

=over

=item C<version>

Image tag of the exporter, C<docker.io/rocm/device-metrics-exporter:VERSION>,
with its C<v>. Default: C<v1.5.3>. The objects and the config stay those of
v1.5.3's chart, and the init container's C<busybox:1.36> stays as upstream
has it.

=item C<affinity>

A pod C<affinity> (hashref, as in a pod spec) for the DaemonSet, on top of
the C<amd64> C<nodeSelector>; see L</deploy_amd_device_plugin> for an
example and why a node label of your own selects more safely than Node
Feature Discovery's. Default: none, every amd64 node, as upstream. Anything
but a hashref dies before the cluster is touched.

=back

  # the exporter on every node with an AMD GPU set up
  deploy_amd_metrics_exporter(
    kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml",
    affinity   => $amd_gpu_nodes,
  );

=cut

sub deploy_amd_metrics_exporter {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";
  my $version    = $opts{version} // AMD_METRICS_EXPORTER_VERSION;
  my $affinity   = _check_affinity($opts{affinity});

  Rex::Logger::info("Deploying AMD GPU metrics exporter $version...");

  my $api = _api($kubeconfig);
  _create_or_update($api, @$_) for _amd_metrics_exporter_specs($version, $affinity);

  Rex::Logger::info("AMD GPU metrics exporter applied; its pods serve /metrics on port 5000"
    . " (Service kube-system/amdgpu-metrics-exporter)");
}

=method remove_amd_metrics_exporter(%opts)

Delete what L</deploy_amd_metrics_exporter> deploys, in reverse order: the
Service, the DaemonSet (its pods go with it), the ConfigMap, the
ClusterRoleBinding, the ClusterRole and the ServiceAccount.

Idempotent like L</remove_amd_device_plugin>: an object that is not there is
logged and skipped, any other error dies (and leaves the objects after it in
place). Locally via L<Kubernetes::REST>.

It does not remove:

=over

=item * The node labels C<metricsexporter.amd.com.gpu.ID.state> the
exporter set for GPUs it found unhealthy.

=item * The host directories C</var/lib/amd-metrics-exporter> and
C</var/run/exporter>, which the DaemonSet created where they were missing,
and what the exporter left in them.

=back

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

  remove_amd_metrics_exporter(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

=cut

sub remove_amd_metrics_exporter {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";

  Rex::Logger::info("Removing AMD GPU metrics exporter...");

  # The objects the deploy sends, in reverse: Service, DaemonSet, ConfigMap,
  # ClusterRoleBinding, ClusterRole, ServiceAccount.
  my $api = _api($kubeconfig);
  _delete_if_present($api, $_->[0] => $_->[1]{metadata})
    for reverse _amd_metrics_exporter_specs(AMD_METRICS_EXPORTER_VERSION);
}

=method untaint_node(%opts)

Remove C<node-role.kubernetes.io/control-plane:NoSchedule> and
C<node-role.kubernetes.io/master:NoSchedule> taints from all nodes in the
cluster.

Kubernetes adds these taints to control-plane nodes to prevent general
workloads from being scheduled there. On single-node clusters (where the
control plane is also the only worker) these taints must be removed so that
pods can run.

Each node is fetched fresh before patching (to get the current
C<resourceVersion> for optimistic concurrency), and only patched if it
actually has one of the taints. Nodes that are already untainted are
skipped silently.

All operations run locally via L<Kubernetes::REST>.

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

  untaint_node(kubeconfig => "$ENV{HOME}/.kube/single-node.yaml");

=cut

sub untaint_node {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";

  Rex::Logger::info("Removing control-plane taints (single-node)...");

  my $api   = _api($kubeconfig);
  my $nodes = $api->list('Node');

  for my $node (@{ $nodes->items }) {
    my $name   = $node->metadata->name;
    my @taints = @{ $node->spec->taints // [] };
    my @keep   = grep {
      ($_->{key} // '') !~ /^node-role\.kubernetes\.io\/(control-plane|master)$/
    } @taints;

    next if @keep == @taints;  # nothing to remove

    my $fresh = $api->get('Node', $name);
    $fresh->spec->taints(\@keep);
    $api->update($fresh);
    Rex::Logger::info("  Untainted: $name");
  }
}

=method control_plane_version(%opts)

The Kubernetes version of the cluster's control plane, as the agent side of
the version skew policy needs it: the lowest C<kubeletVersion> among the
nodes labelled C<node-role.kubernetes.io/control-plane> (or C<master>) —
during a rolling server upgrade that is the server not yet upgraded — or,
without such nodes, the API server's C</version>. RKE2 and K3s report their
own release there (C<v1.30.4+rke2r1>). Nothing when neither gives a
version. Runs locally via L<Kubernetes::REST>; an API error dies.

Required options:

=over

=item C<kubeconfig>

Local path to the cluster kubeconfig.

=back

  my $version = control_plane_version(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

=cut

sub control_plane_version {
  my (%opts) = @_;
  my $kubeconfig = $opts{kubeconfig} or die "kubeconfig required\n";
  my $D = 'Rex::Rancher::Distribution';

  my $api = _api($kubeconfig);
  my @versions;
  for my $node (@{ $api->list('Node')->items }) {
    my $labels = $node->metadata->labels // {};
    next unless exists $labels->{'node-role.kubernetes.io/control-plane'}
      || exists $labels->{'node-role.kubernetes.io/master'};
    my $info = $node->status && $node->status->nodeInfo;
    my $version = $info && $info->kubeletVersion;
    my @parts = $D->parse_release($version);
    push @versions, $version if @parts;
  }
  my ($lowest) = sort { $D->compare_versions($a, $b) } @versions;
  return $lowest if defined $lowest;

  my $version = $api->cluster_version;
  my @parts = $D->parse_release($version);
  return @parts ? $version : ();
}

# ============================================================
#  Internal helpers
# ============================================================

sub _api {
  my ($kubeconfig) = @_;
  return Kubernetes::REST::Kubeconfig->new(
    kubeconfig_path => $kubeconfig,
  )->api;
}

# The nvidia-device-plugin DaemonSet as a plain hashref, split out verbatim
# from deploy_nvidia_device_plugin so its shape can be unit-tested offline —
# no cluster, no kubeconfig, no Kubernetes::REST client. $version is the only
# value that varies; the caller resolves the DEVICE_PLUGIN_VERSION default
# before calling. new_object(DaemonSet => %{ ... }) receives exactly the same
# named args as the previous inline literal.
sub _nvidia_device_plugin_daemonset_spec {
  my ($version) = @_;
  return {
    metadata => {
      name      => 'nvidia-device-plugin-daemonset',
      namespace => 'kube-system',
    },
    spec => {
      selector => {
        matchLabels => { name => 'nvidia-device-plugin-ds' },
      },
      updateStrategy => { type => 'RollingUpdate' },
      template => {
        metadata => {
          labels => { name => 'nvidia-device-plugin-ds' },
        },
        spec => {
          runtimeClassName  => 'nvidia',
          priorityClassName => 'system-node-critical',
          tolerations => [{
            key      => 'nvidia.com/gpu',
            operator => 'Exists',
            effect   => 'NoSchedule',
          }],
          containers => [{
            name  => 'nvidia-device-plugin-ctr',
            image => "nvcr.io/nvidia/k8s-device-plugin:$version",
            env   => [{
              name  => 'FAIL_ON_INIT_ERROR',
              value => 'false',
            }],
            securityContext => {
              allowPrivilegeEscalation => \0,
              capabilities            => { drop => ['ALL'] },
            },
            volumeMounts => [{
              name      => 'device-plugin',
              mountPath => '/var/lib/kubelet/device-plugins',
            }],
          }],
          volumes => [{
            name     => 'device-plugin',
            hostPath => { path => '/var/lib/kubelet/device-plugins' },
          }],
        },
      },
    },
  };
}

# ROCm's device plugin DaemonSet, upstream's k8s-ds-amdgpu-dp.yaml at the
# release AMD_DEVICE_PLUGIN_VERSION names, with four changes: the image
# carries the tag; the securityContext is the Helm chart's (amd-gpu-helm
# 0.22.0), not privileged: the plugin reads /sys, writes its socket to the
# kubelet's device-plugins directory and hands the kubelet the device nodes
# (/dev/kfd, /dev/dri/cardN, /dev/dri/renderDN) to put into the pods without
# opening them itself (the chart's extra /var/lib/amd-metrics-exporter mount
# is for its -pulse health checks, not used here) — a DaemonSet of this form
# (kubernetes-ocp's own, not this code) registered amd.com/gpu: 1 on synapse,
# RKE2 1.36.4 with a gfx1151, on 2026-10-31; the container's command and
# arguments are given, to pass -resource_naming_strategy=$naming; and
# $affinity, if given, is the pod affinity. A plain hashref like the NVIDIA
# one, so its shape is unit-tested offline. The caller resolves the defaults.
#
# The image (config of rocm/k8s-device-plugin:1.31.0.11, Dockerfile at the
# tag) has no Entrypoint, only Cmd ["./k8s-device-plugin", "-logtostderr=true",
# "-stderrthreshold=INFO", "-v=5"] with WorkingDir /root/: args alone would
# replace that Cmd and run "-resource_naming_strategy=..." as the program.
# So command is the binary, args carry the image's three log flags on, and
# workingDir is spelled out for the relative ./k8s-device-plugin, as
# upstream's own command form has it (k8s-ds-amdgpu-dp-health.yaml, the
# labeller) rather than resting on the image's WorkingDir.
sub _amd_device_plugin_daemonset_spec {
  my ($version, $naming, $affinity) = @_;
  return {
    metadata => {
      name      => 'amdgpu-device-plugin-daemonset',
      namespace => 'kube-system',
    },
    spec => {
      selector => {
        matchLabels => { name => 'amdgpu-dp-ds' },
      },
      template => {
        metadata => {
          labels => { name => 'amdgpu-dp-ds' },
        },
        spec => {
          restartPolicy     => 'Always',
          nodeSelector      => { 'kubernetes.io/arch' => 'amd64' },
          ( defined $affinity ? ( affinity => $affinity ) : () ),
          priorityClassName => 'system-node-critical',
          tolerations => [{
            key      => 'CriticalAddonsOnly',
            operator => 'Exists',
          }],
          containers => [{
            image      => "rocm/k8s-device-plugin:$version",
            name       => 'amdgpu-dp-cntr',
            workingDir => '/root',
            command    => ['./k8s-device-plugin'],
            args       => [
              qw( -logtostderr=true -stderrthreshold=INFO -v=5 ),
              "-resource_naming_strategy=$naming",
            ],
            securityContext => {
              allowPrivilegeEscalation => \0,
              capabilities             => { drop => ['ALL'] },
            },
            volumeMounts => [
              { name => 'dp',  mountPath => '/var/lib/kubelet/device-plugins' },
              { name => 'sys', mountPath => '/sys' },
            ],
          }],
          volumes => [
            { name => 'dp',  hostPath => { path => '/var/lib/kubelet/device-plugins' } },
            { name => 'sys', hostPath => { path => '/sys' } },
          ],
        },
      },
    },
  };
}

# The node labeller, upstream's k8s-ds-amdgpu-labeller.yaml at the same
# release: [ kind => spec ] pairs in upstream's order. It stays privileged,
# as there ("Needed for /dev"): kubernetes-ocp's live test on synapse (RKE2
# 1.36.4, gfx1151, 2026-10-31) ran it unprivileged, and it failed to open
# /dev/dri/card0 ("operation not permitted", the device cgroup) and labelled
# the device ID only; privileged it labelled cu-count, device-id, family,
# product-name, simd-count and vram. Changes: the image is labeller-$version,
# not labeller-latest, and so its imagePullPolicy Always is left out
# (Kubernetes' default for a tag other than latest is IfNotPresent; a pinned
# tag needs no pull on every pod start, which would tie each restart to
# Docker Hub); the ClusterRoleBinding loses upstream's namespace: default,
# which a cluster-scoped object does not have; $affinity, if given, is the
# pod affinity, as for the plugin.
sub _amd_node_labeller_specs {
  my ($version, $affinity) = @_;
  return (
    [ ClusterRole => {
      metadata => { name => 'cr-node-labeller' },
      rules    => [{
        apiGroups => [''],
        resources => ['nodes'],
        verbs     => [qw( watch get list update )],
      }],
    } ],
    [ ClusterRoleBinding => {
      metadata => { name => 'labeller' },
      roleRef  => {
        apiGroup => 'rbac.authorization.k8s.io',
        kind     => 'ClusterRole',
        name     => 'cr-node-labeller',
      },
      subjects => [{
        kind      => 'ServiceAccount',
        name      => 'node-labeller-sa',
        namespace => 'kube-system',
      }],
    } ],
    [ ServiceAccount => {
      metadata => { name => 'node-labeller-sa', namespace => 'kube-system' },
    } ],
    [ DaemonSet => {
      metadata => {
        name      => 'amdgpu-labeller-daemonset',
        namespace => 'kube-system',
      },
      spec => {
        selector => {
          matchLabels => { name => 'amdgpu-lr-ds' },
        },
        template => {
          metadata => {
            labels => { name => 'amdgpu-lr-ds' },
          },
          spec => {
            serviceAccountName => 'node-labeller-sa',
            nodeSelector       => { 'kubernetes.io/arch' => 'amd64' },
            ( defined $affinity ? ( affinity => $affinity ) : () ),
            priorityClassName  => 'system-node-critical',
            tolerations => [{
              key      => 'CriticalAddonsOnly',
              operator => 'Exists',
            }],
            containers => [{
              name       => 'amdgpu-lr-cntr',
              image      => "rocm/k8s-device-plugin:labeller-$version",
              workingDir => '/root',
              command    => ['./k8s-node-labeller'],
              args       => [qw( -vram -cu-count -simd-count -device-id -family -product-name )],
              env        => [{
                name      => 'DS_NODE_NAME',
                valueFrom => { fieldRef => { fieldPath => 'spec.nodeName' } },
              }],
              # Upstream: privileged is needed for /dev.
              securityContext => {
                privileged   => \1,
                capabilities => { drop => ['ALL'] },
              },
              volumeMounts => [
                { name => 'sys', mountPath => '/sys', readOnly => \1 },
                { name => 'dev', mountPath => '/dev' },
              ],
            }],
            volumes => [
              { name => 'sys', hostPath => { path => '/sys', type => 'Directory' } },
              { name => 'dev', hostPath => { path => '/dev', type => 'Directory' } },
            ],
          },
        },
      },
    } ],
  );
}

# ROCm's DRA driver: the objects its Helm chart at AMD_DRA_DRIVER_VERSION
# renders with the default values (serviceaccount.yaml, clusterrole.yaml,
# clusterrolebinding.yaml, validatingadmissionpolicy.yaml,
# validatingadmissionpolicybinding.yaml, deviceclass.yaml, kubeletplugin.yaml
# under helm-charts-k8s/templates), as [ kind => spec ] pairs in the order
# they are created: what an object refers to exists before it. The names are
# the chart's for a release named k8s-gpu-dra-driver, as its README installs
# it. Values that are the chart's defaults are kept as they are (the image
# pull policy, the probe, the environment, the paths, priorityClassName
# system-node-critical, no tolerations); the webhook and the OpenShift SCC
# are off by default there and left out here.
#
# What differs:
# - kube-system instead of the README's kube-amd-gpu, as for the device
#   plugin: no namespace object to create or to remove, and the priority
#   class system-node-critical (the chart's own) is at home there. The
#   admission policy's user follows the namespace and the ServiceAccount.
# - The image tag is $version, never the chart's appVersion (v0.1.0 in git,
#   a tag that does not exist); the init image docker.io/busybox:1.36 stays.
# - nodeSelector kubernetes.io/arch amd64, as the image is amd64 only (the
#   chart has none); $affinity, if given, is the pod affinity.
# - No Helm labels (helm.sh/chart, app.kubernetes.io/managed-by: Helm):
#   Helm does not manage these objects. app.kubernetes.io/version is
#   $version, the image the DaemonSet runs.
# - No metadata.namespace on the ClusterRole and the ClusterRoleBinding,
#   which the chart gives them and which cluster-scoped objects do not have.
# - The chart's empty pod securityContext and container resources ({}) are
#   left out: the API server stores the same empty objects without them.
#
# The selector is fixed and carries no version: a DaemonSet's selector cannot
# change, and an update with another one would be refused.
#
# The admission policy names resourceslices in v1beta1, as the chart does;
# whether it also applies to the plugin's writes through v1 (matchPolicy
# Equivalent, if the cluster still serves v1beta1) is upstream's matter.
sub _amd_dra_driver_specs {
  my ($version, $affinity) = @_;
  my $namespace = 'kube-system';
  my $name      = 'k8s-gpu-dra-driver';
  my $sa        = "$name-service-account";
  my $role      = "$name-role";
  my $policy    = "resourceslices-policy-$name";
  my %selector  = (
    'app.kubernetes.io/name'      => $name,
    'app.kubernetes.io/instance'  => $name,
    'app.kubernetes.io/component' => 'kubeletplugin',
  );
  my %labels = (
    'app.kubernetes.io/name'     => $name,
    'app.kubernetes.io/instance' => $name,
    'app.kubernetes.io/version'  => $version,
  );
  my $cdi       = '/var/run/cdi';
  my $registrar = '/var/lib/kubelet/plugins_registry';
  my $plugins   = '/var/lib/kubelet/plugins';
  my $health    = 51515;

  return (
    [ ServiceAccount => {
      metadata => { name => $sa, namespace => $namespace, labels => { %labels } },
    } ],
    [ ClusterRole => {
      metadata => { name => $role },
      rules    => [
        { apiGroups => ['resource.k8s.io'], resources => ['resourceclaims'], verbs => ['get'] },
        { apiGroups => [''],                resources => ['nodes'],          verbs => ['get'] },
        { apiGroups => ['resource.k8s.io'], resources => ['resourceslices'],
          verbs     => [qw( get list watch create update patch delete )] },
      ],
    } ],
    [ ClusterRoleBinding => {
      metadata => { name => "$role-binding" },
      subjects => [{ kind => 'ServiceAccount', name => $sa, namespace => $namespace }],
      roleRef  => {
        kind     => 'ClusterRole',
        name     => $role,
        apiGroup => 'rbac.authorization.k8s.io',
      },
    } ],
    # The plugin of a node may change only that node's ResourceSlices. The
    # chart's folded (>-) expressions as one line each.
    [ ValidatingAdmissionPolicy => {
      metadata => { name => $policy },
      spec     => {
        failurePolicy    => 'Fail',
        matchConstraints => {
          resourceRules => [{
            apiGroups   => ['resource.k8s.io'],
            apiVersions => ['v1beta1'],
            operations  => [qw( CREATE UPDATE DELETE )],
            resources   => ['resourceslices'],
          }],
        },
        matchConditions => [{
          name       => 'isRestrictedUser',
          expression => 'request.userInfo.username == "system:serviceaccount:'.$namespace.':'.$sa.'"',
        }],
        variables => [
          { name       => 'userNodeName',
            expression => q{request.userInfo.extra[?'authentication.kubernetes.io/node-name'][0].orValue('')} },
          { name       => 'objectNodeName',
            expression => q{(request.operation == "DELETE" ? oldObject : object).spec.?nodeName.orValue("")} },
        ],
        validations => [
          { expression => 'variables.userNodeName != ""',
            message    => 'no node association found for user, this user must run in a pod on a node'
              .' and ServiceAccountTokenPodNodeInfo must be enabled' },
          { expression        => 'variables.userNodeName == variables.objectNodeName',
            messageExpression => q{"this user running on node '"+variables.userNodeName+"' may not modify " +}
              .q{ (variables.objectNodeName == "" ?"cluster resourceslices" : "resourceslices on node '"+variables.objectNodeName+"'")} },
        ],
      },
    } ],
    [ ValidatingAdmissionPolicyBinding => {
      metadata => { name => $policy },
      spec     => { policyName => $policy, validationActions => ['Deny'] },
    } ],
    [ DeviceClass => {
      metadata => { name => 'gpu.amd.com' },
      spec     => { selectors => [{ cel => { expression => q{device.driver == 'gpu.amd.com'} } }] },
    } ],
    [ DaemonSet => {
      metadata => {
        name      => "$name-kubeletplugin",
        namespace => $namespace,
        labels    => { %labels, 'app.kubernetes.io/component' => 'kubeletplugin' },
      },
      spec => {
        selector       => { matchLabels => { %selector } },
        updateStrategy => { type => 'RollingUpdate' },
        template       => {
          metadata => { labels => { %selector } },
          spec     => {
            priorityClassName  => 'system-node-critical',
            serviceAccountName => $sa,
            nodeSelector       => { 'kubernetes.io/arch' => 'amd64' },
            ( defined $affinity ? ( affinity => $affinity ) : () ),
            # Waits for the amdgpu driver, verbatim from the chart.
            initContainers => [{
              name    => 'driver-init',
              image   => 'docker.io/busybox:1.36',
              command => [ 'sh', '-c', 'while [ ! -d /sys/class/kfd ] || [ ! -d /sys/module/amdgpu/drivers/ ];'
                .q{ do echo 'amdgpu driver is not loaded'; sleep 2; done} ],
              securityContext => { privileged => \1 },
              volumeMounts    => [{ name => 'sys', mountPath => '/sys' }],
            }],
            containers => [{
              name            => 'plugin',
              securityContext => { privileged => \1 },
              image           => "docker.io/rocm/k8s-gpu-dra-driver:$version",
              imagePullPolicy => 'IfNotPresent',
              command         => ['gpu-kubeletplugin'],
              livenessProbe   => {
                grpc             => { port => $health, service => 'liveness' },
                failureThreshold => 3,
                periodSeconds    => 10,
              },
              env => [
                { name => 'CDI_ROOT',                         value => $cdi },
                { name => 'KUBELET_REGISTRAR_DIRECTORY_PATH', value => $registrar },
                { name => 'KUBELET_PLUGINS_DIRECTORY_PATH',   value => $plugins },
                { name => 'NODE_NAME', valueFrom => { fieldRef => { fieldPath => 'spec.nodeName' } } },
                { name => 'NAMESPACE', valueFrom => { fieldRef => { fieldPath => 'metadata.namespace' } } },
                { name => 'HEALTHCHECK_PORT',                 value => "$health" },
              ],
              volumeMounts => [
                { name => 'plugins-registry', mountPath => $registrar },
                { name => 'plugins',          mountPath => $plugins },
                { name => 'cdi',              mountPath => $cdi },
                { name => 'dev',              mountPath => '/dev' },
                { name => 'sys',              mountPath => '/sys' },
              ],
            }],
            volumes => [
              { name => 'plugins-registry', hostPath => { path => $registrar } },
              { name => 'plugins',          hostPath => { path => $plugins } },
              { name => 'cdi',              hostPath => { path => $cdi } },
              { name => 'dev',              hostPath => { path => '/dev' } },
              { name => 'sys',              hostPath => { path => '/sys' } },
            ],
          },
        },
      },
    } ],
  );
}

# ROCm's device metrics exporter: the objects its Helm chart at
# AMD_METRICS_EXPORTER_VERSION renders with the default values, the GPU
# branch (monitor.resources.gpu true, nic false, platform k8s, service type
# ClusterIP; metrics-exporter-rbac.yaml, configmap.yaml, daemonsets.yaml,
# metrics-exporter-service.yaml under helm-charts/templates), as
# [ kind => spec ] pairs in the order they are created: what an object
# refers to exists before it. Values that are the chart's defaults are kept
# as they are (the arguments, the environment, the port, the resources, the
# mounts and their hostPath types, the init container with its
# imagePullPolicy IfNotPresent, the securityContexts, hostNetwork false, the
# rolling update with maxUnavailable 1, internalTrafficPolicy Local); the
# chart sets no priority class, tolerations, nodeSelector or affinity by
# default. The ServiceMonitor is off by default and left out, and so are
# the NIC branch and the OpenShift SCC rule.
#
# What differs:
# - kube-system instead of the install docs' kube-amd-gpu, as for the DRA
#   driver: no namespace object to create or to remove.
# - Names without a Helm release: the ServiceAccount's, which the chart
#   fixes as amdgpu-metrics-exporter, for the DaemonSet, the ClusterRole and
#   its binding and the Service too, and amdgpu-metrics-exporter-config for
#   the ConfigMap. The pod label app is the chart's release-less one,
#   amdgpu-metrics-exporter (its DaemonSet already carries it); the chart's
#   selector and Service use the release's.
# - The image tag is $version; the init image busybox:1.36 stays, written
#   as the chart writes it. The exporter's imagePullPolicy Always is left
#   out, as for the node labeller: Kubernetes' default for a tag other than
#   latest is IfNotPresent, and Always would tie every pod start to Docker
#   Hub (some 330 MB) for a tag that does not move.
# - nodeSelector kubernetes.io/arch amd64, as the image is amd64 only (the
#   chart has none by default); $affinity, if given, is the pod affinity.
# - No Helm labels: not helm.sh/chart and app.kubernetes.io/managed-by
#   (Helm does not manage these objects), and not app.kubernetes.io/name
#   and app.kubernetes.io/instance either, which name the chart
#   (device-metrics-exporter-charts) and the Helm release, neither of which
#   exists here. (The DRA driver keeps those two: its selector is made of
#   them, and its release is named as its objects are.)
#   app.kubernetes.io/version is $version, the image the DaemonSet runs.
#   The pod label app.kubernetes.io/name: metrics-exporter is no Helm label
#   and stays: the exporter knows it (DefaultExporterLabel in
#   pkg/exporter/globals/constants.go) and upstream's docs select its pods
#   by it.
# - The config.json is built here, without GPUConfig.Fields
#   (_amd_metrics_exporter_config).
#
# The selector is fixed and carries no version: a DaemonSet's selector cannot
# change, and an update with another one would be refused.
sub _amd_metrics_exporter_specs {
  my ($version, $affinity) = @_;
  my $namespace = 'kube-system';
  my $name      = 'amdgpu-metrics-exporter';
  my $config    = "$name-config";
  my $port      = 5000;
  my %app       = ( app => $name );
  my %labels    = (
    'app.kubernetes.io/component' => 'amd-gpu',
    'app.kubernetes.io/part-of'   => 'amd-gpu',
    'app.kubernetes.io/version'   => $version,
  );
  # The chart's literal block (|), its continuation line and final newline
  # included.
  my $driver_wait = join '', map { "$_\n" }
    'echo "Checking for AMD GPU driver..."',
    'while [ ! -d /host-sys/class/kfd ] || \\',
    '      [ ! -d /host-sys/module/amdgpu/drivers ]; do',
    '  echo "amdgpu driver is not loaded"',
    '  sleep 2',
    'done';

  return (
    [ ServiceAccount => {
      metadata => { name => $name, namespace => $namespace, labels => { %labels } },
    } ],
    [ ClusterRole => {
      metadata => { name => $name, labels => { %labels } },
      rules    => [
        { apiGroups => [''], resources => ['pods'],   verbs => [qw( watch get list )] },
        { apiGroups => [''], resources => ['nodes'],  verbs => [qw( watch get list update )] },
        { apiGroups => [''], resources => ['events'], verbs => ['create'] },
      ],
    } ],
    [ ClusterRoleBinding => {
      metadata => { name => $name, labels => { %labels } },
      roleRef  => {
        apiGroup => 'rbac.authorization.k8s.io',
        kind     => 'ClusterRole',
        name     => $name,
      },
      subjects => [{ kind => 'ServiceAccount', name => $name, namespace => $namespace }],
    } ],
    [ ConfigMap => {
      metadata => { name => $config, namespace => $namespace },
      data     => {
        'config.json' => JSON::MaybeXS->new( canonical => 1, convert_blessed => 1 )
          ->encode( _amd_metrics_exporter_config() ),
      },
    } ],
    [ DaemonSet => {
      metadata => {
        name      => $name,
        namespace => $namespace,
        labels    => { %app, 'app.kubernetes.io/version' => $version },
      },
      spec => {
        updateStrategy => {
          type          => 'RollingUpdate',
          rollingUpdate => { maxUnavailable => 1 },
        },
        selector => { matchLabels => { %app } },
        template => {
          metadata => { labels => { %app, 'app.kubernetes.io/name' => 'metrics-exporter' } },
          spec     => {
            hostNetwork        => \0,
            serviceAccountName => $name,
            nodeSelector       => { 'kubernetes.io/arch' => 'amd64' },
            ( defined $affinity ? ( affinity => $affinity ) : () ),
            initContainers => [{
              command         => [ 'sh', '-c', $driver_wait ],
              image           => 'busybox:1.36',
              imagePullPolicy => 'IfNotPresent',
              name            => 'driver-init',
              securityContext => { privileged => \1 },
              volumeMounts    => [{ mountPath => '/host-sys', name => 'sys-volume' }],
            }],
            containers => [{
              name  => "$name-container",
              image => "docker.io/rocm/device-metrics-exporter:$version",
              args  => [qw( -monitor-gpu=true -monitor-nic=false )],
              env   => [
                { name => 'NODE_NAME', valueFrom => { fieldRef => { fieldPath => 'spec.nodeName' } } },
                { name => 'METRICS_EXPORTER_PORT', value => "$port" },
              ],
              ports           => [{ containerPort => $port, protocol => 'TCP' }],
              securityContext => { privileged => \1 },
              resources       => {
                limits   => { cpu => '2',    memory => '4Gi' },
                requests => { cpu => '500m', memory => '512M' },
              },
              volumeMounts => [
                { mountPath => '/dev',                           name => 'dev-volume' },
                { mountPath => '/sys',                           name => 'sys-volume' },
                { mountPath => '/var/lib/kubelet/pod-resources', name => 'pod-resources' },
                { mountPath => '/var/lib/amd-metrics-exporter',  name => 'exporter-health-grpc-volume' },
                { mountPath => '/var/run/exporter',              name => 'exporter-slurm-job' },
                { name => 'metrics-config-volume', mountPath => '/etc/metrics/' },
              ],
              workingDir => '/root',
            }],
            volumes => [
              { hostPath => { path => '/dev', type => 'Directory' }, name => 'dev-volume' },
              { hostPath => { path => '/sys', type => 'Directory' }, name => 'sys-volume' },
              { hostPath => { path => '/var/lib/kubelet/pod-resources', type => 'Directory' },
                name     => 'pod-resources' },
              { hostPath => { path => '/var/lib/amd-metrics-exporter', type => 'DirectoryOrCreate' },
                name     => 'exporter-health-grpc-volume' },
              { hostPath => { path => '/var/run/exporter', type => 'DirectoryOrCreate' },
                name     => 'exporter-slurm-job' },
              { name => 'metrics-config-volume', configMap => { name => $config } },
            ],
          },
        },
      },
    } ],
    [ Service => {
      metadata => { name => $name, namespace => $namespace, labels => { %app } },
      spec     => {
        selector              => { %app },
        internalTrafficPolicy => 'Local',
        type                  => 'ClusterIP',
        ports                 => [{ protocol => 'TCP', name => 'http', port => $port }],
      },
    } ],
  );
}

# The exporter's config.json as the packaged chart of
# AMD_METRICS_EXPORTER_VERSION carries it -- example/config-gpu.json at the
# tag through the Makefile's jq 'del(.ServerPort, .GPUConfig.ExtraPodLabels)'
# -- with the same keys and values, numbers as numbers, minus
# GPUConfig.Fields. Encoded canonically by the caller, so the same config is
# the same string and a re-run changes nothing in the ConfigMap.
#
# Fields is left out as an equivalent at v1.5.3, chosen here: the chart lists
# 194 fields, exactly the values of the enum GPUMetricField in
# pkg/exporter/proto/exporterconfig.proto at the tag, and an empty or missing
# Fields switches every value of that enum on (initFieldConfig in
# pkg/amdgpu/gpuagent/gpuagent_gpu_metrics.go, the only reader of Fields;
# the collector filter of buildGPUGetFilter follows the same switches;
# docs/configuration/configmap.md: "An empty Fields (the default) exports
# everything"). The same metrics, without 194 lines here. A version bump
# with fields new to it therefore exports those too, where the chart's list
# would leave them out until the chart named them.
#
# Kept, though not the exporter's defaults: MetricsFieldPrefix amd_ (without
# it the metrics are gpu_edge_temperature, not amd_gpu_edge_temperature),
# the Labels, HealthThresholds, CustomLabels' CLUSTER_NAME, ProfilerMetrics
# with the example's placeholder hostname1 (a node of that name gets the
# profiler off, which all already says) and ProfilerConfig.
sub _amd_metrics_exporter_config {
  my $ecc = 'GPU_ECC_UNCORRECT_';
  return {
    CommonConfig => {
      MetricsFieldPrefix => 'amd_',
      HealthService      => { Enable => JSON()->true, PollingRate => '30s' },
      Logging            => { Level => 'info', MaxFileSizeMB => 10, MaxBackups => 3, MaxAgeDays => 7 },
      Debug              => { EnableAPI => JSON()->false },
    },
    GPUConfig => {
      Labels => [qw(
        GPU_UUID SERIAL_NUMBER GPU_ID POD POD_UUID NAMESPACE CONTAINER JOB_ID JOB_USER
        JOB_PARTITION CLUSTER_NAME CARD_SERIES CARD_MODEL CARD_VENDOR DRIVER_VERSION
        VBIOS_VERSION HOSTNAME GPU_PARTITION_ID GPU_COMPUTE_PARTITION_TYPE
        GPU_MEMORY_PARTITION_TYPE KFD_PROCESS_ID DEPLOYMENT_MODE
      )],
      HealthThresholds => {
        ( map { ( $ecc . $_ => 0 ) } qw(
          SDMA GFX MMHUB ATHUB BIF HDP XGMI_WAFL DF SMN SEM MP0 MP1 FUSE UMC MCA VCN JPEG IH MPIO
        ) ),
        GPU_CPER_MAX_AGE => '',
      },
      CustomLabels    => { CLUSTER_NAME => 'amdgpu-k8s-metrics-exporter' },
      ProfilerMetrics => { all => JSON()->false, hostname1 => JSON()->false },
      ProfilerConfig  => { SamplingInterval => 1000, PtlDelay => 0 },
    },
  };
}

# Whether the cluster serves DeviceClass in resource.k8s.io/v1 (Kubernetes
# 1.34 on), asked before any DRA object is created. Kubernetes::REST (with
# resource_map_from_cluster, the default _api keeps) builds the map behind
# new_object from the cluster's aggregated discovery: a Kind maps to the
# IO::K8s class of the version its group prefers, and only Kinds the cluster
# serves and IO::K8s ships are in it. Without resource.k8s.io there is no
# DeviceClass in it, and new_object('DeviceClass') dies with "Can't locate
# IO/K8s/DeviceClass.pm" -- after the ServiceAccount, the RBAC and the
# policy are created; on 1.32 or 1.33 it maps to the v1beta2 or v1beta1
# class. fetch_resource_map is that map, from the same cached discovery
# new_object then uses (no second fetch); where discovery cannot be read it
# dies ("Could not load resource map from cluster: ..."), where new_object
# would fall back to IO::K8s's built-in map with a warning.
sub _serves_dra_v1 {
  my ($api) = @_;
  my $class = $api->fetch_resource_map->{DeviceClass} // '';
  return $class =~ /(?:\A|::)Api::Resource::V1::DeviceClass\z/ ? 1 : 0;
}

# Create the $kind object $spec describes or, where it already exists, update
# it with the cluster's resourceVersion (optimistic concurrency). Namespaced
# or cluster-scoped as $spec's metadata has it.
sub _create_or_update {
  my ($api, $kind, $spec) = @_;
  my $obj = $api->new_object($kind => %$spec);

  return $obj if eval { $api->create($obj); 1 };
  my $err = $@;
  die $err unless $err =~ /already exist/i;

  Rex::Logger::info("  $kind already exists, updating...");
  my $namespace = $spec->{metadata}{namespace};
  my $existing  = $api->get($kind, $spec->{metadata}{name},
    ( defined $namespace ? ( namespace => $namespace ) : () ));
  $obj->metadata->resourceVersion($existing->metadata->resourceVersion);
  $api->update($obj);
  return $obj;
}

# Delete the $kind object $metadata names (in its namespace, if it has one),
# with the API's default propagation, which for apps/v1 (the DaemonSets) is
# Background: the pods go too, after the call returns.
# Not there is fine — removal is idempotent — and only logged: Kubernetes::REST
# (1.109 on) dies with a Kubernetes::REST::APIError for an HTTP error status,
# and a 404 is its is_not_found. Anything else (a 403, a 599 for no
# connection, a croak) dies. True if it deleted something.
sub _delete_if_present {
  my ($api, $kind, $metadata) = @_;
  my ($name, $namespace) = @{$metadata}{qw( name namespace )};

  if (eval {
    $api->delete($kind, $name, ( defined $namespace ? ( namespace => $namespace ) : () ));
    1;
  }) {
    Rex::Logger::info("  Removed $kind/$name");
    return 1;
  }
  my $err = $@;
  die $err unless blessed $err
    && $err->isa('Kubernetes::REST::APIError') && $err->is_not_found;

  Rex::Logger::info("  $kind/$name not there, nothing to remove");
  return 0;
}

# The labeller's four objects, for deploy_amd_node_labeller and
# deploy_amd_device_plugin(node_labeller => 1) alike.
sub _deploy_amd_node_labeller {
  my ($api, $version, $affinity) = @_;
  _create_or_update($api, @$_) for _amd_node_labeller_specs($version, $affinity);
}

# resource_naming as given, or single; anything ROCm's plugin does not know
# dies here, before the cluster is touched.
sub _check_amd_resource_naming {
  my ($naming) = @_;
  return 'single' unless defined $naming;
  return $naming if !ref $naming && grep { $_ eq $naming } AMD_RESOURCE_NAMINGS;
  die "resource_naming must be one of " . join(', ', AMD_RESOURCE_NAMINGS)
    . ", not '$naming'\n";
}

# affinity as given (undef: none); anything but a hashref dies here.
sub _check_affinity {
  my ($affinity) = @_;
  die "affinity must be a hash reference (a pod spec's affinity)\n"
    if defined $affinity && ref $affinity ne 'HASH';
  return $affinity;
}

# Poll for $resource (nvidia.com/gpu, amd.com/gpu) in any node's capacity.
# A $resource ending in / is a prefix: any resource under it counts
# (amd.com/ for ROCm's mixed naming, amd.com/gpu or amd.com/cpx_nps4).
sub _wait_for_gpu_resource {
  my ($api, $resource) = @_;
  my $prefix = $resource =~ m{/\z};
  my $label  = $prefix ? "$resource*" : $resource;

  # The error of the last attempt, if it failed: a 403 or a dead API reads
  # the same as a plugin that has not reported yet until the warning names it.
  my $last_error;
  for my $i (1..24) {
    my $found = eval {
      my $nodes = $api->list('Node');
      for my $node (@{ $nodes->items }) {
        my $cap = $node->status->capacity or next;
        my @names = $prefix
          ? sort grep { index($_, $resource) == 0 } keys %$cap
          : ($resource);
        for my $name (@names) {
          next unless $cap->{$name} && $cap->{$name} > 0;
          Rex::Logger::info("  [ok] $name: "
            . $cap->{$name} . " on "
            . $node->metadata->name);
          return 1;  # returns 1 as value of the eval block
        }
      }
      0;
    };
    $last_error = $@ ? ( $@ =~ s/\s+\z//r ) : undef;
    return 1 if $found;  # exit the sub once GPU capacity is confirmed
    Rex::Logger::info("  No GPU capacity yet ($i/24), waiting...");
    sleep 5;
  }

  Rex::Logger::info("  $label resource did not appear — check device plugin"
    . ( defined $last_error ? " (last API error: $last_error)" : '' ), "warn");
  return 0;
}

1;

=head1 SYNOPSIS

  use Rex::Rancher::K8s;

  # Wait for API to become available after cluster installation
  wait_for_api(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

  # Deploy NVIDIA device plugin and wait for gpu resource to appear
  deploy_nvidia_device_plugin(
    kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml",
    version    => 'v0.17.0',
  );

  # Deploy ROCm's device plugin for AMD GPUs, with its node labeller,
  # and wait for amd.com/gpu to appear
  deploy_amd_device_plugin(
    kubeconfig    => "$ENV{HOME}/.kube/mycluster.yaml",
    node_labeller => 1,
  );

  # Or each on its own nodes: the labeller on every AMD GPU node, the
  # plugin with mixed resource naming and no wait on some of them
  deploy_amd_node_labeller(
    kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml",
    affinity   => $amd_gpu_nodes,
  );
  deploy_amd_device_plugin(
    kubeconfig      => "$ENV{HOME}/.kube/mycluster.yaml",
    affinity        => $device_plugin_nodes,
    resource_naming => 'mixed',
    wait            => 0,
  );

  # ROCm's DRA driver instead, on nodes of its own
  deploy_amd_dra_driver(
    kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml",
    affinity   => $dra_nodes,
  );

  # ROCm's metrics exporter on the AMD GPU nodes, next to either
  deploy_amd_metrics_exporter(
    kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml",
    affinity   => $amd_gpu_nodes,
  );

  # And take them out again
  remove_amd_device_plugin(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");
  remove_amd_node_labeller(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");
  remove_amd_dra_driver(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");
  remove_amd_metrics_exporter(kubeconfig => "$ENV{HOME}/.kube/mycluster.yaml");

  # Remove control-plane taints on a single-node cluster
  untaint_node(kubeconfig => "$ENV{HOME}/.kube/single.yaml");

=head1 DESCRIPTION

L<Rex::Rancher::K8s> provides Kubernetes API operations for L<Rex::Rancher>
using L<Kubernetes::REST> and L<IO::K8s>. All twelve public functions run
entirely on the B<local machine> against the cluster's HTTP API — no
C<kubectl> binary is required anywhere, and no SSH connection to the cluster
nodes is needed for these operations.

The module is used internally by L<Rex::Rancher/rancher_deploy_server> to:

=over

=item 1. Wait for the API server to respond after C<install_server> returns

=item 2. Deploy the NVIDIA device plugin, the AMD one, or both, when
C<gpu =E<gt> 1> (which one: L<Rex::Rancher/GPU hardware support>)

=back

L<Rex::Rancher::Agent/install_agent> uses L</control_plane_version> to keep
an agent from a newer minor version than the control plane.

It can also be used standalone for post-deploy operations such as removing
control-plane taints on single-node clusters, or deploying and removing the
AMD device plugin and node labeller on nodes of your choosing
(L</deploy_amd_node_labeller>, L</remove_amd_device_plugin>,
L</remove_amd_node_labeller>), ROCm's DRA driver for AMD GPUs
(L</deploy_amd_dra_driver>, L</remove_amd_dra_driver>) and ROCm's device
metrics exporter (L</deploy_amd_metrics_exporter>,
L</remove_amd_metrics_exporter>). L<Rex::Rancher>
re-exports only L</wait_for_api>, L</untaint_node> and the two
C<deploy_*_device_plugin> functions; the others come from
C<use Rex::Rancher::K8s>.

=head2 No kubectl required

All Kubernetes API calls are made via L<Kubernetes::REST>, which implements
the Kubernetes REST API client in pure Perl using L<IO::K8s> for object
serialization. The kubeconfig file is parsed by
C<Kubernetes::REST::Kubeconfig> to extract the cluster address and
credentials.

=head1 SEE ALSO

L<Rex::Rancher>, L<Rex::GPU>, L<Kubernetes::REST>, L<IO::K8s>

=cut
