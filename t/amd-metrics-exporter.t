use strict;
use warnings;
use Test::More;

# k103: deploy_amd_metrics_exporter puts ROCm's device-metrics-exporter v1.5.3
# into the cluster as its Helm chart at that tag renders with the default
# values (the GPU branch) -- ServiceAccount, ClusterRole, ClusterRoleBinding,
# ConfigMap with config.json, DaemonSet, Service; no ServiceMonitor -- with the
# documented changes: kube-system, names without a Helm release, the image tag
# pinned without imagePullPolicy Always, amd64 nodeSelector, no Helm labels,
# config.json without GPUConfig.Fields. remove_amd_metrics_exporter deletes
# the same objects in reverse, idempotently.
#
# Offline. The specs are compared with the chart's objects, rendered by hand
# from helm-charts/templates at v1.5.3 (no helm here) for a release named
# exporter, as upstream's install docs name it; the config.json under
# __DATA__ is the packaged chart's file, byte for byte. deploy and remove run
# through the real Kubernetes::REST client with only its IO faked, discovery
# included, so the resolution of the Kinds, the paths, and the APIError a
# 404/409/403 becomes are the installed client's own. That the image starts,
# that the exporter reads the config, finds the GPUs and serves metrics, and
# that the API server keeps the Service's clusterIP over an update are only
# shown live.

use IO::K8s;
use JSON::MaybeXS;
use Kubernetes::REST;
use Kubernetes::REST::HTTPResponse;
use Scalar::Util qw( blessed );
use YAML::PP;
use Rex::Rancher::K8s;

my ( @info, @warn );
{
  no warnings 'redefine';
  *Rex::Logger::info = sub { push @{ ( $_[1] // '' ) eq 'warn' ? \@warn : \@info }, $_[0] };
}

my $version = 'v1.5.3';
is( Rex::Rancher::K8s::AMD_METRICS_EXPORTER_VERSION(), $version, 'pinned release v1.5.3, with its v' );

# --- the chart's objects, rendered with the defaults --------------------------------
#
# Release exporter; helm install --namespace puts the namespaced ones there,
# the templates name no namespace. The init script keeps the template's
# indentation: a literal block (|) at 10 columns.

my $UPSTREAM = <<'YAML';
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: amdgpu-metrics-exporter
  labels:
    app.kubernetes.io/component: amd-gpu
    app.kubernetes.io/part-of: amd-gpu
    helm.sh/chart: device-metrics-exporter-charts-v1.5.3
    app.kubernetes.io/name: device-metrics-exporter-charts
    app.kubernetes.io/instance: exporter
    app.kubernetes.io/version: "v1.5.3"
    app.kubernetes.io/managed-by: Helm
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: exporter-device-metrics-exporter-charts-metrics-exporter
  labels:
    app.kubernetes.io/component: amd-gpu
    app.kubernetes.io/part-of: amd-gpu
    helm.sh/chart: device-metrics-exporter-charts-v1.5.3
    app.kubernetes.io/name: device-metrics-exporter-charts
    app.kubernetes.io/instance: exporter
    app.kubernetes.io/version: "v1.5.3"
    app.kubernetes.io/managed-by: Helm
rules:
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - watch
  - get
  - list
- apiGroups:
  - ""
  resources:
  - nodes
  verbs:
  - watch
  - get
  - list
  - update
- apiGroups:
  - ""
  resources:
  - events
  verbs:
  - create
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: exporter-device-metrics-exporter-charts-metrics-exporter
  labels:
    app.kubernetes.io/component: amd-gpu
    app.kubernetes.io/part-of: amd-gpu
    helm.sh/chart: device-metrics-exporter-charts-v1.5.3
    app.kubernetes.io/name: device-metrics-exporter-charts
    app.kubernetes.io/instance: exporter
    app.kubernetes.io/version: "v1.5.3"
    app.kubernetes.io/managed-by: Helm
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: 'exporter-device-metrics-exporter-charts-metrics-exporter'
subjects:
- kind: ServiceAccount
  name: amdgpu-metrics-exporter
  namespace: 'kube-system'
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: exporter-configmap
data:
  config.json: |-
    (the packaged config.json, checked on its own below)
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: exporter-amdgpu-metrics-exporter
  labels:
    app: amdgpu-metrics-exporter
    helm.sh/chart: device-metrics-exporter-charts-v1.5.3
    app.kubernetes.io/name: device-metrics-exporter-charts
    app.kubernetes.io/instance: exporter
    app.kubernetes.io/version: "v1.5.3"
    app.kubernetes.io/managed-by: Helm
spec:
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  selector:
    matchLabels:
      app: exporter-amdgpu-metrics-exporter
  template:
    metadata:
      labels:
        app: exporter-amdgpu-metrics-exporter
        app.kubernetes.io/name: metrics-exporter
    spec:
      hostNetwork: false
      serviceAccountName: amdgpu-metrics-exporter
      initContainers:
      - command:
        - sh
        - -c
        - |
          echo "Checking for AMD GPU driver..."
          while [ ! -d /host-sys/class/kfd ] || \
                [ ! -d /host-sys/module/amdgpu/drivers ]; do
            echo "amdgpu driver is not loaded"
            sleep 2
          done
        image: busybox:1.36
        imagePullPolicy: IfNotPresent
        name: driver-init
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /host-sys
          name: sys-volume
      containers:
        - name: amdgpu-metrics-exporter-container
          image: "docker.io/rocm/device-metrics-exporter:v1.5.3"
          imagePullPolicy: Always
          args:
            - "-monitor-gpu=true"
            - "-monitor-nic=false"
          env:
          - name: NODE_NAME
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
          - name: METRICS_EXPORTER_PORT
            value: "5000"
          ports:
            - containerPort: 5000
              protocol: TCP
          securityContext:
            privileged: true
          resources:
            limits:
              cpu: "2"
              memory: 4Gi
            requests:
              cpu: 500m
              memory: 512M
          volumeMounts:
          - mountPath: /dev
            name: dev-volume
          - mountPath: /sys
            name: sys-volume
          - mountPath: /var/lib/kubelet/pod-resources
            name: pod-resources
          - mountPath: /var/lib/amd-metrics-exporter
            name: exporter-health-grpc-volume
          - mountPath: /var/run/exporter
            name: exporter-slurm-job
          - name: metrics-config-volume
            mountPath: /etc/metrics/
          workingDir: /root
      volumes:
      - hostPath:
          path: /dev
          type: Directory
        name: dev-volume
      - hostPath:
          path: /sys
          type: Directory
        name: sys-volume
      - hostPath:
          path: /var/lib/kubelet/pod-resources
          type: Directory
        name: pod-resources
      - hostPath:
          path: /var/lib/amd-metrics-exporter
          type: DirectoryOrCreate
        name: exporter-health-grpc-volume
      - hostPath:
          path: /var/run/exporter
          type: DirectoryOrCreate
        name: exporter-slurm-job
      - name: metrics-config-volume
        configMap:
          name: exporter-configmap
---
apiVersion: v1
kind: Service
metadata:
  name: exporter-amd-metrics-exporter-svc
  labels:
    app: exporter-amdgpu-metrics-exporter
spec:
  selector:
      app: exporter-amdgpu-metrics-exporter
  internalTrafficPolicy: Local
  type: ClusterIP
  ports:
    - protocol: "TCP"
      name: http
      port: 5000
YAML

my @upstream = YAML::PP->new( boolean => 'JSON::PP' )->load_string($UPSTREAM);
my %upstream = map { $_->{kind} => $_ } @upstream;
is( scalar @upstream, 6, 'the chart renders six objects with the defaults (no ServiceMonitor)' );

# The documented changes, applied to the chart's objects.
my %RENAME = (
  'exporter-amdgpu-metrics-exporter'                         => 'amdgpu-metrics-exporter',
  'exporter-device-metrics-exporter-charts-metrics-exporter' => 'amdgpu-metrics-exporter',
  'exporter-amd-metrics-exporter-svc'                        => 'amdgpu-metrics-exporter',
  'exporter-configmap'                                       => 'amdgpu-metrics-exporter-config',
);
sub rename_all {
  my ($v) = @_;
  return { map { $_ => rename_all( $v->{$_} ) } keys %$v } if ref $v eq 'HASH';
  return [ map { rename_all($_) } @$v ] if ref $v eq 'ARRAY';
  return defined $v && !ref $v && exists $RENAME{$v} ? $RENAME{$v} : $v;
}
@upstream = map { rename_all($_) } @upstream;
%upstream = map { $_->{kind} => $_ } @upstream;
for my $obj (@upstream) {
  my $labels = $obj->{metadata}{labels} or next;
  delete @{$labels}{qw( helm.sh/chart app.kubernetes.io/managed-by app.kubernetes.io/instance )};
  delete $labels->{'app.kubernetes.io/name'}
    if ( $labels->{'app.kubernetes.io/name'} // '' ) eq 'device-metrics-exporter-charts';
}
$upstream{$_}{metadata}{namespace} = 'kube-system' for qw( ServiceAccount ConfigMap DaemonSet Service );
{
  my $pod = $upstream{DaemonSet}{spec}{template}{spec};
  delete $pod->{containers}[0]{imagePullPolicy};
  $pod->{nodeSelector} = { 'kubernetes.io/arch' => 'amd64' };
}

# Booleans as the strings true/false, whichever form they come in (\1 in the
# specs, JSON::PP::Boolean from YAML::PP and IO::K8s), so both sides compare.
sub norm {
  my ($v) = @_;
  return $$v ? 'true' : 'false' if ref $v eq 'SCALAR';
  return $v ? 'true' : 'false' if blessed $v && JSON::MaybeXS::is_bool($v);
  return { map { $_ => norm( $v->{$_} ) } keys %$v } if ref $v eq 'HASH';
  return [ map { norm($_) } @$v ] if ref $v eq 'ARRAY';
  return $v;
}

my $k8s   = IO::K8s->new;
my @specs = Rex::Rancher::K8s::_amd_metrics_exporter_specs($version);
is_deeply( [ map { $_->[0] } @specs ],
  [qw( ServiceAccount ClusterRole ClusterRoleBinding ConfigMap DaemonSet Service )],
  'the six objects, in creation order: what an object refers to comes first' );
my %spec = map { $_->[0] => $_->[1] } @specs;

# --- config.json: the packaged chart's, without GPUConfig.Fields ---------------------

my $canonical = JSON::MaybeXS->new( canonical => 1 );
my $packaged  = do { local $/; <DATA> };
my $chart_cfg = $canonical->decode($packaged);
my $cm_json   = $spec{ConfigMap}{data}{'config.json'};
my $ours      = eval { $canonical->decode($cm_json) };
ok( $ours, 'config.json: valid JSON' ) or diag $@;

is( scalar @{ $chart_cfg->{GPUConfig}{Fields} }, 194, "the chart's config lists 194 fields" );
my %seen;
is( scalar( grep { !$seen{$_}++ } @{ $chart_cfg->{GPUConfig}{Fields} } ), 194, '... each once' );
ok( !exists $ours->{GPUConfig}{Fields}, 'config.json: no Fields (empty means every field)' );
unlike( $cm_json, qr/"Fields"/, '... not even an empty one' );
{
  my %want = %$chart_cfg;
  $want{GPUConfig} = { %{ $chart_cfg->{GPUConfig} } };
  delete $want{GPUConfig}{Fields};
  is_deeply( norm($ours), norm( \%want ), "config.json: everything else is the chart's" );
}
is_deeply( [ sort keys %$ours ], [qw( CommonConfig GPUConfig )], 'config.json: CommonConfig and GPUConfig' );
is_deeply( [ sort keys %{ $ours->{GPUConfig} } ],
  [qw( CustomLabels HealthThresholds Labels ProfilerConfig ProfilerMetrics )], '... GPUConfig without Fields' );
is( $ours->{CommonConfig}{MetricsFieldPrefix}, 'amd_', '... the prefix amd_ (not the exporter default)' );
is_deeply( $ours->{GPUConfig}{Labels}, $chart_cfg->{GPUConfig}{Labels}, '... the labels in the chart order' );

# Types as the chart has them: numbers unquoted, booleans true/false, the
# empty CPER age a string.
like( $cm_json, qr/"MaxFileSizeMB":10[,}]/,      'config.json: numbers as numbers' );
like( $cm_json, qr/"GPU_ECC_UNCORRECT_UMC":0[,}]/, '... thresholds too' );
like( $cm_json, qr/"Enable":true[,}]/,           '... booleans as true' );
like( $cm_json, qr/"all":false[,}]/,             '... and false' );
like( $cm_json, qr/"GPU_CPER_MAX_AGE":""/,       '... the CPER age an empty string' );

# Stable: canonical, the same string on every build, so an update sends
# nothing new.
is( $cm_json, $canonical->encode($ours), 'config.json: canonical (sorted keys, no whitespace)' );
my %again = map { $_->[0] => $_->[1] } Rex::Rancher::K8s::_amd_metrics_exporter_specs($version);
is( $again{ConfigMap}{data}{'config.json'}, $cm_json, '... the same string on the next build' );
my %other_version = map { $_->[0] => $_->[1] } Rex::Rancher::K8s::_amd_metrics_exporter_specs('v9.9.9');
is( $other_version{ConfigMap}{data}{'config.json'}, $cm_json, '... and for another version' );

# The ConfigMap's content is checked; the rest of it compares structurally.
$upstream{ConfigMap}{data}{'config.json'} = $cm_json;

# --- every object against the chart's -------------------------------------------------

for (@specs) {
  my ( $kind, $spec ) = @$_;
  my %want = %{ $upstream{$kind} };
  my ( $api_version ) = delete @want{qw( apiVersion kind )};
  is_deeply( norm($spec), norm( \%want ), "$kind: the chart's, with the documented changes" );

  # Through the typed classes, as Kubernetes::REST sends it: a field IO::K8s
  # does not know is dropped here, a missing required one dies.
  my $obj = eval { $k8s->new_object( $kind => %$spec ) };
  ok( $obj, "$kind: new_object builds" ) or diag $@;
  next unless $obj;
  is( $obj->api_version, $api_version, "$kind: $api_version" );
  is_deeply( norm( $k8s->object_to_struct($obj) ), norm( $upstream{$kind} ),
    "$kind: nothing lost in the typed classes" );
}

# --- the single points, spelled out ---------------------------------------------------

my $sa   = $spec{ServiceAccount}{metadata};
my $pod  = $spec{DaemonSet}{spec}{template}{spec};
my ($init) = @{ $pod->{initContainers} };
my ($ctr)  = @{ $pod->{containers} };
my $NAME = 'amdgpu-metrics-exporter';

is_deeply( $sa, { name => $NAME, namespace => 'kube-system',
  labels => { 'app.kubernetes.io/component' => 'amd-gpu', 'app.kubernetes.io/part-of' => 'amd-gpu',
    'app.kubernetes.io/version' => 'v1.5.3' } },
  'ServiceAccount: the chart name, in kube-system, not kube-amd-gpu, no Helm labels' );
is( $spec{$_}{metadata}{name}, $NAME, "$_: $NAME, no release" ) for qw( ClusterRole ClusterRoleBinding DaemonSet Service );
is( $spec{ConfigMap}{metadata}{name}, "$NAME-config", 'ConfigMap: amdgpu-metrics-exporter-config' );
is( $spec{$_}{metadata}{namespace}, 'kube-system', "$_: in kube-system" ) for qw( ConfigMap DaemonSet Service );
ok( !exists $spec{$_}{metadata}{namespace}, "$_: cluster-scoped, no namespace" ) for qw( ClusterRole ClusterRoleBinding );
is_deeply( $spec{ClusterRoleBinding}{roleRef}, { apiGroup => 'rbac.authorization.k8s.io', kind => 'ClusterRole',
  name => $spec{ClusterRole}{metadata}{name} }, 'ClusterRoleBinding: binds the ClusterRole' );
is_deeply( $spec{ClusterRoleBinding}{subjects},
  [ { kind => 'ServiceAccount', name => $sa->{name}, namespace => $sa->{namespace} } ],
  '... to that ServiceAccount' );
is( $pod->{serviceAccountName}, $sa->{name}, 'DaemonSet: runs as it' );
ok( !grep( { grep { /securitycontextconstraints/ } @{ $_->{resources} } } @{ $spec{ClusterRole}{rules} } ),
  'ClusterRole: no OpenShift SCC rule' );
ok( !grep( { /^(?:helm\.sh\/chart|app\.kubernetes\.io\/(?:managed-by|instance))$/ }
  map { keys %{ $_->[1]{metadata}{labels} // {} } } @specs ), 'no Helm labels on any object' );

is( $ctr->{image}, 'docker.io/rocm/device-metrics-exporter:v1.5.3', 'exporter: image pinned to v1.5.3' );
ok( !exists $ctr->{imagePullPolicy}, "exporter: no imagePullPolicy Always (Kubernetes' IfNotPresent)" );
is( ${ $ctr->{securityContext}{privileged} }, 1, 'exporter: privileged, as the chart' );
is_deeply( $ctr->{args}, [qw( -monitor-gpu=true -monitor-nic=false )], 'exporter: GPU, not NIC' );
is_deeply( [ map { "$_->{name}:$_->{mountPath}" } @{ $ctr->{volumeMounts} } ],
  [qw( dev-volume:/dev sys-volume:/sys pod-resources:/var/lib/kubelet/pod-resources
    exporter-health-grpc-volume:/var/lib/amd-metrics-exporter exporter-slurm-job:/var/run/exporter
    metrics-config-volume:/etc/metrics/ )],
  'exporter: /dev, /sys, pod-resources, the health and Slurm dirs, the config' );
is_deeply( { map { $_->{name} => $_->{hostPath}{type} } grep { $_->{hostPath} } @{ $pod->{volumes} } },
  { 'dev-volume' => 'Directory', 'sys-volume' => 'Directory', 'pod-resources' => 'Directory',
    'exporter-health-grpc-volume' => 'DirectoryOrCreate', 'exporter-slurm-job' => 'DirectoryOrCreate' },
  "volumes: the chart's hostPath types, two of them created on the host" );
my ($cfg_vol) = grep { $_->{configMap} } @{ $pod->{volumes} };
is( $cfg_vol->{configMap}{name}, $spec{ConfigMap}{metadata}{name}, 'volumes: mounts our ConfigMap' );
is( $init->{image}, 'busybox:1.36', 'init: busybox:1.36, as the chart writes it' );
is( $init->{imagePullPolicy}, 'IfNotPresent', "init: the chart's IfNotPresent" );
is( ${ $init->{securityContext}{privileged} }, 1, 'init: privileged' );
is( $init->{command}[2], qq{echo "Checking for AMD GPU driver..."\n}
  . qq{while [ ! -d /host-sys/class/kfd ] || \\\n}
  . qq{      [ ! -d /host-sys/module/amdgpu/drivers ]; do\n}
  . qq{  echo "amdgpu driver is not loaded"\n  sleep 2\ndone\n},
  'init: waits for /sys/class/kfd and /sys/module/amdgpu/drivers, the script verbatim' );
is_deeply( $pod->{nodeSelector}, { 'kubernetes.io/arch' => 'amd64' }, 'amd64 only (the image is)' );
ok( !exists $pod->{$_}, "no $_, as the chart's defaults" ) for qw( affinity tolerations priorityClassName );
is( ${ $pod->{hostNetwork} }, 0, 'hostNetwork false, as the chart' );

my $svc = $spec{Service}{spec};
is_deeply( $svc->{ports}, [ { protocol => 'TCP', name => 'http', port => 5000 } ], 'Service: port 5000, named http' );
is( $svc->{type}, 'ClusterIP', 'Service: ClusterIP' );
is( $svc->{internalTrafficPolicy}, 'Local', "Service: the chart's internalTrafficPolicy Local" );
is_deeply( $svc->{selector}, $spec{DaemonSet}{spec}{selector}{matchLabels}, "Service: selects the DaemonSet's pods" );
is( $ctr->{ports}[0]{containerPort}, $svc->{ports}[0]{port}, '... on the port the exporter listens on' );
is_deeply( [ map { "$_->{name}=" . ( $_->{value} // 'fieldRef' ) } @{ $ctr->{env} } ],
  [ 'NODE_NAME=fieldRef', 'METRICS_EXPORTER_PORT=5000' ], '... which METRICS_EXPORTER_PORT says' );

# The selector cannot change on a DaemonSet: it is the same for any version
# and the pod labels match it.
my %other = map { $_->[0] => $_->[1] } Rex::Rancher::K8s::_amd_metrics_exporter_specs('v9.9.9');
is_deeply( $other{DaemonSet}{spec}{selector}, $spec{DaemonSet}{spec}{selector}, 'selector: the same for another version' );
is_deeply( $spec{DaemonSet}{spec}{selector}, { matchLabels => { app => $NAME } }, 'selector: app, no version' );
is_deeply( $spec{DaemonSet}{spec}{template}{metadata}{labels},
  { app => $NAME, 'app.kubernetes.io/name' => 'metrics-exporter' },
  "selector: the pod labels match it, plus upstream's app.kubernetes.io/name" );
is( $other{DaemonSet}{spec}{template}{spec}{containers}[0]{image}, 'docker.io/rocm/device-metrics-exporter:v9.9.9',
  'version: reaches the image tag' );
is( $other{DaemonSet}{spec}{template}{spec}{initContainers}[0]{image}, 'busybox:1.36', 'version: not the init image' );
is( $other{DaemonSet}{metadata}{labels}{'app.kubernetes.io/version'}, 'v9.9.9', 'version: and the version label' );

my $affinity = { nodeAffinity => { requiredDuringSchedulingIgnoredDuringExecution => { nodeSelectorTerms => [
  { matchExpressions => [ { key => 'ocp.internal/amd-gpu.present', operator => 'In', values => ['true'] } ] },
] } } };
my %aff = map { $_->[0] => $_->[1] } Rex::Rancher::K8s::_amd_metrics_exporter_specs( $version, $affinity );
is_deeply( $aff{DaemonSet}{spec}{template}{spec}{affinity}, $affinity, 'affinity: on the exporter pods' );
is_deeply( $aff{DaemonSet}{spec}{template}{spec}{nodeSelector}, { 'kubernetes.io/arch' => 'amd64' }, 'affinity: amd64 stays' );
my $aff_obj = $k8s->new_object( DaemonSet => %{ $aff{DaemonSet} } );
is( $k8s->object_to_struct($aff_obj)->{spec}{template}{spec}{affinity}{nodeAffinity}
  {requiredDuringSchedulingIgnoredDuringExecution}{nodeSelectorTerms}[0]{matchExpressions}[0]{key},
  'ocp.internal/amd-gpu.present', 'affinity: survives the typed classes' );

# --- a fake API server behind the real Kubernetes::REST client ------------------------

my $json = JSON::MaybeXS->new( canonical => 1 );

# Aggregated discovery (apidiscovery.k8s.io/v2): [ group, [ version, [ Kind,
# plural, scope ], ... ], ... ], the first version the preferred one.
sub discovery {
  return { kind => 'APIGroupDiscoveryList', apiVersion => 'apidiscovery.k8s.io/v2', items => [
    map {
      my ( $group, @versions ) = @$_;
      +{ metadata => { name => $group }, versions => [ map {
        my ( $v, @kinds ) = @$_;
        +{ version => $v, resources => [ map {
          +{ resource => $_->[1], responseKind => { kind => $_->[0] }, scope => $_->[2] }
        } @kinds ] }
      } @versions ] }
    } @_
  ] };
}

my $CORE = discovery( [ '', [ 'v1', [qw( ServiceAccount serviceaccounts Namespaced )],
  [qw( ConfigMap configmaps Namespaced )], [qw( Service services Namespaced )] ] ] );
my $APIS = discovery(
  [ 'apps', [ 'v1', [qw( DaemonSet daemonsets Namespaced )] ] ],
  [ 'rbac.authorization.k8s.io',
    [ 'v1', [qw( ClusterRole clusterroles Cluster )], [qw( ClusterRoleBinding clusterrolebindings Cluster )] ] ],
);

# %status: an HTTP status for "METHOD path"; @requests: "METHOD path" of each
# request sent; %body: the JSON of each POST and PUT, by "METHOD path";
# %stored: objects that exist, by path.
our ( %status, @requests, %body, %stored );
{
  package FakeIO;
  use Moo;
  with 'Kubernetes::REST::Role::IO';
  sub call {
    my ( $self, $req ) = @_;
    my $path = $req->url =~ s{^http://mock\.local}{}r =~ s{\?.*}{}r;
    my $call = $req->method . ' ' . $path;
    push @main::requests, $call;
    $main::body{$call} = $req->content if defined $req->content && length $req->content;

    my $reply = sub {
      my ( $code, $content ) = @_;
      return Kubernetes::REST::HTTPResponse->new( status => $code, content => $content );
    };
    my $status = sub {
      my ( $code, $message ) = @_;
      my $reason = { 200 => 'Success', 403 => 'Forbidden', 404 => 'NotFound', 409 => 'AlreadyExists',
        599 => 'Unreachable' }->{$code};
      return $reply->( $code, $json->encode( { kind => 'Status', apiVersion => 'v1',
        status => $code < 400 ? 'Success' : 'Failure', reason => $reason, code => $code,
        message => $message // $reason } ) );
    };

    return $status->( $main::status{$call} ) if $main::status{$call};
    return $reply->( 200, $json->encode($CORE) ) if $call eq 'GET /api';
    return $reply->( 200, $json->encode($APIS) ) if $call eq 'GET /apis';

    if ( $req->method eq 'POST' ) {
      my $obj  = $json->decode( $req->content );
      my $name = $obj->{metadata}{name};
      return $status->( 409, qq{"$name" already exists} ) if $main::stored{"$path/$name"};
      return $reply->( 201, $req->content );
    }
    if ( $req->method eq 'GET' ) {
      my $obj = $main::stored{$path} or return $status->(404);
      return $reply->( 200, $json->encode( { %$obj,
        metadata => { %{ $obj->{metadata} }, resourceVersion => 'rv-' . $obj->{metadata}{name} } } ) );
    }
    return $reply->( 200, $req->content ) if $req->method eq 'PUT';
    return $status->(200) if $req->method eq 'DELETE';
    die "unexpected $call\n";
  }
  sub call_streaming { die "not used\n" }
}

# As _api builds it, resource map from the cluster's discovery (the default).
my @api_for;
{
  no warnings 'redefine';
  *Rex::Rancher::K8s::_api = sub {
    push @api_for, $_[0];
    Kubernetes::REST->new(
      server      => { endpoint => 'http://mock.local' },
      credentials => { token => 'test' },
      io          => FakeIO->new,
    );
  };
}

my $SA  = '/api/v1/namespaces/kube-system/serviceaccounts';
my $CR  = '/apis/rbac.authorization.k8s.io/v1/clusterroles';
my $CRB = '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings';
my $CM  = '/api/v1/namespaces/kube-system/configmaps';
my $DS  = '/apis/apps/v1/namespaces/kube-system/daemonsets';
my $SVC = '/api/v1/namespaces/kube-system/services';
my @OBJECTS = (
  "$SA/$NAME",
  "$CR/$NAME",
  "$CRB/$NAME",
  "$CM/$NAME-config",
  "$DS/$NAME",
  "$SVC/$NAME",
);
my @DISCOVERY = ( 'GET /api', 'GET /apis' );

sub run_api {
  my ( $what, $st, %o ) = @_;
  local %status = %{ $st // {} };
  ( @requests, @api_for, @info, @warn, %body ) = ();
  no strict 'refs';
  return eval { &{"Rex::Rancher::K8s::${what}_amd_metrics_exporter"}( kubeconfig => '/tmp/kc.yaml', %o ); 1 };
}

# --- deploy_amd_metrics_exporter ------------------------------------------------------------

my @POSTS = ( "POST $SA", "POST $CR", "POST $CRB", "POST $CM", "POST $DS", "POST $SVC" );

ok( run_api('deploy'), 'deployed' ) or diag $@;
is_deeply( \@api_for, ['/tmp/kc.yaml'], '... through the given kubeconfig' );
is_deeply( \@requests, [ @DISCOVERY, @POSTS ],
  '... created in order: ServiceAccount, ClusterRole, ClusterRoleBinding, ConfigMap, DaemonSet, Service' );
{
  my $cm = $json->decode( $body{"POST $CM"} );
  is( $cm->{data}{'config.json'}, $cm_json, '... the ConfigMap sent with the canonical config.json' );
  my $ds = $json->decode( $body{"POST $DS"} );
  my $c  = $ds->{spec}{template}{spec}{containers}[0];
  is( $c->{image}, 'docker.io/rocm/device-metrics-exporter:v1.5.3', '... the pinned image' );
  ok( !exists $c->{imagePullPolicy}, '... no imagePullPolicy' );
  like( $body{"POST $DS"}, qr/"value":"5000"/, '... METRICS_EXPORTER_PORT sent as the string "5000"' );
  like( $body{"POST $DS"}, qr/"containerPort":5000[,}]/, '... containerPort as the number 5000' );
  like( $body{"POST $DS"}, qr/"maxUnavailable":1[,}]/, '... maxUnavailable as the number 1' );
  like( $body{"POST $DS"}, qr/"hostNetwork":false/, '... hostNetwork false' );
  like( $body{"POST $SVC"}, qr/"port":5000[,}]/, '... the Service port as the number 5000' );
}
like( $info[0], qr/^Deploying AMD GPU metrics exporter v1\.5\.3/, '... names the version' );
like( $info[-1], qr{/metrics on port 5000}, '... and where the metrics are' );
is_deeply( \@warn, [], '... no warning' );

ok( run_api( deploy => undef, version => 'v1.5.2', affinity => $affinity ), 'version and affinity' ) or diag $@;
my $sent = $json->decode( $body{"POST $DS"} )->{spec}{template}{spec};
is( $sent->{containers}[0]{image}, 'docker.io/rocm/device-metrics-exporter:v1.5.2', '... the version on the image' );
is_deeply( $sent->{affinity}, $affinity, '... the affinity on the pods' );
like( $info[0], qr/v1\.5\.2/, '... and in the log' );

{
  my %collection = ( ServiceAccount => $SA, ClusterRole => $CR, ClusterRoleBinding => $CRB,
    ConfigMap => $CM, DaemonSet => $DS, Service => $SVC );
  local %stored = map {
    my ( $kind, $spec ) = @$_;
    ( "$collection{$kind}/$spec->{metadata}{name}" => { apiVersion => 'x', kind => $kind, %$spec } );
  } @specs;
  is_deeply( [ sort keys %stored ], [ sort @OBJECTS ], 'all six stored where the deploy puts them' );
  ok( run_api('deploy'), 'all there already: deployed' ) or diag $@;
  is_deeply( \@requests,
    [ @DISCOVERY, map { my ($col) = m{^(.*)/[^/]+\z}; ( "POST $col", "GET $_", "PUT $_" ) } @OBJECTS ],
    '... each updated where it is, the cluster-scoped ones without namespace' );
  is_deeply( [ map { $json->decode( $body{"PUT $_"} )->{metadata}{resourceVersion} } @OBJECTS ],
    [ map { 'rv-' . ( m{([^/]+)\z} )[0] } @OBJECTS ], '... at the resourceVersion the cluster has' );
  is( $json->decode( $body{"PUT $CM/$NAME-config"} )->{data}{'config.json'}, $cm_json,
    '... the ConfigMap with the same config.json as before' );
  is( scalar( grep { /already exists, updating/ } @info ), 6, '... each said' );
}

ok( !run_api( deploy => { "POST $CM" => 403 } ), 'a 403 on the ConfigMap: dies' );
is( ref $@ && $@->code, 403, '... with the 403' );
is_deeply( \@requests, [ @DISCOVERY, @POSTS[ 0 .. 3 ] ], '... no DaemonSet, no Service after it' );

ok( !run_api( deploy => undef, affinity => [] ), 'affinity not a hashref: dies' );
like( $@, qr/^affinity must be a hash reference/, '... saying so' );
is_deeply( \@api_for, [], '... before the cluster is touched' );

ok( !eval { Rex::Rancher::K8s::deploy_amd_metrics_exporter(); 1 }, 'no kubeconfig: dies' );
like( $@, qr/^kubeconfig required/, '... saying so' );

# --- remove_amd_metrics_exporter ------------------------------------------------------------

my @DELETES = map { "DELETE $_" } reverse @OBJECTS;

# delete needs no resource map: no discovery, only the six DELETEs.
ok( run_api('remove'), 'removed' ) or diag $@;
is_deeply( \@api_for, ['/tmp/kc.yaml'], '... through the given kubeconfig' );
is_deeply( \@requests, \@DELETES,
  '... in reverse: Service, DaemonSet, ConfigMap, ClusterRoleBinding, ClusterRole, ServiceAccount' );
is( scalar( grep { /^  Removed / } @info ), 6, '... each one said' );
is_deeply( \@warn, [], '... no warning' );

ok( run_api( remove => { map { $_ => 404 } @DELETES } ), 'nothing there: no die' ) or diag $@;
is_deeply( \@requests, \@DELETES, '... still asks for all six' );
is( scalar( grep { /not there, nothing to remove$/ } @info ), 6, '... each logged' );
is_deeply( \@warn, [], '... as info, not a warning' );

ok( run_api( remove => { "DELETE $CM/$NAME-config" => 404 } ), 'the ConfigMap already gone: no die' ) or diag $@;
is_deeply( \@requests, \@DELETES, '... the others deleted' );
is( scalar( grep { /^  Removed / } @info ), 5, '... five removed' );
ok( grep( { m{^  ConfigMap/amdgpu-metrics-exporter-config not there} } @info ), '... the ConfigMap logged as not there' );

ok( !run_api( remove => { "DELETE $DS/$NAME" => 403 } ), 'a 403 on the DaemonSet: dies' );
is( ref $@ && $@->code, 403, '... with the 403' );
is_deeply( \@requests, [ @DELETES[ 0, 1 ] ], '... ConfigMap and RBAC left in place' );

ok( !eval { Rex::Rancher::K8s::remove_amd_metrics_exporter(); 1 }, 'no kubeconfig: dies' );
like( $@, qr/^kubeconfig required/, '... saying so' );

# Exported by Rex::Rancher::K8s, not re-exported by Rex::Rancher (its
# pipeline does not call them).
require Rex::Rancher;
for my $f (qw( deploy_amd_metrics_exporter remove_amd_metrics_exporter )) {
  ok( grep( { $_ eq $f } @Rex::Rancher::K8s::EXPORT ), "$f exported by Rex::Rancher::K8s" );
  ok( !grep( { $_ eq $f } @Rex::Rancher::EXPORT ), "... not re-exported by Rex::Rancher" );
}

done_testing;

# The packaged chart's config.json, device-metrics-exporter-charts-v1.5.3.tgz
# (sha256 c653e9918a1f1d4d2021e775d3e2b3c953d686fcffd55f865e7562f5b76a7634),
# byte for byte.
__DATA__
{
  "CommonConfig": {
    "MetricsFieldPrefix": "amd_",
    "HealthService": {
      "Enable": true,
      "PollingRate": "30s"
    },
    "Logging": {
      "Level": "info",
      "MaxFileSizeMB": 10,
      "MaxBackups": 3,
      "MaxAgeDays": 7
    },
    "Debug": {
      "EnableAPI": false
    }
  },
  "GPUConfig": {
    "Fields": [
      "GPU_NODES_TOTAL",
      "GPU_PACKAGE_POWER",
      "GPU_AVERAGE_PACKAGE_POWER",
      "GPU_EDGE_TEMPERATURE",
      "GPU_JUNCTION_TEMPERATURE",
      "GPU_MEMORY_TEMPERATURE",
      "GPU_HBM_TEMPERATURE",
      "GPU_GFX_ACTIVITY",
      "GPU_UMC_ACTIVITY",
      "GPU_MMA_ACTIVITY",
      "GPU_VCN_ACTIVITY",
      "GPU_JPEG_ACTIVITY",
      "GPU_VOLTAGE",
      "GPU_GFX_VOLTAGE",
      "GPU_MEMORY_VOLTAGE",
      "PCIE_SPEED",
      "PCIE_MAX_SPEED",
      "PCIE_BANDWIDTH",
      "GPU_ENERGY_CONSUMED",
      "PCIE_REPLAY_COUNT",
      "PCIE_RECOVERY_COUNT",
      "PCIE_REPLAY_ROLLOVER_COUNT",
      "PCIE_NACK_SENT_COUNT",
      "PCIE_NACK_RECEIVED_COUNT",
      "GPU_CLOCK",
      "GPU_POWER_USAGE",
      "GPU_VRAM_MAX_BANDWIDTH",
      "GPU_TOTAL_VRAM",
      "GPU_ECC_CORRECT_TOTAL",
      "GPU_ECC_UNCORRECT_TOTAL",
      "GPU_ECC_CORRECT_SDMA",
      "GPU_ECC_UNCORRECT_SDMA",
      "GPU_ECC_CORRECT_GFX",
      "GPU_ECC_UNCORRECT_GFX",
      "GPU_ECC_CORRECT_MMHUB",
      "GPU_ECC_UNCORRECT_MMHUB",
      "GPU_ECC_CORRECT_ATHUB",
      "GPU_ECC_UNCORRECT_ATHUB",
      "GPU_ECC_CORRECT_BIF",
      "GPU_ECC_UNCORRECT_BIF",
      "GPU_ECC_CORRECT_HDP",
      "GPU_ECC_UNCORRECT_HDP",
      "GPU_ECC_CORRECT_XGMI_WAFL",
      "GPU_ECC_UNCORRECT_XGMI_WAFL",
      "GPU_ECC_CORRECT_DF",
      "GPU_ECC_UNCORRECT_DF",
      "GPU_ECC_CORRECT_SMN",
      "GPU_ECC_UNCORRECT_SMN",
      "GPU_ECC_CORRECT_SEM",
      "GPU_ECC_UNCORRECT_SEM",
      "GPU_ECC_CORRECT_MP0",
      "GPU_ECC_UNCORRECT_MP0",
      "GPU_ECC_CORRECT_MP1",
      "GPU_ECC_UNCORRECT_MP1",
      "GPU_ECC_CORRECT_FUSE",
      "GPU_ECC_UNCORRECT_FUSE",
      "GPU_ECC_CORRECT_UMC",
      "GPU_ECC_UNCORRECT_UMC",
      "GPU_XGMI_NBR_0_NOP_TX",
      "GPU_XGMI_NBR_0_REQ_TX",
      "GPU_XGMI_NBR_0_RESP_TX",
      "GPU_XGMI_NBR_0_BEATS_TX",
      "GPU_XGMI_NBR_1_NOP_TX",
      "GPU_XGMI_NBR_1_REQ_TX",
      "GPU_XGMI_NBR_1_RESP_TX",
      "GPU_XGMI_NBR_1_BEATS_TX",
      "GPU_XGMI_NBR_0_TX_THRPUT",
      "GPU_XGMI_NBR_1_TX_THRPUT",
      "GPU_XGMI_NBR_2_TX_THRPUT",
      "GPU_XGMI_NBR_3_TX_THRPUT",
      "GPU_XGMI_NBR_4_TX_THRPUT",
      "GPU_XGMI_NBR_5_TX_THRPUT",
      "GPU_USED_VRAM",
      "GPU_FREE_VRAM",
      "GPU_TOTAL_VISIBLE_VRAM",
      "GPU_USED_VISIBLE_VRAM",
      "GPU_FREE_VISIBLE_VRAM",
      "GPU_TOTAL_GTT",
      "GPU_USED_GTT",
      "GPU_FREE_GTT",
      "GPU_ECC_CORRECT_MCA",
      "GPU_ECC_UNCORRECT_MCA",
      "GPU_ECC_CORRECT_VCN",
      "GPU_ECC_UNCORRECT_VCN",
      "GPU_ECC_CORRECT_JPEG",
      "GPU_ECC_UNCORRECT_JPEG",
      "GPU_ECC_CORRECT_IH",
      "GPU_ECC_UNCORRECT_IH",
      "GPU_ECC_CORRECT_MPIO",
      "GPU_ECC_UNCORRECT_MPIO",
      "GPU_ECC_DEFERRED_TOTAL",
      "GPU_ECC_DEFERRED_SDMA",
      "GPU_ECC_DEFERRED_GFX",
      "GPU_ECC_DEFERRED_MMHUB",
      "GPU_ECC_DEFERRED_ATHUB",
      "GPU_ECC_DEFERRED_BIF",
      "GPU_ECC_DEFERRED_HDP",
      "GPU_ECC_DEFERRED_XGMI_WAFL",
      "GPU_ECC_DEFERRED_DF",
      "GPU_ECC_DEFERRED_SMN",
      "GPU_ECC_DEFERRED_SEM",
      "GPU_ECC_DEFERRED_MP0",
      "GPU_ECC_DEFERRED_MP1",
      "GPU_ECC_DEFERRED_FUSE",
      "GPU_ECC_DEFERRED_UMC",
      "GPU_ECC_DEFERRED_MCA",
      "GPU_ECC_DEFERRED_VCN",
      "GPU_ECC_DEFERRED_JPEG",
      "GPU_ECC_DEFERRED_IH",
      "GPU_ECC_DEFERRED_MPIO",
      "GPU_HEALTH",
      "GPU_XGMI_LINK_RX",
      "GPU_XGMI_LINK_TX",
      "GPU_VIOLATION_CURRENT_ACCUMULATED_COUNTER",
      "GPU_VIOLATION_PROCESSOR_HOT_RESIDENCY_ACCUMULATED",
      "GPU_VIOLATION_PPT_RESIDENCY_ACCUMULATED",
      "GPU_VIOLATION_SOCKET_THERMAL_RESIDENCY_ACCUMULATED",
      "GPU_VIOLATION_VR_THERMAL_RESIDENCY_ACCUMULATED",
      "GPU_VIOLATION_HBM_THERMAL_RESIDENCY_ACCUMULATED",
      "GPU_GFX_BUSY_INSTANTANEOUS",
      "GPU_VCN_BUSY_INSTANTANEOUS",
      "GPU_JPEG_BUSY_INSTANTANEOUS",
      "GPU_PROF_GRBM_GUI_ACTIVE",
      "GPU_PROF_SQ_WAVES",
      "GPU_PROF_GRBM_COUNT",
      "GPU_PROF_CPC_CPC_STAT_BUSY",
      "GPU_PROF_CPC_CPC_STAT_IDLE",
      "GPU_PROF_CPC_CPC_STAT_STALL",
      "GPU_PROF_CPC_CPC_TCIU_BUSY",
      "GPU_PROF_CPC_CPC_TCIU_IDLE",
      "GPU_PROF_CPC_CPC_UTCL2IU_BUSY",
      "GPU_PROF_CPC_CPC_UTCL2IU_IDLE",
      "GPU_PROF_CPC_CPC_UTCL2IU_STALL",
      "GPU_PROF_CPC_ME1_BUSY_FOR_PACKET_DECODE",
      "GPU_PROF_CPC_ME1_DC0_SPI_BUSY",
      "GPU_PROF_CPC_UTCL1_STALL_ON_TRANSLATION",
      "GPU_PROF_CPC_ALWAYS_COUNT",
      "GPU_PROF_CPC_ADC_VALID_CHUNK_NOT_AVAIL",
      "GPU_PROF_CPC_ADC_DISPATCH_ALLOC_DONE",
      "GPU_PROF_CPC_ADC_VALID_CHUNK_END",
      "GPU_PROF_CPC_SYNC_FIFO_FULL_LEVEL",
      "GPU_PROF_CPC_SYNC_FIFO_FULL",
      "GPU_PROF_CPC_GD_BUSY",
      "GPU_PROF_CPC_TG_SEND",
      "GPU_PROF_CPC_WALK_NEXT_CHUNK",
      "GPU_PROF_CPC_STALLED_BY_SE0_SPI",
      "GPU_PROF_CPC_STALLED_BY_SE1_SPI",
      "GPU_PROF_CPC_STALLED_BY_SE2_SPI",
      "GPU_PROF_CPC_STALLED_BY_SE3_SPI",
      "GPU_PROF_CPC_LTE_ALL",
      "GPU_PROF_CPC_SYNC_WRREQ_FIFO_BUSY",
      "GPU_PROF_CPC_CANE_BUSY",
      "GPU_PROF_CPC_CANE_STALL",
      "GPU_PROF_CPF_CMP_UTCL1_STALL_ON_TRANSLATION",
      "GPU_PROF_CPF_CPF_STAT_BUSY",
      "GPU_PROF_CPF_CPF_STAT_IDLE",
      "GPU_PROF_CPF_CPF_STAT_STALL",
      "GPU_PROF_CPF_CPF_TCIU_BUSY",
      "GPU_PROF_CPF_CPF_TCIU_IDLE",
      "GPU_PROF_CPF_CPF_TCIU_STALL",
      "GPU_PROF_FETCH_SIZE",
      "GPU_PROF_WRITE_SIZE",
      "GPU_PROF_TOTAL_16_OPS",
      "GPU_PROF_TOTAL_32_OPS",
      "GPU_PROF_TOTAL_64_OPS",
      "GPU_PROF_GUI_UTIL_PERCENT",
      "GPU_PROF_OCCUPANCY_PERCENT",
      "GPU_PROF_TENSOR_ACTIVE_PERCENT",
      "GPU_PROF_VALU_PIPE_ISSUE_UTIL",
      "GPU_PROF_SM_ACTIVE",
      "GPU_PROF_OCCUPANCY_ELAPSED",
      "GPU_PROF_OCCUPANCY_PER_ACTIVE_CU",
      "GPU_PROF_OCCUPANCY_PER_CU",
      "GPU_PROF_SIMD_UTILIZATION",
      "PCIE_RX",
      "PCIE_TX",
      "PCIE_BIDIRECTIONAL_BANDWIDTH",
      "GPU_AFID_ERRORS",
      "GPU_MIN_CLOCK",
      "GPU_MAX_CLOCK",
      "GPU_VIOLATION_PROCESSOR_HOT_RESIDENCY_PERCENTAGE",
      "GPU_VIOLATION_PPT_RESIDENCY_PERCENTAGE",
      "GPU_VIOLATION_SOCKET_THERMAL_RESIDENCY_PERCENTAGE",
      "GPU_VIOLATION_VR_THERMAL_RESIDENCY_PERCENTAGE",
      "GPU_VIOLATION_HBM_THERMAL_RESIDENCY_PERCENTAGE",
      "GPU_VIOLATION_GFX_CLOCK_BELOW_HOST_LIMIT_POWER_ACCUMULATED",
      "GPU_VIOLATION_GFX_CLOCK_BELOW_HOST_LIMIT_THERMAL_ACCUMULATED",
      "GPU_VIOLATION_LOW_UTILIZATION_ACCUMULATED",
      "GPU_VIOLATION_GFX_CLOCK_BELOW_HOST_LIMIT_TOTAL_ACCUMULATED",
      "GPU_VIOLATION_GFX_CLOCK_BELOW_HOST_LIMIT_POWER_PERCENTAGE",
      "GPU_VIOLATION_GFX_CLOCK_BELOW_HOST_LIMIT_THERMAL_PERCENTAGE",
      "GPU_VIOLATION_LOW_UTILIZATION_PERCENTAGE",
      "GPU_VIOLATION_GFX_CLOCK_BELOW_HOST_LIMIT_TOTAL_PERCENTAGE",
      "GPU_PROCESS_CU_OCCUPANCY"
    ],
    "Labels": [
      "GPU_UUID",
      "SERIAL_NUMBER",
      "GPU_ID",
      "POD",
      "POD_UUID",
      "NAMESPACE",
      "CONTAINER",
      "JOB_ID",
      "JOB_USER",
      "JOB_PARTITION",
      "CLUSTER_NAME",
      "CARD_SERIES",
      "CARD_MODEL",
      "CARD_VENDOR",
      "DRIVER_VERSION",
      "VBIOS_VERSION",
      "HOSTNAME",
      "GPU_PARTITION_ID",
      "GPU_COMPUTE_PARTITION_TYPE",
      "GPU_MEMORY_PARTITION_TYPE",
      "KFD_PROCESS_ID",
      "DEPLOYMENT_MODE"
    ],
    "HealthThresholds": {
      "GPU_ECC_UNCORRECT_SDMA": 0,
      "GPU_ECC_UNCORRECT_GFX": 0,
      "GPU_ECC_UNCORRECT_MMHUB": 0,
      "GPU_ECC_UNCORRECT_ATHUB": 0,
      "GPU_ECC_UNCORRECT_BIF": 0,
      "GPU_ECC_UNCORRECT_HDP": 0,
      "GPU_ECC_UNCORRECT_XGMI_WAFL": 0,
      "GPU_ECC_UNCORRECT_DF": 0,
      "GPU_ECC_UNCORRECT_SMN": 0,
      "GPU_ECC_UNCORRECT_SEM": 0,
      "GPU_ECC_UNCORRECT_MP0": 0,
      "GPU_ECC_UNCORRECT_MP1": 0,
      "GPU_ECC_UNCORRECT_FUSE": 0,
      "GPU_ECC_UNCORRECT_UMC": 0,
      "GPU_ECC_UNCORRECT_MCA": 0,
      "GPU_ECC_UNCORRECT_VCN": 0,
      "GPU_ECC_UNCORRECT_JPEG": 0,
      "GPU_ECC_UNCORRECT_IH": 0,
      "GPU_ECC_UNCORRECT_MPIO": 0,
      "GPU_CPER_MAX_AGE": ""
    },
    "CustomLabels": {
      "CLUSTER_NAME": "amdgpu-k8s-metrics-exporter"
    },
    "ProfilerMetrics": {
      "all": false,
      "hostname1": false
    },
    "ProfilerConfig": {
      "SamplingInterval": 1000,
      "PtlDelay": 0
    }
  }
}
