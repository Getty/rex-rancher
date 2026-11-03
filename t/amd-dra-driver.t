#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# k102: deploy_amd_dra_driver puts ROCm's k8s-gpu-dra-driver v1.0.1 into the
# cluster as its Helm chart at that tag renders with the default values --
# ServiceAccount, ClusterRole, ClusterRoleBinding, ValidatingAdmissionPolicy
# and its binding, DeviceClass gpu.amd.com (resource.k8s.io/v1), the
# kubelet plugin DaemonSet -- with the documented changes (kube-system, the
# image tag pinned, amd64 nodeSelector, no Helm labels, no namespace on
# cluster-scoped objects, the admission policy also matching
# resource.k8s.io/v1), after asking the cluster whether it serves
# DeviceClass in resource.k8s.io/v1 at all. remove_amd_dra_driver deletes the
# same objects in reverse, idempotently.
#
# Offline. The specs are compared with the chart's objects, rendered by hand
# from helm-charts-k8s/templates at v1.0.1 (no helm here) for a release
# k8s-gpu-dra-driver in kube-system and a cluster serving resource.k8s.io/v1.
# deploy and remove run through the real Kubernetes::REST client with only its
# IO faked, discovery included, so the resolution of the Kinds, the paths, and
# the APIError a 404/409/403 becomes are the installed client's own. That the
# image starts, that the plugin publishes ResourceSlices, that the admission
# policy lets it and refuses it another node's, and that a claim gets a GPU
# into a pod are only shown live.

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

my $version = 'v1.0.1';
is( Rex::Rancher::K8s::AMD_DRA_DRIVER_VERSION(), $version, 'pinned release v1.0.1, with its v' );

# --- the chart's objects, rendered with the defaults --------------------------------

my $UPSTREAM = <<'YAML';
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: k8s-gpu-dra-driver-service-account
  namespace: kube-system
  labels:
    helm.sh/chart: k8s-gpu-dra-driver-v1.0.1
    app.kubernetes.io/name: k8s-gpu-dra-driver
    app.kubernetes.io/instance: k8s-gpu-dra-driver
    app.kubernetes.io/version: "v1.0.1"
    app.kubernetes.io/managed-by: Helm
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: k8s-gpu-dra-driver-role
  namespace: kube-system
rules:
- apiGroups: ["resource.k8s.io"]
  resources: ["resourceclaims"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get"]
- apiGroups: ["resource.k8s.io"]
  resources: ["resourceslices"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: k8s-gpu-dra-driver-role-binding
  namespace: kube-system
subjects:
- kind: ServiceAccount
  name: k8s-gpu-dra-driver-service-account
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: k8s-gpu-dra-driver-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: resourceslices-policy-k8s-gpu-dra-driver
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups:   ["resource.k8s.io"]
      apiVersions: ["v1beta1"]
      operations:  ["CREATE", "UPDATE", "DELETE"]
      resources:   ["resourceslices"]
  matchConditions:
  - name: isRestrictedUser
    expression: >-
      request.userInfo.username == "system:serviceaccount:kube-system:k8s-gpu-dra-driver-service-account"
  variables:
  - name: userNodeName
    expression: >-
      request.userInfo.extra[?'authentication.kubernetes.io/node-name'][0].orValue('')
  - name: objectNodeName
    expression: >-
      (request.operation == "DELETE" ? oldObject : object).spec.?nodeName.orValue("")
  validations:
  - expression: variables.userNodeName != ""
    message: >-
      no node association found for user, this user must run in a pod on a node and ServiceAccountTokenPodNodeInfo must be enabled
  - expression: variables.userNodeName == variables.objectNodeName
    messageExpression: >-
      "this user running on node '"+variables.userNodeName+"' may not modify " +
      (variables.objectNodeName == "" ?"cluster resourceslices" : "resourceslices on node '"+variables.objectNodeName+"'")
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: resourceslices-policy-k8s-gpu-dra-driver
spec:
  policyName: resourceslices-policy-k8s-gpu-dra-driver
  validationActions: [Deny]
  # All ResourceSlices are matched.
---
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata:
  name: gpu.amd.com
spec:
  selectors:
  - cel:
      expression: "device.driver == 'gpu.amd.com'"
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: k8s-gpu-dra-driver-kubeletplugin
  namespace: kube-system
  labels:
    helm.sh/chart: k8s-gpu-dra-driver-v1.0.1
    app.kubernetes.io/name: k8s-gpu-dra-driver
    app.kubernetes.io/instance: k8s-gpu-dra-driver
    app.kubernetes.io/version: "v1.0.1"
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/component: kubeletplugin
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: k8s-gpu-dra-driver
      app.kubernetes.io/instance: k8s-gpu-dra-driver
      app.kubernetes.io/component: kubeletplugin
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      labels:
        app.kubernetes.io/name: k8s-gpu-dra-driver
        app.kubernetes.io/instance: k8s-gpu-dra-driver
        app.kubernetes.io/component: kubeletplugin
    spec:
      priorityClassName: system-node-critical
      serviceAccountName: k8s-gpu-dra-driver-service-account
      securityContext:
        {}
      initContainers:
      - name: driver-init
        image: "docker.io/busybox:1.36"
        command: ["sh", "-c", "while [ ! -d /sys/class/kfd ] || [ ! -d /sys/module/amdgpu/drivers/ ]; do echo 'amdgpu driver is not loaded'; sleep 2; done"]
        securityContext:
          privileged: true
        resources:
          {}
        volumeMounts:
        - name: sys
          mountPath: /sys
      containers:
      - name: plugin
        securityContext:
          privileged: true
        image: docker.io/rocm/k8s-gpu-dra-driver:v1.0.1
        imagePullPolicy: IfNotPresent
        command: ["gpu-kubeletplugin"]
        resources:
          {}
        livenessProbe:
          grpc:
            port: 51515
            service: liveness
          failureThreshold: 3
          periodSeconds: 10
        env:
        - name: CDI_ROOT
          value: "/var/run/cdi"
        - name: KUBELET_REGISTRAR_DIRECTORY_PATH
          value: "/var/lib/kubelet/plugins_registry"
        - name: KUBELET_PLUGINS_DIRECTORY_PATH
          value: "/var/lib/kubelet/plugins"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: HEALTHCHECK_PORT
          value: "51515"
        volumeMounts:
        - name: plugins-registry
          mountPath: "/var/lib/kubelet/plugins_registry"
        - name: plugins
          mountPath: "/var/lib/kubelet/plugins"
        - name: cdi
          mountPath: "/var/run/cdi"
        - name: dev
          mountPath: /dev
        - name: sys
          mountPath: /sys
      volumes:
      - name: plugins-registry
        hostPath:
          path: "/var/lib/kubelet/plugins_registry"
      - name: plugins
        hostPath:
          path: "/var/lib/kubelet/plugins"
      - name: cdi
        hostPath:
          path: "/var/run/cdi"
      - name: dev
        hostPath:
          path: /dev
      - name: sys
        hostPath:
          path: /sys
YAML

my @upstream = YAML::PP->new( boolean => 'JSON::PP' )->load_string($UPSTREAM);
my %upstream = map { $_->{kind} => $_ } @upstream;
is( scalar @upstream, 7, 'the chart renders seven objects with the defaults' );

# The documented changes, applied to the chart's objects.
for my $obj (@upstream) {
  my $labels = $obj->{metadata}{labels} or next;
  delete @{$labels}{qw( helm.sh/chart app.kubernetes.io/managed-by )};
}
delete $upstream{$_}{metadata}{namespace} for qw( ClusterRole ClusterRoleBinding );
# the policy's rule also names resource.k8s.io/v1 (k107)
push @{ $upstream{ValidatingAdmissionPolicy}{spec}{matchConstraints}{resourceRules}[0]{apiVersions} }, 'v1';
{
  my $pod = $upstream{DaemonSet}{spec}{template}{spec};
  delete $pod->{securityContext};
  delete $_->{resources} for @{ $pod->{initContainers} }, @{ $pod->{containers} };
  $pod->{nodeSelector} = { 'kubernetes.io/arch' => 'amd64' };
}

# Booleans as the strings true/false, whichever form they come in (\1 in the
# specs, JSON::PP::Boolean from YAML::PP and IO::K8s), so both sides compare.
sub norm {
  my ($v) = @_;
  return $$v ? 'true' : 'false' if ref $v eq 'SCALAR';
  return $v ? 'true' : 'false' if blessed $v && $v->isa('JSON::PP::Boolean');
  return { map { $_ => norm( $v->{$_} ) } keys %$v } if ref $v eq 'HASH';
  return [ map { norm($_) } @$v ] if ref $v eq 'ARRAY';
  return $v;
}

my $k8s   = IO::K8s->new;
my @specs = Rex::Rancher::K8s::_amd_dra_driver_specs($version);
is_deeply( [ map { $_->[0] } @specs ],
  [qw( ServiceAccount ClusterRole ClusterRoleBinding ValidatingAdmissionPolicy
    ValidatingAdmissionPolicyBinding DeviceClass DaemonSet )],
  'the seven objects, in creation order: what an object refers to comes first' );

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

my %spec = map { $_->[0] => $_->[1] } @specs;
my $sa   = $spec{ServiceAccount}{metadata};
my $pod  = $spec{DaemonSet}{spec}{template}{spec};
my ($init) = @{ $pod->{initContainers} };
my ($ctr)  = @{ $pod->{containers} };

is_deeply( $sa, { name => 'k8s-gpu-dra-driver-service-account', namespace => 'kube-system',
  labels => { 'app.kubernetes.io/name' => 'k8s-gpu-dra-driver', 'app.kubernetes.io/instance' => 'k8s-gpu-dra-driver',
    'app.kubernetes.io/version' => 'v1.0.1' } },
  'ServiceAccount: in kube-system, not kube-amd-gpu' );
is( $spec{ValidatingAdmissionPolicy}{spec}{matchConditions}[0]{expression},
  'request.userInfo.username == "system:serviceaccount:' . $sa->{namespace} . ':' . $sa->{name} . '"',
  "policy: its user is the ServiceAccount's, namespace and name" );
# k107: the chart's rule names only v1beta1, and on a cluster that serves
# resource.k8s.io only as v1 (amdlab, RKE2 1.36) it matched nothing: a
# ResourceSlice for another node, written as the plugin, went through.
my ($rule) = @{ $spec{ValidatingAdmissionPolicy}{spec}{matchConstraints}{resourceRules} };
is_deeply( [ sort @{ $rule->{apiVersions} } ], [qw( v1 v1beta1 )],
  "policy: matches resourceslices in v1 as well as the chart's v1beta1" );
is_deeply( $spec{ClusterRoleBinding}{subjects},
  [ { kind => 'ServiceAccount', name => $sa->{name}, namespace => $sa->{namespace} } ],
  'ClusterRoleBinding: binds that ServiceAccount' );
is( $pod->{serviceAccountName}, $sa->{name}, 'DaemonSet: runs as it' );
ok( !exists $spec{$_}{metadata}{namespace}, "$_: cluster-scoped, no namespace" )
  for qw( ClusterRole ClusterRoleBinding ValidatingAdmissionPolicy ValidatingAdmissionPolicyBinding DeviceClass );
is( $spec{ValidatingAdmissionPolicyBinding}{spec}{policyName}, $spec{ValidatingAdmissionPolicy}{metadata}{name},
  'policy binding: binds the policy' );
is( $spec{DeviceClass}{metadata}{name}, 'gpu.amd.com', 'DeviceClass: gpu.amd.com' );
is( $spec{DeviceClass}{spec}{selectors}[0]{cel}{expression}, q{device.driver == 'gpu.amd.com'},
  "DeviceClass: selects the driver's devices" );

is( $spec{DaemonSet}{metadata}{name}, 'k8s-gpu-dra-driver-kubeletplugin', 'DaemonSet: the chart name' );
is( $ctr->{image}, 'docker.io/rocm/k8s-gpu-dra-driver:v1.0.1', 'plugin: image pinned to v1.0.1, not appVersion, not latest' );
is( ${ $ctr->{securityContext}{privileged} }, 1, 'plugin: privileged, as the chart' );
is_deeply( $ctr->{command}, ['gpu-kubeletplugin'], 'plugin: command' );
is( $init->{image}, 'docker.io/busybox:1.36', 'init: busybox:1.36' );
is( ${ $init->{securityContext}{privileged} }, 1, 'init: privileged' );
like( $init->{command}[2], qr{\[ ! -d /sys/class/kfd \] \|\| \[ ! -d /sys/module/amdgpu/drivers/ \]},
  'init: waits for /sys/class/kfd and /sys/module/amdgpu/drivers/' );
is_deeply( [ map { "$_->{name}:$_->{mountPath}" } @{ $ctr->{volumeMounts} } ],
  [qw( plugins-registry:/var/lib/kubelet/plugins_registry plugins:/var/lib/kubelet/plugins
    cdi:/var/run/cdi dev:/dev sys:/sys )],
  'plugin: the kubelet plugin dirs, the CDI dir, /dev and /sys' );
is_deeply( $pod->{nodeSelector}, { 'kubernetes.io/arch' => 'amd64' }, 'amd64 only (the image is)' );
ok( !exists $pod->{affinity}, 'no affinity unless given (upstream behaviour)' );
ok( !exists $pod->{tolerations}, 'no tolerations, as the chart' );
is( $pod->{priorityClassName}, 'system-node-critical', "system-node-critical, the chart's" );

# The selector cannot change on a DaemonSet: it is the same for any version
# and the pod labels match it.
my ($other) = map { $_->[1] } grep { $_->[0] eq 'DaemonSet' } Rex::Rancher::K8s::_amd_dra_driver_specs('v9.9.9');
is_deeply( $other->{spec}{selector}, $spec{DaemonSet}{spec}{selector}, 'selector: the same for another version' );
ok( !grep( { /version/ } keys %{ $spec{DaemonSet}{spec}{selector}{matchLabels} } ), 'selector: no version label' );
is_deeply( $spec{DaemonSet}{spec}{template}{metadata}{labels}, $spec{DaemonSet}{spec}{selector}{matchLabels},
  'selector: the pod labels match it' );
is( $other->{spec}{template}{spec}{containers}[0]{image}, 'docker.io/rocm/k8s-gpu-dra-driver:v9.9.9',
  'version: reaches the image tag' );
is( $other->{spec}{template}{spec}{initContainers}[0]{image}, 'docker.io/busybox:1.36', 'version: not the init image' );
is( $other->{metadata}{labels}{'app.kubernetes.io/version'}, 'v9.9.9', 'version: and the version label' );

my $affinity = { nodeAffinity => { requiredDuringSchedulingIgnoredDuringExecution => { nodeSelectorTerms => [
  { matchExpressions => [ { key => 'ocp.internal/amd-gpu.dra', operator => 'In', values => ['true'] } ] },
] } } };
my ($ads) = map { $_->[1] } grep { $_->[0] eq 'DaemonSet' } Rex::Rancher::K8s::_amd_dra_driver_specs( $version, $affinity );
is_deeply( $ads->{spec}{template}{spec}{affinity}, $affinity, 'affinity: on the plugin pods' );
is_deeply( $ads->{spec}{template}{spec}{nodeSelector}, { 'kubernetes.io/arch' => 'amd64' }, 'affinity: amd64 stays' );
my $ads_obj = $k8s->new_object( DaemonSet => %$ads );
is( $k8s->object_to_struct($ads_obj)->{spec}{template}{spec}{affinity}{nodeAffinity}
  {requiredDuringSchedulingIgnoredDuringExecution}{nodeSelectorTerms}[0]{matchExpressions}[0]{key},
  'ocp.internal/amd-gpu.dra', 'affinity: survives the typed classes' );

# k108: init_image replaces the init container's image, and nothing else.
my $mirror = 'registry.example.com:5000/library/busybox:1.36';
my %mirrored = map { $_->[0] => $_->[1] } Rex::Rancher::K8s::_amd_dra_driver_specs( $version, undef, $mirror );
my $mpod = $mirrored{DaemonSet}{spec}{template}{spec};
is( $mpod->{initContainers}[0]{image}, $mirror, 'init_image: on the init container' );
is( $mpod->{containers}[0]{image}, 'docker.io/rocm/k8s-gpu-dra-driver:v1.0.1', 'init_image: not the plugin image' );
$mpod->{initContainers}[0]{image} = 'docker.io/busybox:1.36';
is_deeply( \%mirrored, \%spec, 'init_image: nothing else changes' );

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

my @DRA_KINDS = ( [qw( DeviceClass deviceclasses Cluster )], [qw( ResourceSlice resourceslices Cluster )] );
my @BASE = (
  [ 'apps', [ 'v1', [qw( DaemonSet daemonsets Namespaced )] ] ],
  [ 'rbac.authorization.k8s.io',
    [ 'v1', [qw( ClusterRole clusterroles Cluster )], [qw( ClusterRoleBinding clusterrolebindings Cluster )] ] ],
  [ 'admissionregistration.k8s.io',
    [ 'v1', [qw( ValidatingAdmissionPolicy validatingadmissionpolicies Cluster )],
      [qw( ValidatingAdmissionPolicyBinding validatingadmissionpolicybindings Cluster )] ] ],
);
my %CLUSTER = (
  # 1.36: resource.k8s.io/v1 preferred, the betas still listed
  '1.36'   => discovery( @BASE, [ 'resource.k8s.io', [ 'v1', @DRA_KINDS ], [ 'v1beta2', @DRA_KINDS ],
    [ 'v1beta1', @DRA_KINDS ] ] ),
  # 1.33: DRA in beta only
  '1.33'   => discovery( @BASE, [ 'resource.k8s.io', [ 'v1beta2', @DRA_KINDS ], [ 'v1beta1', @DRA_KINDS ] ] ),
  # no resource.k8s.io at all
  'no-dra' => discovery(@BASE),
);
my $CORE = discovery( [ '', [ 'v1', [qw( ServiceAccount serviceaccounts Namespaced )] ] ] );

# $cluster: the /apis document; %status: an HTTP status for "METHOD path";
# @requests: "METHOD path" of each request sent; %body: the JSON of each POST
# and PUT, by "METHOD path"; %stored: objects that exist, by path.
our ( $cluster, %status, @requests, %body, %stored );
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
    return $reply->( 200, $json->encode($CORE) )         if $call eq 'GET /api';
    return $reply->( 200, $json->encode($main::cluster) ) if $call eq 'GET /apis';

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

my $SA   = '/api/v1/namespaces/kube-system/serviceaccounts';
my $CR   = '/apis/rbac.authorization.k8s.io/v1/clusterroles';
my $CRB  = '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings';
my $VAP  = '/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies';
my $VAPB = '/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings';
my $DC   = '/apis/resource.k8s.io/v1/deviceclasses';
my $DS   = '/apis/apps/v1/namespaces/kube-system/daemonsets';
my @OBJECTS = (
  "$SA/k8s-gpu-dra-driver-service-account",
  "$CR/k8s-gpu-dra-driver-role",
  "$CRB/k8s-gpu-dra-driver-role-binding",
  "$VAP/resourceslices-policy-k8s-gpu-dra-driver",
  "$VAPB/resourceslices-policy-k8s-gpu-dra-driver",
  "$DC/gpu.amd.com",
  "$DS/k8s-gpu-dra-driver-kubeletplugin",
);
my @DISCOVERY = ( 'GET /api', 'GET /apis' );

sub run_api {
  my ( $what, $cl, $st, %o ) = @_;
  local $cluster = $CLUSTER{$cl};
  local %status  = %{ $st // {} };
  ( @requests, @api_for, @info, @warn, %body ) = ();
  no strict 'refs';
  return eval { &{"Rex::Rancher::K8s::${what}_amd_dra_driver"}( kubeconfig => '/tmp/kc.yaml', %o ); 1 };
}

# --- deploy_amd_dra_driver ------------------------------------------------------------------

my @POSTS = ( "POST $SA", "POST $CR", "POST $CRB", "POST $VAP", "POST $VAPB", "POST $DC", "POST $DS" );

ok( run_api( deploy => '1.36' ), 'Kubernetes 1.36: deployed' ) or diag $@;
is_deeply( \@api_for, ['/tmp/kc.yaml'], '... through the given kubeconfig' );
is_deeply( \@requests, [ @DISCOVERY, @POSTS ],
  '... discovery once, then created in order, the DeviceClass in resource.k8s.io/v1' );
is( $json->decode( $body{"POST $DC"} )->{apiVersion}, 'resource.k8s.io/v1', '... DeviceClass sent as resource.k8s.io/v1' );
is( $json->decode( $body{"POST $DS"} )->{spec}{template}{spec}{containers}[0]{image},
  'docker.io/rocm/k8s-gpu-dra-driver:v1.0.1', '... the pinned image' );
is( $json->decode( $body{"POST $DS"} )->{spec}{template}{spec}{initContainers}[0]{image},
  'docker.io/busybox:1.36', "... the chart's init image" );
like( $info[0], qr/^Deploying AMD GPU DRA driver v1\.0\.1/, '... names the version' );
like( $info[-1], qr/ResourceSlices of driver gpu\.amd\.com/, '... and how to see the GPUs arrive' );
is_deeply( \@warn, [], '... no warning' );

ok( run_api( deploy => '1.36', undef, version => 'v1.0.0', affinity => $affinity ), 'version and affinity' ) or diag $@;
my $sent = $json->decode( $body{"POST $DS"} )->{spec}{template}{spec};
is( $sent->{containers}[0]{image}, 'docker.io/rocm/k8s-gpu-dra-driver:v1.0.0', '... the version on the image' );
is_deeply( $sent->{affinity}, $affinity, '... the affinity on the pods' );
like( $info[0], qr/v1\.0\.0/, '... and in the log' );

# A made-up digest: only the form of the reference matters here.
my $digest = 'docker.io/library/busybox@sha256:' . ( 'ab' x 32 );
ok( run_api( deploy => '1.36', undef, init_image => $digest ), 'init_image' ) or diag $@;
$sent = $json->decode( $body{"POST $DS"} )->{spec}{template}{spec};
is( $sent->{initContainers}[0]{image}, $digest, '... on the init container sent' );
is( $sent->{containers}[0]{image}, 'docker.io/rocm/k8s-gpu-dra-driver:v1.0.1', '... the plugin image untouched' );

{
  local %stored = map {
    my $path = $_;
    my ($spec) = grep { $path =~ m{/\Q$_->[1]{metadata}{name}\E\z} } @specs;
    ( $path => { apiVersion => 'x', kind => $spec->[0], %{ $spec->[1] } } );
  } @OBJECTS;
  ok( run_api( deploy => '1.36' ), 'all there already: deployed' ) or diag $@;
  is_deeply( \@requests,
    [ @DISCOVERY, map { my ($col) = m{^(.*)/[^/]+\z}; ( "POST $col", "GET $_", "PUT $_" ) } @OBJECTS ],
    '... each updated where it is, the cluster-scoped ones without namespace' );
  is_deeply( [ map { $json->decode( $body{"PUT $_"} )->{metadata}{resourceVersion} } @OBJECTS ],
    [ map { 'rv-' . ( m{([^/]+)\z} )[0] } @OBJECTS ], '... at the resourceVersion the cluster has' );
  is( scalar( grep { /already exists, updating/ } @info ), 7, '... each said' );
  is_deeply( $json->decode( $body{"PUT $VAP/resourceslices-policy-k8s-gpu-dra-driver"} )
    ->{spec}{matchConstraints}{resourceRules}[0]{apiVersions}, [qw( v1beta1 v1 )],
    '... the policy replaced with the rule for v1 and v1beta1 (k107)' );
}

ok( !run_api( deploy => '1.36', { "POST $VAP" => 403 } ), 'a 403 on the policy: dies' );
is( ref $@ && $@->code, 403, '... with the 403' );
is_deeply( \@requests, [ @DISCOVERY, @POSTS[ 0 .. 3 ] ], '... nothing after it' );

# The check before anything is created.
for my $case ( [ 'no-dra', 'a cluster without resource.k8s.io' ], [ '1.33', 'Kubernetes 1.33, DRA in beta only' ] ) {
  my ( $cl, $label ) = @$case;
  ok( !run_api( deploy => $cl ), "$label: dies" );
  like( $@, qr/^The cluster does not serve DeviceClass in resource\.k8s\.io\/v1: .* Kubernetes 1\.34 or later; nothing deployed$/,
    '... saying what it needs' );
  unlike( $@, qr/Can't locate/, "... not IO::K8s's missing class" );
  is_deeply( \@requests, \@DISCOVERY, '... after discovery, before any object is created' );
}

ok( !run_api( deploy => '1.36', { 'GET /apis' => 403 } ), 'discovery refused: dies' );
like( $@, qr/^Could not load resource map from cluster: .*403/, '... naming the reason' );
ok( !grep( { /^POST / } @requests ), '... before any object is created' );

ok( !run_api( deploy => '1.36', undef, affinity => [] ), 'affinity not a hashref: dies' );
like( $@, qr/^affinity must be a hash reference/, '... saying so' );
is_deeply( \@api_for, [], '... before the cluster is touched' );

# A ref would die only in the typed DaemonSet, after the six objects before
# it are created; an empty or padded string would reach the template.
for my $bad ( [ '' => 'empty' ], [ ' busybox:1.36' => 'with whitespace' ], [ ['busybox:1.36'] => 'an array reference' ] ) {
  my ( $value, $label ) = @$bad;
  ok( !run_api( deploy => '1.36', undef, init_image => $value ), "init_image $label: dies" );
  like( $@, qr/^init_image must be an image reference/, '... saying so' );
  is_deeply( \@api_for, [], '... before the cluster is touched' );
}

ok( !eval { Rex::Rancher::K8s::deploy_amd_dra_driver(); 1 }, 'no kubeconfig: dies' );
like( $@, qr/^kubeconfig required/, '... saying so' );

# --- remove_amd_dra_driver ------------------------------------------------------------------

my @DELETES = map { "DELETE $_" } reverse @OBJECTS;

ok( run_api( remove => '1.36' ), 'removed' ) or diag $@;
is_deeply( \@api_for, ['/tmp/kc.yaml'], '... through the given kubeconfig' );
is_deeply( \@requests, [ @DISCOVERY, @DELETES ],
  '... in reverse: DaemonSet, DeviceClass, policy binding, policy, ClusterRoleBinding, ClusterRole, ServiceAccount' );
is( scalar( grep { /^  Removed / } @info ), 7, '... each one said' );
is_deeply( \@warn, [], '... no warning' );

ok( run_api( remove => '1.36', { map { $_ => 404 } @DELETES } ), 'nothing there: no die' ) or diag $@;
is_deeply( \@requests, [ @DISCOVERY, @DELETES ], '... still asks for all seven' );
is( scalar( grep { /not there, nothing to remove$/ } @info ), 7, '... each logged' );
is_deeply( \@warn, [], '... as info, not a warning' );

ok( run_api( remove => 'no-dra' ), 'a cluster without resource.k8s.io: no die' ) or diag $@;
is_deeply( \@requests, [ @DISCOVERY, grep { !m{/deviceclasses/} } @DELETES ],
  '... the others deleted, no request for the DeviceClass' );
ok( grep( { m{^  DeviceClass/gpu\.amd\.com not there \(the cluster does not serve resource\.k8s\.io/v1\)} } @info ),
  '... which counts as not there' );

ok( !run_api( remove => '1.36', { "DELETE $DS/k8s-gpu-dra-driver-kubeletplugin" => 403 } ),
  'a 403 on the DaemonSet: dies' );
is( ref $@ && $@->code, 403, '... with the 403' );
is_deeply( \@requests, [ @DISCOVERY, $DELETES[0] ], '... DeviceClass, policy and RBAC left in place' );

ok( !run_api( remove => '1.36', { 'GET /api' => 599 } ), 'discovery unreachable: dies' );
ok( !grep( { /^DELETE / } @requests ), '... before anything is deleted' );

ok( !eval { Rex::Rancher::K8s::remove_amd_dra_driver(); 1 }, 'no kubeconfig: dies' );
like( $@, qr/^kubeconfig required/, '... saying so' );

# Exported by Rex::Rancher::K8s, not re-exported by Rex::Rancher (its
# pipeline does not call them).
require Rex::Rancher;
for my $f (qw( deploy_amd_dra_driver remove_amd_dra_driver )) {
  ok( grep( { $_ eq $f } @Rex::Rancher::K8s::EXPORT ), "$f exported by Rex::Rancher::K8s" );
  ok( !grep( { $_ eq $f } @Rex::Rancher::EXPORT ), "... not re-exported by Rex::Rancher" );
}

done_testing;
