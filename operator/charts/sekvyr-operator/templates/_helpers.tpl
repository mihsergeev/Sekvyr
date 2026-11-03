{{- define "sekvyr-operator.name" -}}
{{- printf "%s-operator" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "sekvyr-operator.serviceAccountUID" -}}
{{- if .Values.ha.enabled -}}
{{- if and .Values.serviceAccount.uid (ne .Values.serviceAccount.uid .Values.ha.operatorServiceAccountUID) -}}
{{- fail "serviceAccount.uid must equal the HA operator ServiceAccount UID" -}}
{{- end -}}
{{- .Values.ha.operatorServiceAccountUID -}}
{{- else -}}{{- .Values.serviceAccount.uid -}}{{- end -}}
{{- end -}}
{{- define "sekvyr-operator.leaseUID" -}}
{{- if .Values.ha.enabled -}}
{{- if and .Values.leaderElection.uid (ne .Values.leaderElection.uid .Values.ha.leaseUID) -}}
{{- fail "leaderElection.uid must equal the HA Lease UID" -}}
{{- end -}}
{{- .Values.ha.leaseUID -}}
{{- else -}}{{- .Values.leaderElection.uid -}}{{- end -}}
{{- end -}}
{{- define "sekvyr-operator.labels" -}}
app.kubernetes.io/name: sekvyr-operator
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
{{- end -}}
{{- define "sekvyr-operator.installation" -}}
{{- $config := deepCopy .Values.installation -}}
{{- $serviceAccountUID := include "sekvyr-operator.serviceAccountUID" . -}}
{{- $leaseUID := include "sekvyr-operator.leaseUID" . -}}
{{- if and (not .Values.serviceAccount.create) (not $serviceAccountUID) -}}
{{- fail "an external ServiceAccount requires an explicit UID pin" -}}
{{- end -}}
{{- if and (not .Values.leaderElection.create) (not $leaseUID) -}}
{{- fail "an external Lease requires an explicit UID pin" -}}
{{- end -}}
{{- if $serviceAccountUID -}}{{- $_ := set $config "serviceAccountUID" $serviceAccountUID -}}{{- end -}}
{{- if $leaseUID -}}
{{- $_ := set $config "leaderElectionLeaseName" .Values.leaderElection.id -}}
{{- $_ := set $config "leaderElectionLeaseUID" $leaseUID -}}
{{- end -}}
{{- if and .Values.rollout.enabled (or (not .Values.sync.enabled) (eq (len .Values.rollout.allowedDeployments) 0)) -}}
{{- fail "rollout.enabled requires sync.enabled and an explicit rollout.allowedDeployments allowlist" -}}
{{- end -}}
{{- $_ := set $config "rolloutEnabled" .Values.rollout.enabled -}}
{{- $_ := set $config "allowedDeployments" .Values.rollout.allowedDeployments -}}
{{- if ne .Release.Namespace (required "installation.namespace is required" $config.namespace) -}}
{{- fail "installation.namespace must equal the Helm release namespace" -}}
{{- end -}}
{{- $names := list $config.identityKeySecret.name $config.trustBundleSecret.name $config.stateSecret.name -}}
{{- $uids := list $config.identityKeySecret.uid $config.trustBundleSecret.uid $config.stateSecret.uid -}}
{{- if and (not .Values.ha.enabled) .Values.ha.webhook.retiredStateSecrets -}}
{{- fail "retired state pins require the HA admission profile" -}}
{{- end -}}
{{- if and (not .Values.ha.enabled) .Values.ha.maintenance -}}{{- fail "maintenance requires the HA profile" -}}{{- end -}}
{{- if and (not .Values.ha.enabled) (lt (int .Values.replicas) 1) -}}{{- fail "non-HA needs at least one operator replica" -}}{{- end -}}
{{- if or (ne (len (uniq $names)) 3) (ne (len (uniq $uids)) 3) -}}
{{- fail "identity, trust and state Secret names and UIDs must be distinct" -}}
{{- end -}}
{{- if .Values.ha.enabled -}}
{{- $readiness := .Values.ha.fencer.readinessTimeoutSeconds -}}
{{- if or (not (or (kindIs "int" $readiness) (kindIs "int64" $readiness) (kindIs "float64" $readiness))) (not (regexMatch "^[0-9]+$" (toString $readiness))) (lt (int $readiness) 1) (gt (int $readiness) 30) -}}
{{- fail "ha.fencer.readinessTimeoutSeconds must be an integer from 1 through 30" -}}
{{- end -}}
{{- if or (not .Values.ha.trial) (not .Values.ha.config.trial) (not .Values.sync.enabled) (lt (int .Values.ha.fencer.replicas) 2) -}}
{{- fail "HA requires explicit trial, sync and at least two fencer replicas" -}}
{{- end -}}
{{- if .Values.ha.maintenance -}}
{{- if ne (int .Values.replicas) 0 -}}{{- fail "HA maintenance must stop all operator replicas" -}}{{- end -}}
{{- else if lt (int .Values.replicas) 2 -}}
{{- fail "normal HA requires at least two operator replicas" -}}
{{- end -}}
{{- if or (eq .Values.ha.fencer.serviceAccount.name $config.serviceAccount) (eq .Values.ha.fencer.serviceAccount.uid .Values.ha.operatorServiceAccountUID) -}}
{{- fail "the fencer must use a separate ServiceAccount name and UID" -}}
{{- end -}}
{{- if or (has (printf "%s-fencer" .Release.Name | trunc 63 | trimSuffix "-") .Values.rollout.allowedDeployments) (has (include "sekvyr-operator.name" .) .Values.rollout.allowedDeployments) -}}
{{- fail "operator rollout permissions cannot include the fencer or operator Deployment" -}}
{{- end -}}
{{- range $pin := list .Values.ha.config.gatewayClientSecret .Values.ha.fencer.gatewayClientSecret .Values.ha.fencer.signingKeySecret .Values.ha.fencer.tlsSecret -}}
{{- if or (has $pin.name $names) (has $pin.uid $uids) -}}{{- fail "HA credential names and UIDs must be distinct from bootstrap and one another" -}}{{- end -}}
{{- $names = append $names $pin.name -}}{{- $uids = append $uids $pin.uid -}}
{{- end -}}
{{- $expected := dict -}}{{- $_ := set $expected (printf "v1/Secret/%s" $config.stateSecret.name) $config.stateSecret.uid -}}
{{- range $name := $config.allowedTargetSecrets -}}{{- $_ := set $expected (printf "v1/Secret/%s" $name) "" -}}{{- end -}}
{{- if .Values.rollout.enabled -}}{{- range $name := .Values.rollout.allowedDeployments -}}{{- $_ := set $expected (printf "apps/v1/Deployment/%s" $name) "" -}}{{- end -}}{{- end -}}
{{- if ne (len .Values.ha.managedObjects) (len $expected) -}}{{- fail "HA must pin every state, target and rollout object exactly once" -}}{{- end -}}
{{- $seen := dict -}}
{{- range $ref := .Values.ha.managedObjects -}}
{{- $key := printf "%s/%s/%s" $ref.apiVersion $ref.kind $ref.name -}}
{{- if or (ne $ref.namespace $config.namespace) (not (hasKey $expected $key)) (hasKey $seen $key) -}}{{- fail "HA object pins must match exact configured names and namespace" -}}{{- end -}}
{{- if and (get $expected $key) (ne (get $expected $key) $ref.uid) -}}{{- fail "HA state UID must equal the existing state Secret pin" -}}{{- end -}}
{{- $_ := set $seen $key true -}}
{{- end -}}
{{- if gt (len .Values.ha.webhook.retiredStateSecrets) 16 -}}{{- fail "too many retired state pins" -}}{{- end -}}
{{- range $pin := .Values.ha.webhook.retiredStateSecrets -}}
{{- if or (ne (len $pin) 2) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $pin.name)) (gt (len $pin.name) 253) (not (regexMatch "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" $pin.uid)) -}}
{{- fail "retired state requires only an exact DNS name and creation UUID" -}}
{{- end -}}
{{- if or (has $pin.name $names) (has $pin.uid $uids) (has $pin.name $config.allowedTargetSecrets) -}}
{{- fail "retired state names and UIDs must be distinct from active and protected objects" -}}
{{- end -}}
{{- range $ref := $.Values.ha.managedObjects -}}
{{- if or (eq $pin.name $ref.name) (eq $pin.uid $ref.uid) -}}{{- fail "a retired state pin cannot be an active managed object" -}}{{- end -}}
{{- end -}}
{{- $names = append $names $pin.name -}}{{- $uids = append $uids $pin.uid -}}
{{- end -}}
{{- range $ref := list .Values.ha.config.fencerCAConfigMapRef .Values.ha.config.gatewayCAConfigMapRef -}}
{{- $found := false -}}{{- range $pin := $config.caConfigMaps -}}{{- if and (eq $pin.name $ref.name) (eq $pin.key $ref.key) -}}{{- $found = true -}}{{- end -}}{{- end -}}
{{- if not $found -}}{{- fail "HA CAs must reference existing administrative ConfigMap pins" -}}{{- end -}}
{{- end -}}
{{- $_ := set $config "ha" .Values.ha.config -}}
{{- end -}}
{{- $_ := set $config "protectedSecretNames" (concat $config.protectedSecretNames $names | uniq) -}}
{{- $_ := set $config "protectedSecretUIDs" (concat $config.protectedSecretUIDs $uids | uniq) -}}
{{- $_ := set $config "protectedPrefixes" (concat $config.protectedPrefixes (list "sh.helm.release.v1." "kube-api-access-" ) | uniq) -}}
{{- if and .Values.sync.enabled (eq (len $config.allowedTargetSecrets) 0) -}}
{{- fail "sync.enabled requires an explicit installation.allowedTargetSecrets allowlist" -}}
{{- end -}}
{{- range $target := $config.allowedTargetSecrets -}}
{{- if has $target $config.protectedSecretNames -}}
{{- fail "an allowed target cannot be a protected bootstrap Secret" -}}
{{- end -}}
{{- range $prefix := $config.protectedPrefixes -}}
{{- if hasPrefix $prefix $target -}}
{{- fail "an allowed target cannot use a protected Secret prefix" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $config.witnessCAConfigMapRef -}}
{{- $found := false -}}
{{- range $ca := $config.caConfigMaps -}}
{{- if and (eq $ca.name $config.witnessCAConfigMapRef.name) (eq $ca.key $config.witnessCAConfigMapRef.key) -}}
{{- $found = true -}}
{{- end -}}
{{- end -}}
{{- if not $found -}}
{{- fail "installation.witnessCAConfigMapRef must reference an existing administrative CA pin" -}}
{{- end -}}
{{- end -}}
{{- $config | toJson -}}
{{- end -}}
{{- define "sekvyr-operator.configName" -}}
{{- printf "%s-install-%s" (.Release.Name | trunc 36 | trimSuffix "-") (include "sekvyr-operator.installation" . | sha256sum | trunc 12) -}}
{{- end -}}
