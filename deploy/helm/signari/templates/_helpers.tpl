{{/* Standard name/label helpers. */}}
{{- define "signari.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "signari.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "signari.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "signari.labels" -}}
app.kubernetes.io/name: {{ include "signari.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "signari.selectorLabels" -}}
app.kubernetes.io/name: {{ include "signari.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
The console's pods, by a name of their own. Sharing the engine's would put them
behind the engine's Service, budget and policy, whose selectors cannot change on an
upgrade.
*/}}
{{- define "signari.consoleSelectorLabels" -}}
app.kubernetes.io/name: {{ include "signari.name" . }}-console
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "signari.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
The Secret name in use: an operator-managed existingSecret, or the one this
chart renders.
*/}}
{{- define "signari.secretName" -}}
{{- if .Values.secret.existingSecret -}}
{{- .Values.secret.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "signari.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Refuse to render an unsafe deployment. The two values here are the ones whose
absence is not a warning but a broken or dangerous engine:
  - no DSN: the engine cannot start.
  - no root key: a generated-on-boot key would invalidate every stored signing
    key on every restart, so it must be supplied and stable.
Fail at template time, where the operator sees it, rather than at pod crash.
*/}}
{{- define "signari.validate" -}}
{{- if not .Values.issuer -}}
{{- fail "signari: .Values.issuer is required (the public https URL, e.g. https://auth.example.com)" -}}
{{- end -}}
{{- if not .Values.secret.existingSecret -}}
{{- if not .Values.secret.dsn -}}
{{- fail "signari: set secret.dsn or secret.existingSecret -- the engine cannot start without a database" -}}
{{- end -}}
{{- if not .Values.secret.rootKey -}}
{{- fail "signari: set secret.rootKey or secret.existingSecret -- a generated-on-boot key would invalidate every signing key on restart" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.adminApi.enabled (not .Values.tls.certSecretName) (not .Values.adminApi.insecure) -}}
{{- fail "signari: adminApi.enabled needs tls.certSecretName, since the engine refuses to serve the admin API in plaintext; set adminApi.insecure=true to ask for plaintext by name" -}}
{{- end -}}
{{- if and .Values.metrics.serviceMonitor.enabled (not .Values.metrics.enabled) -}}
{{- fail "signari: metrics.serviceMonitor.enabled needs metrics.enabled, or it monitors a service that does not exist" -}}
{{- end -}}
{{- if .Values.console.enabled -}}
{{- if not .Values.console.url -}}
{{- fail "signari: console.enabled needs console.url, the address operators open it at" -}}
{{- end -}}
{{- if not .Values.console.database.host -}}
{{- fail "signari: console.enabled needs console.database.host; it connects as signari_admin and nothing wider" -}}
{{- end -}}
{{- if and (not .Values.console.secret.existingSecret) (or (not .Values.console.secret.appKey) (not .Values.console.secret.dbPassword)) -}}
{{- fail "signari: console.enabled needs console.secret.appKey and console.secret.dbPassword, or console.secret.existingSecret" -}}
{{- end -}}
{{- if and (not .Values.console.adminUrl) (not .Values.adminApi.enabled) -}}
{{- fail "signari: console.enabled writes through the Admin API; enable adminApi or give console.adminUrl" -}}
{{- end -}}
{{- end -}}
{{- range $k, $v := .Values.extraEnv -}}
{{- if has $k (list "SIGNARI_SHUTDOWN_DRAIN" "SIGNARI_SHUTDOWN_TIMEOUT") -}}
{{- fail (printf "signari: set %s through shutdown.drainSeconds and shutdown.timeoutSeconds, not extraEnv, so the pod's grace period follows it" $k) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
The pod's grace period: the drain, then the request timeout, then five seconds
for the process to exit. Shorter, and the kubelet's SIGKILL lands on requests
the engine is still finishing.
*/}}
{{- define "signari.gracePeriod" -}}
{{- add (int .Values.shutdown.drainSeconds) (int .Values.shutdown.timeoutSeconds) 5 -}}
{{- end -}}
