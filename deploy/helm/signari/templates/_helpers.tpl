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
{{- end -}}
