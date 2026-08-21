{{/*
Expand the name of the chart.
*/}}
{{- define "krawl.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "krawl.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "krawl.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "krawl.labels" -}}
helm.sh/chart: {{ include "krawl.chart" . }}
{{ include "krawl.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "krawl.selectorLabels" -}}
app.kubernetes.io/name: {{ include "krawl.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "krawl.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "krawl.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Resolve the PostgreSQL Secret name to reference for credentials.
Prefers an operator-supplied existing Secret; falls back to the chart-managed
Secret. Returns the Secret name and key as a pair via a dict so templates can
share the same resolution logic.
*/}}
{{- define "krawl.postgres.secret" -}}
{{- $name := .Values.postgres.existingSecret.name | default (printf "%s-postgres" (include "krawl.fullname" .)) }}
{{- $key := .Values.postgres.existingSecret.passwordKey | default "postgres-password" }}
{{- dict "name" $name "key" $key | toJson }}
{{- end }}

{{/*
Resolve the Redis Secret name/key to reference for credentials.
*/}}
{{- define "krawl.redis.secret" -}}
{{- $name := .Values.redis.existingSecret.name | default (printf "%s-redis" (include "krawl.fullname" .)) }}
{{- $key := .Values.redis.existingSecret.passwordKey | default "redis-password" }}
{{- dict "name" $name "key" $key | toJson }}
{{- end }}

{{/*
Resolve the Dashboard password Secret name/key to reference.
*/}}
{{- define "krawl.dashboard.secret" -}}
{{- $name := .Values.dashboardExistingSecret.name | default (printf "%s-dashboard" (include "krawl.fullname" .)) }}
{{- $key := .Values.dashboardExistingSecret.passwordKey | default "dashboard-password" }}
{{- dict "name" $name "key" $key | toJson }}
{{- end }}

{{/*
Resolve the Dashboard secret path Secret name/key to reference.
Empty when no external Secret is configured (path auto-generates from config).
*/}}
{{- define "krawl.dashboardPath.secret" -}}
{{- $name := ternary .Values.dashboardExistingSecret.name "" (not (empty .Values.dashboardExistingSecret.pathKey)) }}
{{- $key := .Values.dashboardExistingSecret.pathKey | default "dashboard-path" }}
{{- dict "name" $name "key" $key | toJson }}
{{- end }}

{{/*
Resolve the AI API key Secret name/key to reference.
*/}}
{{- define "krawl.ai.secret" -}}
{{- $name := .Values.aiExistingSecret.name | default (printf "%s-ai" (include "krawl.fullname" .)) }}
{{- $key := .Values.aiExistingSecret.key | default "ai-api-key" }}
{{- dict "name" $name "key" $key | toJson }}
{{- end }}

{{/*
Resolve the canary token URL Secret name/key to reference.
*/}}
{{- define "krawl.canary.secret" -}}
{{- $name := .Values.canaryExistingSecret.name | default (ternary (printf "%s-canary" (include "krawl.fullname" .)) "" (not (empty .Values.canaryTokenUrl))) }}
{{- $key := .Values.canaryExistingSecret.key | default "canary-token-url" }}
{{- dict "name" $name "key" $key | toJson }}
{{- end }}

{{/*
Resolve the CloudFlare credentials Secret name to reference.
*/}}
{{- define "krawl.cloudflare.secret" -}}
{{- .Values.cloudflare.existingSecret.name | default (printf "%s-cloudflare" (include "krawl.fullname" .)) }}
{{- end }}
