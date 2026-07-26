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
{{- $name := .Values.postgres.existingSecret | default (printf "%s-postgres" (include "krawl.fullname" .)) }}
{{- $key := .Values.postgres.existingSecretKey | default "postgres-password" }}
{{- dict "name" $name "key" $key | toJson }}
{{- end }}

{{/*
Resolve the Redis Secret name/key to reference for credentials.
*/}}
{{- define "krawl.redis.secret" -}}
{{- $name := .Values.redis.existingSecret | default (printf "%s-redis" (include "krawl.fullname" .)) }}
{{- $key := .Values.redis.existingSecretKey | default "redis-password" }}
{{- dict "name" $name "key" $key | toJson }}
{{- end }}

{{/*
Resolve the Dashboard password Secret name/key to reference.
*/}}
{{- define "krawl.dashboard.secret" -}}
{{- $name := .Values.dashboardExistingSecret | default (printf "%s-dashboard" (include "krawl.fullname" .)) }}
{{- $key := .Values.dashboardExistingSecretKey | default "dashboard-password" }}
{{- dict "name" $name "key" $key | toJson }}
{{- end }}

{{/*
Resolve the Dashboard secret path Secret name/key to reference.
Empty when no external Secret is configured (path auto-generates from config).
*/}}
{{- define "krawl.dashboardPath.secret" -}}
{{- $name := .Values.dashboardPathExistingSecret | default "" }}
{{- $key := .Values.dashboardPathExistingSecretKey | default "dashboard-path" }}
{{- dict "name" $name "key" $key | toJson }}
{{- end }}
