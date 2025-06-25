{{/*
Expand the name of the chart.
*/}}
{{- define "ssso-backend.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "ssso-backend.fullname" -}}
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
{{- define "ssso-backend.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ssso-backend.labels" -}}
helm.sh/chart: {{ include "ssso-backend.chart" . }}
{{ include "ssso-backend.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ssso-backend.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ssso-backend.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "ssso-backend.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ssso-backend.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the MongoDB connection URI.
If mongodb.enabled is true, it constructs a URI for the in-cluster MongoDB.
Otherwise, it uses the URI from the main config.
*/}}
{{- define "ssso-backend.mongodb.uri" -}}
{{- if .Values.mongodb.enabled -}}
  {{- if .Values.mongodb.connection.uriOverride -}}
    {{- .Values.mongodb.connection.uriOverride -}}
  {{- else -}}
    {{- $mongodbFullname := printf "%s-mongodb" (include "ssso-backend.fullname" .) -}}
    {{- $database := .Values.mongodb.connection.databaseName | default "shadow_sso_db" -}}
    {{- /* This is a simplified example; Bitnami chart might have different service names/auth */ -}}
    {{- /* You'd typically get this from the subchart's outputs or known service name */ -}}
    {{- printf "mongodb://%s/%s" $mongodbFullname $database -}}
    {{- /* Add auth parameters if mongodb.auth.enabled is true in a subchart scenario */ -}}
  {{- end -}}
{{- else -}}
  {{- .Values.config.SSSO_MONGO_URI | default "" -}}
{{- end -}}
{{- end -}}

{{/*
Return the MongoDB database name.
*/}}
{{- define "ssso-backend.mongodb.databaseName" -}}
{{- if .Values.mongodb.enabled -}}
  {{- .Values.mongodb.connection.databaseName | default "shadow_sso_db" -}}
{{- else -}}
  {{- .Values.config.SSSO_MONGO_DB_NAME | default "shadow_sso_db" -}}
{{- end -}}
{{- end -}}
