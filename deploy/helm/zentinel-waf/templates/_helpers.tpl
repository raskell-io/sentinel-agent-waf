{{/*
Expand the name of the chart.
*/}}
{{- define "zentinel-waf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "zentinel-waf.fullname" -}}
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
{{- define "zentinel-waf.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "zentinel-waf.labels" -}}
helm.sh/chart: {{ include "zentinel-waf.chart" . }}
{{ include "zentinel-waf.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: zentinel
{{- end }}

{{/*
Selector labels
*/}}
{{- define "zentinel-waf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zentinel-waf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: waf
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "zentinel-waf.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "zentinel-waf.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image tag
*/}}
{{- define "zentinel-waf.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag }}
{{- end }}
