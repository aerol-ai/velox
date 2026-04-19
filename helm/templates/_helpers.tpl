{{/*
Expand the name of the chart.
*/}}
{{- define "velox.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this.
*/}}
{{- define "velox.fullname" -}}
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
Create chart label.
*/}}
{{- define "velox.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "velox.labels" -}}
helm.sh/chart: {{ include "velox.chart" . }}
{{ include "velox.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "velox.selectorLabels" -}}
app.kubernetes.io/name: {{ include "velox.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "velox.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "velox.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Build the list of args for the velox server command.
*/}}
{{- define "velox.serverArgs" -}}
- /home/app/velox
- server
- "ws://0.0.0.0:{{ .Values.service.containerPort }}"
{{- if .Values.velox.logLevel }}
- "--log-lvl"
- {{ .Values.velox.logLevel | quote }}
{{- end }}
{{- if .Values.velox.httpUpgradePathPrefix }}
- "--restrict-http-upgrade-path-prefix"
- {{ .Values.velox.httpUpgradePathPrefix | quote }}
{{- end }}
{{- range .Values.velox.restrictTo }}
- "--restrict-to"
- {{ . | quote }}
{{- end }}
{{- if .Values.velox.restrictConfig.enabled }}
- "--restrict-config"
- "/etc/velox/restrictions.yaml"
{{- end }}
{{- if .Values.velox.quic.enabled }}
- "--quic-bind"
- {{ printf "0.0.0.0:%d" (int .Values.velox.quic.port) | quote }}
{{- with .Values.velox.quic.keepAlive }}
- "--quic-keep-alive"
- {{ . | quote }}
{{- end }}
{{- with .Values.velox.quic.maxIdleTimeout }}
- "--quic-max-idle-timeout"
- {{ . | quote }}
{{- end }}
{{- with .Values.velox.quic.maxStreams }}
- "--quic-max-streams"
- {{ . | quote }}
{{- end }}
{{- with .Values.velox.quic.datagramBufferSize }}
- "--quic-datagram-buffer-size"
- {{ . | quote }}
{{- end }}
{{- if .Values.velox.quic.zeroRtt }}
- "--quic-0rtt"
{{- end }}
{{- if .Values.velox.quic.disableMigration }}
- "--quic-disable-migration"
{{- end }}
{{- end }}
{{- range .Values.velox.extraArgs }}
- {{ . | quote }}
{{- end }}
{{- end }}
