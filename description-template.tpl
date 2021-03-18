{{- if gt (len .Alerts) 0 -}}
{{- range $severity, $alerts := (groupAlertsByLabel .Alerts "severity") -}}
{{- range $index, $alert := $alerts }}
Summary: {{ $alert.Annotations.summary }} Description: {{ $alert.Annotations.description }}
{{ end }}
{{ end }}
{{ else -}}
Status: OK
{{- end -}}
