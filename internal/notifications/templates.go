package notifications

import (
	"bytes"
	"embed"
	"html/template"

	"github.com/pilab-dev/shadow-sso/port"
)

//go:embed templates/*.html
var emailTemplatesFS embed.FS

// emailTemplateData holds template variables.
type emailTemplateData struct {
	Name   string
	Link   string
	OTP    string
	Method string
}

func renderEmailTemplate(name string, data emailTemplateData, loader port.TemplateLoader) (string, error) {
	var tmpl *template.Template
	var err error
	if loader != nil {
		b, err := loader.Read("email/" + name)
		if err == nil {
			tmpl, err = template.New(name).Parse(string(b))
		}
	}
	if tmpl == nil {
		f, err := emailTemplatesFS.Open("templates/" + name)
		if err != nil {
			return "", err
		}
		defer f.Close()
		info, _ := f.Stat()
		buf := make([]byte, info.Size())
		_, _ = f.Read(buf)
		tmpl, err = template.New(name).Parse(string(buf))
		if err != nil {
			return "", err
		}
	}
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}