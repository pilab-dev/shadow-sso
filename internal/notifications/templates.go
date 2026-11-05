package notifications

import (
	"bytes"
	"embed"
	"html/template"
	"io/fs"

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
	raw, err := readEmailTemplate(name, loader)
	if err != nil {
		return "", err
	}
	tmpl, err := template.New(name).Parse(string(raw))
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

func readEmailTemplate(name string, loader port.TemplateLoader) ([]byte, error) {
	if loader != nil {
		if b, err := loader.Read("email/" + name); err == nil {
			return b, nil
		}
	}
	return fs.ReadFile(emailTemplatesFS, "templates/"+name)
}