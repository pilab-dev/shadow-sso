package cmd

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// formKind is the input type rendered by the wizard.
type formKind int

const (
	formText formKind = iota
	formSelect
	formMulti
	formBool
)

// formField describes one wizard step.
type formField struct {
	key          string
	label        string
	help         string
	kind         formKind
	required     bool
	options      []string
	defaultValue string
	validate     func(string) error
}

// formModel is a small survey-style form built directly on bubbletea.
type formModel struct {
	title   string
	fields  []formField
	idx     int
	edit    string
	cursor  int
	values  map[string]string
	multi   map[string]map[string]bool
	err     string
	summary bool
	done    bool
	cancel  bool
	// result is populated once the user confirms.
	result map[string]string
}

func newFormModel(title string, fields []formField, initial map[string]string) *formModel {
	m := &formModel{
		title:  title,
		fields: fields,
		values: map[string]string{},
		multi:  map[string]map[string]bool{},
	}
	for _, f := range fields {
		if v, ok := initial[f.key]; ok {
			m.values[f.key] = v
		} else {
			m.values[f.key] = f.defaultValue
		}
		if f.kind == formMulti {
			selected := map[string]bool{}
			for _, opt := range strings.Split(m.values[f.key], ",") {
				opt = strings.TrimSpace(opt)
				if opt != "" {
					selected[opt] = true
				}
			}
			m.multi[f.key] = selected
		}
	}
	m.loadCurrent()
	return m
}

func (m *formModel) current() formField { return m.fields[m.idx] }

func (m *formModel) loadCurrent() {
	if m.idx < 0 || m.idx >= len(m.fields) {
		return
	}
	f := m.current()
	switch f.kind {
	case formText:
		m.edit = m.values[f.key]
	case formMulti:
		var parts []string
		for _, opt := range f.options {
			if m.multi[f.key][opt] {
				parts = append(parts, opt)
			}
		}
		m.values[f.key] = strings.Join(parts, ",")
	case formSelect:
		m.cursor = 0
		for i, opt := range f.options {
			if opt == m.values[f.key] {
				m.cursor = i
			}
		}
	case formBool:
		if m.values[f.key] == "" {
			m.values[f.key] = "false"
		}
	}
}

func (m *formModel) validateCurrent() bool {
	f := m.current()
	value := m.values[f.key]
	if f.kind == formMulti && m.multi[f.key] != nil {
		var parts []string
		for _, opt := range f.options {
			if m.multi[f.key][opt] {
				parts = append(parts, opt)
			}
		}
		value = strings.Join(parts, ",")
	}
	if f.required && strings.TrimSpace(value) == "" {
		m.err = f.label + " is required"
		return false
	}
	if f.validate != nil {
		if err := f.validate(value); err != nil {
			m.err = err.Error()
			return false
		}
	}
	m.values[f.key] = value
	m.err = ""
	return true
}

// next advances to the following field, or to the summary when done.
func (m *formModel) next() {
	if !m.validateCurrent() {
		return
	}
	if m.idx == len(m.fields)-1 {
		m.summary = true
		return
	}
	m.idx++
	m.loadCurrent()
}

// back returns to the previous field (or leaves the summary).
func (m *formModel) back() {
	if m.summary {
		m.summary = false
		m.loadCurrent()
		return
	}
	if m.idx == 0 {
		return
	}
	m.idx--
	m.loadCurrent()
}

func (m *formModel) Init() tea.Cmd { return nil }

func (m *formModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "ctrl+c":
		m.cancel = true
		return m, tea.Quit
	case "esc":
		m.back()
		return m, nil
	case "shift+tab":
		m.back()
		return m, nil
	}

	if m.summary {
		switch key.String() {
		case "y", "Y", "enter":
			m.result = map[string]string{}
			for k, v := range m.values {
				m.result[k] = v
			}
			m.done = true
			return m, tea.Quit
		case "n", "N":
			m.summary = false
			m.loadCurrent()
		}
		return m, nil
	}

	f := m.current()
	switch f.kind {
	case formText:
		switch key.String() {
		case "enter":
			m.next()
		case "backspace":
			r := []rune(m.edit)
			if len(r) > 0 {
				m.edit = string(r[:len(r)-1])
			}
			m.values[f.key] = m.edit
		case " ":
			m.edit += " "
			m.values[f.key] = m.edit
		default:
			if key.Type == tea.KeyRunes {
				m.edit += string(key.Runes)
				m.values[f.key] = m.edit
			}
		}
	case formSelect:
		switch key.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(f.options)-1 {
				m.cursor++
			}
		case "enter":
			m.values[f.key] = f.options[m.cursor]
			m.next()
		}
	case formMulti:
		switch key.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(f.options)-1 {
				m.cursor++
			}
		case " ":
			opt := f.options[m.cursor]
			m.multi[f.key][opt] = !m.multi[f.key][opt]
		case "enter":
			m.next()
		}
	case formBool:
		switch key.String() {
		case "y", "Y":
			m.values[f.key] = "true"
		case "n", "N":
			m.values[f.key] = "false"
		case "left", "right", " ":
			if m.values[f.key] == "true" {
				m.values[f.key] = "false"
			} else {
				m.values[f.key] = "true"
			}
		case "enter":
			m.next()
		}
	}
	return m, nil
}

func (m *formModel) View() string {
	var b strings.Builder
	b.WriteString("\n  ")
	b.WriteString(titleStyle(m.title))
	b.WriteString("\n\n")

	if m.summary {
		b.WriteString("  Review\n\n")
		for _, f := range m.fields {
			b.WriteString(fmt.Sprintf("  %-24s %s\n", f.label+":", m.values[f.key]))
		}
		b.WriteString("\n  Press enter/y to confirm, n to go back, ctrl+c to cancel.\n")
		if m.err != "" {
			b.WriteString("\n  ! " + m.err + "\n")
		}
		return b.String()
	}

	f := m.current()
	b.WriteString(fmt.Sprintf("  Step %d/%d\n\n", m.idx+1, len(m.fields)))
	b.WriteString("  " + f.label)
	if f.required {
		b.WriteString(" *")
	}
	b.WriteString("\n")

	switch f.kind {
	case formText:
		b.WriteString("  > " + m.edit + "█\n")
	case formSelect:
		for i, opt := range f.options {
			marker := "  "
			if i == m.cursor {
				marker = "> "
			}
			b.WriteString(fmt.Sprintf("  %s%s\n", marker, opt))
		}
	case formMulti:
		for i, opt := range f.options {
			marker := "  "
			if i == m.cursor {
				marker = "> "
			}
			check := "[ ]"
			if m.multi[f.key][opt] {
				check = "[x]"
			}
			b.WriteString(fmt.Sprintf("  %s%s %s\n", marker, check, opt))
		}
	case formBool:
		value := "no"
		if m.values[f.key] == "true" {
			value = "yes"
		}
		b.WriteString("  > " + value + "   (space/y/n toggles)\n")
	}

	if f.help != "" {
		b.WriteString("\n  " + f.help + "\n")
	}
	if m.err != "" {
		b.WriteString("\n  ! " + m.err + "\n")
	}
	b.WriteString("\n  enter next · shift+tab back · esc back · ctrl+c cancel\n")
	return b.String()
}

// titleStyle is intentionally minimal: the CLI must also work when colors are
// stripped (pipes, CI, screen readers).
func titleStyle(s string) string { return "── " + s + " ──" }

// runForm executes the wizard and returns the collected values.
func runForm(title string, fields []formField, initial map[string]string) (map[string]string, error) {
	if !interactive() {
		var missing []string
		for _, f := range fields {
			if f.required {
				missing = append(missing, "--"+strings.ReplaceAll(f.key, "_", "-"))
			}
		}
		return nil, requireInteractive(title, missing...)
	}
	model := newFormModel(title, fields, initial)
	program := tea.NewProgram(model)
	final, err := program.Run()
	if err != nil {
		return nil, err
	}
	m, ok := final.(*formModel)
	if !ok || m.cancel || !m.done {
		return nil, errCancelled
	}
	return m.result, nil
}
