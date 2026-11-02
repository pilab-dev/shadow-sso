package cmd

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormModel_TextFlowToSummary(t *testing.T) {
	m := newFormModel("test", []formField{
		{key: "name", label: "Name", kind: formText, required: true},
		{key: "type", label: "Type", kind: formSelect, options: []string{"a", "b"}, defaultValue: "a"},
	}, nil)

	// Type a name and continue.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("my-app")})
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	assert.False(t, m.summary)
	assert.Equal(t, 1, m.idx)

	// Select the second option.
	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	assert.True(t, m.summary)

	// Confirm.
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	assert.True(t, m.done)
	require.NotNil(t, m.result)
	assert.Equal(t, "my-app", m.result["name"])
	assert.Equal(t, "b", m.result["type"])
}

func TestFormModel_RequiredValidation(t *testing.T) {
	m := newFormModel("test", []formField{
		{key: "name", label: "Name", kind: formText, required: true},
	}, nil)

	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	assert.False(t, m.summary)
	assert.Contains(t, m.err, "required")
}

func TestFormModel_MultiSelectToggles(t *testing.T) {
	m := newFormModel("test", []formField{
		{key: "g", label: "Grants", kind: formMulti, options: []string{"a", "b", "c"}, defaultValue: "a"},
	}, nil)

	// Cursor starts on "a"; move to "b" and toggle it on.
	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})

	assert.True(t, m.summary)
	assert.Equal(t, "a,b", m.values["g"])
}

func TestRunForm_NonInteractiveListsRequiredFlags(t *testing.T) {
	old := noInteractive
	noInteractive = true
	defer func() { noInteractive = old }()

	_, err := runForm("test form", []formField{
		{key: "name", label: "Name", kind: formText, required: true},
		{key: "type", label: "Type", kind: formText, required: true},
		{key: "optional", label: "Optional", kind: formText},
	}, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "--name")
	assert.Contains(t, err.Error(), "--type")
	assert.NotContains(t, err.Error(), "--optional")
}

func TestReadDataFlag_LiteralAndEmpty(t *testing.T) {
	data, err := readDataFlag(`{"a":1}`)
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":1}`, string(data))

	data, err = readDataFlag("")
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(data))
}
