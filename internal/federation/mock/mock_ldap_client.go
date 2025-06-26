// Package mock_federation is a generated GoMock package.
package mock_federation

import (
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
	ldap "github.com/go-ldap/ldap/v3"
)

// MockLDAPClient is a mock of LDAPClient interface.
type MockLDAPClient struct {
	ctrl     *gomock.Controller
	recorder *MockLDAPClientMockRecorder
}

// MockLDAPClientMockRecorder is the mock recorder for MockLDAPClient.
type MockLDAPClientMockRecorder struct {
	mock *MockLDAPClient
}

// NewMockLDAPClient creates a new mock instance.
func NewMockLDAPClient(ctrl *gomock.Controller) *MockLDAPClient {
	mock := &MockLDAPClient{ctrl: ctrl}
	mock.recorder = &MockLDAPClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockLDAPClient) EXPECT() *MockLDAPClientMockRecorder {
	return m.recorder
}

// Bind mocks base method.
func (m *MockLDAPClient) Bind(username, password string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Bind", username, password)
	ret0, _ := ret[0].(error)
	return ret0
}

// Bind indicates an expected call of Bind.
func (mr *MockLDAPClientMockRecorder) Bind(username, password interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Bind", reflect.TypeOf((*MockLDAPClient)(nil).Bind), username, password)
}

// Close mocks base method.
func (m *MockLDAPClient) Close() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Close")
}

// Close indicates an expected call of Close.
func (mr *MockLDAPClientMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockLDAPClient)(nil).Close))
}

// Connect mocks base method.
func (m *MockLDAPClient) Connect(url string, startTLS, skipTLSVerify bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Connect", url, startTLS, skipTLSVerify)
	ret0, _ := ret[0].(error)
	return ret0
}

// Connect indicates an expected call of Connect.
func (mr *MockLDAPClientMockRecorder) Connect(url, startTLS, skipTLSVerify interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Connect", reflect.TypeOf((*MockLDAPClient)(nil).Connect), url, startTLS, skipTLSVerify)
}

// SearchUser mocks base method.
func (m *MockLDAPClient) SearchUser(baseDN, filter string, attributes []string) (*ldap.Entry, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SearchUser", baseDN, filter, attributes)
	ret0, _ := ret[0].(*ldap.Entry)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SearchUser indicates an expected call of SearchUser.
func (mr *MockLDAPClientMockRecorder) SearchUser(baseDN, filter, attributes interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SearchUser", reflect.TypeOf((*MockLDAPClient)(nil).SearchUser), baseDN, filter, attributes)
}
