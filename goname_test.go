package goname

import (
	"fmt"
	"net/http"
	// "reflect"
	"regexp"
	"testing"
	// "time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

var (
	mockUsername     = "test-user"
	mockAPIKey       = "test-key"
	mockSessionToken = "abcdef"
	mockBaseURL      = "test://"
)

// NewMock creates a new GoName client with mocked config
func NewMock() *GoName {
	n := New(mockUsername, mockAPIKey)
	n.BaseURL = mockBaseURL
	n.SessionToken = mockSessionToken

	mockTransport := httpmock.NewMockTransport()
	registerMockResponders(mockBaseURL, mockTransport)
	n.Client.Transport = mockTransport

	return n
}

func TestNew(t *testing.T) {
	n := New(mockUsername, mockAPIKey)

	assert.Equal(t, "test-user", n.Username)
	assert.Equal(t, "test-key", n.APIKey)
	assert.Equal(t, "", n.SessionToken)
	assert.Equal(t, NameAPIBaseURL, n.BaseURL)
}

func TestNewMock(t *testing.T) {
	n := NewMock()

	assert.Equal(t, mockUsername, n.Username)
	assert.Equal(t, mockAPIKey, n.APIKey)
	assert.Equal(t, mockSessionToken, n.SessionToken)
	assert.Equal(t, mockBaseURL, n.BaseURL)
}

func TestHello(t *testing.T) {
	n := NewMock()
	resp, err := n.Hello()

	assert.Nil(t, err)
	assert.Equal(t, Result{100, "Operation Successful"}, resp.Result)
	assert.Equal(t, "goname-test", resp.Service)
	assert.Equal(t, "today", resp.ServerDate)
	assert.Equal(t, "0", resp.Version)
	assert.Equal(t, "foo", resp.Language)
	assert.Equal(t, "127.0.0.1", resp.ClientIP)
}

func TestLogin(t *testing.T) {
	n := NewMock()
	n.SessionToken = ""
	assert.NotEqual(t, mockSessionToken, n.SessionToken)

	err := n.Login()

	assert.Nil(t, err)
	assert.Equal(t, mockSessionToken, n.SessionToken)
}

func TestLogout(t *testing.T) {
	n := NewMock()
	err := n.Logout()

	assert.Nil(t, err)
	assert.Equal(t, "", n.SessionToken)
	assert.NotEqual(t, mockSessionToken, n.SessionToken)
}

func TestAccount(t *testing.T) {
	n := NewMock()
	resp, err := n.Account()

	assert.Nil(t, err)
	assert.Equal(t, mockUsername, resp.Username)
	assert.Equal(t, "2018-01-01 12:00:00", resp.CreateDate)
	assert.Equal(t, "0", resp.DomainCount)
	assert.Equal(t, "0.00", resp.AccountCredit)
	assert.Equal(t, []Contact{
		{
			Type:      []string{"mock"},
			FirstName: "Test",
			LastName:  "User",
		},
	}, resp.Contacts)
}

func TestListDomains(t *testing.T) {
	n := NewMock()
	resp, err := n.ListDomains()

	assert.Nil(t, err)
	assert.Equal(t, Result{100, "Operation Successful"}, resp.Result)
	assert.Equal(t, map[string]Domain{
		"foo.mock": {
			TLD:        "mock",
			CreateDate: "2018-01-01 12:00:00",
			ExpireDate: "2019-01-01 12:00:00",
		},
		"bar.mock": {
			TLD:        "mock",
			CreateDate: "2018-01-01 12:00:00",
			ExpireDate: "2019-01-01 12:00:00",
			WhoisPrivacy: struct {
				Enabled    bool   `json:"enabled"`
				ExpireDate string `json:"expire_date"`
			}{
				true,
				"2018-06-01 12:00:00",
			},
			Addons: map[string]struct {
				Price string `json:"price"`
			}{
				"domain/renew":        {"4.99"},
				"whois_privacy/renew": {"1.99"},
			},
		},
	}, resp.Domains)
}

func TestListDNSRecords(t *testing.T) {
	n := NewMock()
	resp, err := n.ListDNSRecords("foo.mock")

	assert.Nil(t, err)
	assert.Equal(t, Result{100, "Operation Successful"}, resp.Result)
	assert.Equal(t, []DNSRecordResponse{
		{
			RecordID:   "1",
			Name:       "foo.mock",
			Type:       "A",
			Content:    "127.0.0.1",
			TTL:        "3600",
			CreateDate: "2018-01-01 12:00:00",
		},
		{
			RecordID:   "2",
			Name:       "foo.mock",
			Type:       "AAAA",
			Content:    "::1",
			TTL:        "3600",
			CreateDate: "2018-01-01 12:00:00",
		},
		{
			RecordID:   "3",
			Name:       "mail.foo.mock",
			Type:       "MX",
			Content:    "127.0.0.1",
			TTL:        "3600",
			CreateDate: "2018-01-01 12:00:00",
			Priority:   "10",
		},
		{
			RecordID:   "4",
			Name:       "www.foo.mock",
			Type:       "CNAME",
			Content:    "foo",
			TTL:        "3600",
			CreateDate: "2018-01-01 12:00:00",
		},
	}, resp.Records)
}

func TestCreateDNSRecord(t *testing.T) {
	n := NewMock()
	req := DNSRecordRequest{
		Hostname: "foo.mock",
		Type:     "txt",
		Content:  "lorem ipsum",
		TTL:      3600,
	}

	resp, err := n.CreateDNSRecord("foo.mock", req)

	assert.Nil(t, err)
	assert.Equal(t, Result{100, "Operation Successful"}, resp.Result)
	assert.Equal(t, 5, resp.RecordID)
	assert.Equal(t, "foo.mock", resp.Name)
	assert.Equal(t, "TXT", resp.Type)
	assert.Equal(t, 3600, resp.TTL)
	assert.Equal(t, "2018-01-01 12:00:00", resp.CreateDate)
}

func TestDeleteDNSRecord(t *testing.T) {
	n := NewMock()
	resp, err := n.DeleteDNSRecord("foo.mock", "5")

	assert.Nil(t, err)
	assert.Equal(t, Result{100, "Operation Successful"}, resp.Result)
}

func TestBuildURL(t *testing.T) {
	n := NewMock()

	assert.Equal(t, "test://foo/bar", n.buildURL("foo/bar"))
	assert.Equal(t, "test://foo/bar", n.buildURL("/foo/bar"))
	assert.Equal(t, "test://foo/bar", n.buildURL("////foo/bar"))
}

func TestResultFailed(t *testing.T) {
	r1 := Result{99, ""}
	r2 := Result{100, ""}
	r3 := Result{101, ""}
	r4 := Result{200, ""}

	assert.Equal(t, true, r1.Failed())
	assert.Equal(t, false, r2.Failed())
	assert.Equal(t, true, r3.Failed())
	assert.Equal(t, true, r4.Failed())
}

func TestResultString(t *testing.T) {
	r := Result{100, "Operation Successful"}
	assert.Equal(t, "100 Operation Successful", r.String())
}

func registerMockResponders(base string, transport *httpmock.MockTransport) {
	responses := []struct {
		Method                string
		Endpoint              string
		RequiresAuthorization bool
		Code                  int
		Response              string
	}{
		{http.MethodGet, "/api/hello", false, 200, `{"result":{"code":100,"message":"Operation Successful"},"service":"goname-test","server_date":"today","version":"0","language":"foo","client_ip":"127.0.0.1"}`},
		{http.MethodPost, "/api/login", false, 200, `{"result":{"code":100,"message":"Operation Successful"},"session_token":"abcdef"}`},
		{http.MethodGet, "/api/logout", false, 200, `{"result":{"code":100,"message":"Operation Successful"}}`},
		{http.MethodGet, "/api/account/get", true, 200, `{"result":{"code":100,"message":"Operation Successful"},"username":"test-user","create_date":"2018-01-01 12:00:00","domain_count":"0","account_credit":"0.00","contacts":[{"type":["mock"],"first_name":"Test","last_name":"User"}]}`},
		{http.MethodGet, "/api/domain/list", true, 200, `{"result":{"code":100,"message":"Operation Successful"},"domains":{"foo.mock":{"tld":"mock","create_date":"2018-01-01 12:00:00","expire_date":"2019-01-01 12:00:00"},"bar.mock":{"tld":"mock","create_date":"2018-01-01 12:00:00","expire_date":"2019-01-01 12:00:00","whois_privacy":{"enabled":true,"expire_date":"2018-06-01 12:00:00"},"addons":{"whois_privacy/renew":{"price":"1.99"},"domain/renew":{"price":"4.99"}}}}}`},
		{http.MethodGet, "/api/dns/list/foo.mock", true, 200, `{"result":{"code":100,"message":"Operation Successful"},"records":[{"record_id":"1","name":"foo.mock","type":"A","content":"127.0.0.1","ttl":"3600","create_date":"2018-01-01 12:00:00"},{"record_id":"2","name":"foo.mock","type":"AAAA","content":"::1","ttl":"3600","create_date":"2018-01-01 12:00:00"},{"record_id":"3","name":"mail.foo.mock","type":"MX","content":"127.0.0.1","ttl":"3600","create_date":"2018-01-01 12:00:00","priority":"10"},{"record_id":"4","name":"www.foo.mock","type":"CNAME","content":"foo","ttl":"3600","create_date":"2018-01-01 12:00:00"}]}`},
		{http.MethodGet, "/api/dns/list/bar.mock", true, 200, `{"result":{"code":100,"message":"Operation Successful"},"records":[]}`},
		{http.MethodPost, "/api/dns/create/foo.mock", true, 200, `{"result":{"code":100,"message":"Operation Successful"},"record_id":5,"name":"foo.mock","type":"TXT","content":"lorem ipsum","ttl":3600,"create_date":"2018-01-01 12:00:00"}`},
		{http.MethodPost, "/api/dns/delete/foo.mock", true, 200, `{"result":{"code":100,"message":"Operation Successful"}}`},
	}

	extraslash := regexp.MustCompile("([^:])//+")
	for r := range responses {
		match := responses[r]
		path := extraslash.ReplaceAllString(fmt.Sprintf("%v/%v", base, match.Endpoint), "$1/")
		transport.RegisterResponder(match.Method, path, func(req *http.Request) (*http.Response, error) {
			resp := httpmock.NewStringResponse(match.Code, match.Response)
			resp.Header.Add("Content-Type", "application/json")
			return resp, nil
		})
	}

	transport.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("no mock registered for this request")
	})
}
