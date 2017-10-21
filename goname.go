package goname

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

const (
	// NameAPIBaseURL Base URL to the production Name.com API
	NameAPIBaseURL = "https://api.name.com"

	// NameAPIBaseDevURL Base URL to the dev Name.com API
	NameAPIBaseDevURL = "https://api.dev.name.com"
)

// GoName API controller
type GoName struct {
	Client       *http.Client
	Username     string
	APIKey       string
	BaseURL      string
	SessionToken string
}

// BasicResponse response with no other details
type BasicResponse struct {
	Result Result `json:"result"`
}

// Result response details
type Result struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Failed returns true if the API reports the request completed with an error
func (r *Result) Failed() bool {
	return r.Code != 100
}

func (r *Result) String() string {
	return fmt.Sprintf("%v %v", r.Code, r.Message)
}

// HelloResponse response from /api/hello
type HelloResponse struct {
	Result     Result `json:"result"`
	Service    string `json:"service"`
	ServerDate string `json:"server_date"`
	Version    string `json:"version"`
	Language   string `json:"language"`
	ClientIP   string `json:"client_ip"`
}

// LoginResponse response from /api/login
type LoginResponse struct {
	Result       Result `json:"result"`
	SessionToken string `json:"session_token"`
}

// AccountResponse response from /api/account/get
type AccountResponse struct {
	Result        Result    `json:"result"`
	Username      string    `json:"username"`
	CreateDate    string    `json:"create_date"`
	DomainCount   string    `json:"domain_count"`
	AccountCredit string    `json:"account_credit"`
	Contacts      []Contact `json:"contacts"`
}

// Contact account and registrant contact information
type Contact struct {
	Type         []string `json:"type"`
	FirstName    string   `json:"first_name"`
	LastName     string   `json:"last_name"`
	Organization string   `json:"organization"`
	AddressLine1 string   `json:"addressline1"`
	AddressLine2 string   `json:"addressline2"`
	City         string   `json:"city"`
	State        string   `json:"state"`
	Phone        string   `json:"phone"`
	Fax          string   `json:"fax"`
	Email        string   `json:"email"`
}

// ListDomainsResponse response from /api/domains/list
type ListDomainsResponse struct {
	Result  Result            `json:"result"`
	Domains map[string]Domain `json:"domains"`
}

// Domain domain information
type Domain struct {
	TLD         string   `json:"tld"`
	CreateDate  string   `json:"create_date"`
	ExpireDate  string   `json:"expire_date"`
	Locked      bool     `json:"locked,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	Addons      map[string]struct {
		Price string `json:"price"`
	} `json:"addons,omitempty"`
	WhoisPrivacy struct {
		Enabled    bool   `json:"enabled"`
		ExpireDate string `json:"expire_date"`
	} `json:"whois_privacy,omitempty"`
	Username string    `json:"username,omitempty"`
	Contacts []Contact `json:"contacts,omitempty"`
}

// ListDNSRecordsResponse response from /api/dns/list/:name
type ListDNSRecordsResponse struct {
	Result  Result      `json:"result"`
	Records []DNSRecord `json:"records"`
}

// DNSRecord DNS record information
type DNSRecord struct {
	RecordID   string `json:"record_id"`
	Name       string `json:"name"`
	HostName   string `json:"hostname"`
	Type       string `json:"type"`
	Content    string `json:"content"`
	TTL        string `json:"ttl"`
	CreateDate string `json:"create_date"`
	Priority   string `json:"priority,omitempty"`
}

// CreateDNSRecordResponse response from /api/dns/create/:name
type CreateDNSRecordResponse struct {
	Result Result `json:"result"`
	DNSRecord
}

// Hello pings the name.com API
func (n *GoName) Hello() (data HelloResponse, err error) {
	err = n.get("/api/hello", &data)

	if data.Result.Failed() {
		return data, fmt.Errorf("api error: %v", data.Result)
	}

	return data, err
}

// Login logs the name.com API session in and sets the session token
func (n *GoName) Login() error {
	var data LoginResponse
	credentials := []byte(fmt.Sprintf(`{"username":"%s","api_token":"%s"}`, n.Username, n.APIKey))

	err := n.post("/api/login", credentials, &data)
	if err != nil {
		return err
	}

	if data.Result.Failed() {
		return fmt.Errorf("api error: %v", data.Result)
	}

	n.SessionToken = data.SessionToken
	return err
}

// Logout logs the name.com API session out
func (n *GoName) Logout() error {
	var data BasicResponse
	err := n.get("/api/logout", &data)
	return err
}

// Account retunrs the associated Name.com account information
func (n *GoName) Account() (data AccountResponse, err error) {
	err = n.get("/api/account/get", &data)
	return data, err
}

// ListDomains retrieves information about domains owned by an account
func (n *GoName) ListDomains() (data ListDomainsResponse, err error) {
	err = n.get("/api/domain/list", &data)
	return data, err
}

// ListDNSRecords retrives records created on supplied domain name
func (n *GoName) ListDNSRecords(domainName string) (data ListDNSRecordsResponse, err error) {
	err = n.get(fmt.Sprintf("/api/dns/list/%s", domainName), &data)
	return data, err
}

// CreateDNSRecord creates a record on a domain
func (n *GoName) CreateDNSRecord(domain string, record DNSRecord) (data CreateDNSRecordResponse, err error) {
	req, err := json.Marshal(record)
	if err != nil {
		return data, err
	}

	err = n.post(fmt.Sprintf("/api/dns/create/%s", domain), req, &data)
	if err != nil {
		return data, err
	}

	if data.Result.Failed() {
		return data, fmt.Errorf("api error: %v", data.Result)
	}

	return data, err
}

// DeleteDNSRecord deletes a record on a domain
func (n *GoName) DeleteDNSRecord(domain, recordID string) error {
	var data BasicResponse
	req := []byte(fmt.Sprintf(`{"record_id":"%s"}`, recordID))
	err := n.post(fmt.Sprintf("/api/dns/delete/%s", domain), req, &data)
	return err
}

func (n *GoName) get(url string, into interface{}) error {
	req, err := http.NewRequest(http.MethodGet, n.buildURL(url), nil)
	if err != nil {
		return err
	}

	requestErr := n.request(req, into)
	return requestErr
}

func (n *GoName) post(url string, body []byte, into interface{}) error {
	req, err := http.NewRequest(http.MethodPost, n.buildURL(url), bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	requestErr := n.request(req, into)
	return requestErr
}

func (n *GoName) request(req *http.Request, into interface{}) error {
	req.Header.Set("Api-Session-Token", n.SessionToken)

	resp, err := n.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf(resp.Status)
	}

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(into)

	return err
}

func (n *GoName) buildURL(url string) string {
	extraslash := regexp.MustCompile("([^:])//+")
	return extraslash.ReplaceAllString(fmt.Sprintf("%v/%v", n.BaseURL, url), "$1/")
}

// New creates a new instance of GoName
func New(username, key string) *GoName {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	return &GoName{
		Client:   client,
		Username: username,
		APIKey:   key,
		BaseURL:  NameAPIBaseURL,
	}
}
