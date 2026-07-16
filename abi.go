package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

const (
	abiVersion              = 1
	schemaVersion           = 1
	methodPluginRegister    = "plugin.register"
	methodPluginReconfigure = "plugin.reconfigure"
	methodManagementRegister = "management.register"
	methodManagementHandle   = "management.handle"
	methodHostAuthList       = "host.auth.list"
	methodHostAuthGet        = "host.auth.get"
	methodHostAuthSave       = "host.auth.save"
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type metadata struct {
	Name             string        `json:"Name"`
	Version          string        `json:"Version"`
	Author           string        `json:"Author"`
	GitHubRepository string        `json:"GitHubRepository"`
	ConfigFields     []interface{} `json:"ConfigFields"`
}

type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      metadata                 `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}

type registrationCapabilities struct {
	ManagementAPI bool `json:"management_api"`
}

type managementRegistration struct {
	Routes    []managementRoute `json:"Routes"`
	Resources []resourceRoute   `json:"Resources"`
}

type managementRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Description string `json:"Description"`
}

type resourceRoute struct {
	Path        string `json:"Path"`
	Menu        string `json:"Menu"`
	Description string `json:"Description"`
}

type managementRequest struct {
	Method  string      `json:"Method"`
	Path    string      `json:"Path"`
	Headers http.Header `json:"Headers"`
	Query   url.Values  `json:"Query"`
	Body    []byte      `json:"Body"`
}

type managementResponse struct {
	StatusCode int         `json:"StatusCode"`
	Headers    http.Header `json:"Headers"`
	Body       []byte      `json:"Body"`
}

type authFileEntry struct {
	ID        string    `json:"id,omitempty"`
	AuthIndex string    `json:"auth_index,omitempty"`
	Name      string    `json:"name"`
	Type      string    `json:"type,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	Email     string    `json:"email,omitempty"`
	Path      string    `json:"path,omitempty"`
	Disabled  bool      `json:"disabled,omitempty"`
	ModTime   time.Time `json:"mod_time,omitempty"`
}

type authListResponse struct {
	Files []authFileEntry `json:"files"`
}

type authGetRequest struct {
	AuthIndex string `json:"auth_index"`
}

type authGetResponse struct {
	AuthIndex string          `json:"auth_index"`
	Name      string          `json:"name,omitempty"`
	Path      string          `json:"path,omitempty"`
	JSON      json.RawMessage `json:"json"`
}

type authSaveRequest struct {
	Name string          `json:"name"`
	JSON json.RawMessage `json:"json"`
}
