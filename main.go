package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	pluginName            = "grok-sso-importer"
	pluginVersion         = "0.1.4"
	managementRoutePrefix = "/plugins/" + pluginName
)

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case methodPluginRegister, methodPluginReconfigure:
		return okEnvelope(registration{
			SchemaVersion: schemaVersion,
			Metadata: metadata{
				Name: pluginName, Version: pluginVersion, Author: "Sakuralaaa",
				GitHubRepository: "https://github.com/Sakuralaaa/grok-sso-importer", ConfigFields: []interface{}{},
			},
			Capabilities: registrationCapabilities{ManagementAPI: true},
		})
	case methodManagementRegister:
		return okEnvelope(managementRegistration{
			Routes: []managementRoute{
				{Method: http.MethodGet, Path: managementRoutePrefix + "/status", Description: "Get Grok SSO import status."},
				{Method: http.MethodPost, Path: managementRoutePrefix + "/import", Description: "Convert Grok SSO cookies and import xAI OAuth credentials."},
			},
			Resources: []resourceRoute{{Path: "/status", Menu: "Grok SSO 导入", Description: "粘贴或上传 TXT，转换并导入 xAI OAuth 凭证。"}},
		})
	case methodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func handleManagement(raw []byte) ([]byte, error) {
	var req managementRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, fmt.Errorf("decode management request: %w", err)
		}
	}
	return okEnvelope(dispatchManagement(req))
}

func dispatchManagement(req managementRequest) managementResponse {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	switch {
	case method == http.MethodGet && matchesResourcePath(req.Path, "/status"):
		return htmlResponse(http.StatusOK, uiPage)
	case method == http.MethodGet && matchesManagementPath(req.Path, "/status"):
		return jsonResponse(http.StatusOK, importer.snapshot())
	case method == http.MethodPost && matchesManagementPath(req.Path, "/import"):
		var body importRequest
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return jsonResponse(http.StatusBadRequest, map[string]any{"error": err.Error()})
		}
		if err := importer.start(body); err != nil {
			return jsonResponse(http.StatusConflict, map[string]any{"error": err.Error()})
		}
		return jsonResponse(http.StatusAccepted, map[string]any{"ok": true, "accepted": true})
	default:
		return jsonResponse(http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

func matchesManagementPath(path, suffix string) bool {
	path = strings.TrimRight(strings.TrimSpace(strings.SplitN(path, "?", 2)[0]), "/")
	return path == managementRoutePrefix+suffix || path == "/v0/management"+managementRoutePrefix+suffix
}

func matchesResourcePath(path, suffix string) bool {
	return strings.TrimRight(strings.TrimSpace(path), "/") == "/v0/resource/plugins/"+pluginName+suffix
}

func okEnvelope(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func jsonResponse(status int, payload any) managementResponse {
	raw, _ := json.Marshal(payload)
	return managementResponse{StatusCode: status, Headers: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}}, Body: raw}
}

func htmlResponse(status int, body []byte) managementResponse {
	return managementResponse{StatusCode: status, Headers: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}, Body: body}
}
