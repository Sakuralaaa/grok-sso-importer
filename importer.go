package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type importRequest struct {
	Content string `json:"content"`
	Workers int    `json:"workers"`
	Proxy   string `json:"proxy"`
}

type importResult struct {
	Index    int    `json:"index"`
	OK       bool   `json:"ok"`
	FileName string `json:"file_name,omitempty"`
	Email    string `json:"email,omitempty"`
	Subject  string `json:"subject,omitempty"`
	Error    string `json:"error,omitempty"`
}

type importSnapshot struct {
	Running    bool           `json:"running"`
	Done       int            `json:"done"`
	Total      int            `json:"total"`
	Success    int            `json:"success"`
	Failed     int            `json:"failed"`
	StartedAt  string         `json:"started_at,omitempty"`
	FinishedAt string         `json:"finished_at,omitempty"`
	Results    []importResult `json:"results"`
}

type importEngine struct {
	mu         sync.Mutex
	running    bool
	done       int
	total      int
	success    int
	failed     int
	startedAt  string
	finishedAt string
	results    []importResult
}

var importer = &importEngine{}

func (e *importEngine) snapshot() importSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return importSnapshot{
		Running: e.running, Done: e.done, Total: e.total, Success: e.success, Failed: e.failed,
		StartedAt: e.startedAt, FinishedAt: e.finishedAt, Results: append([]importResult(nil), e.results...),
	}
}

func (e *importEngine) start(req importRequest) error {
	tokens := parseSSOLines(req.Content)
	if len(tokens) == 0 {
		return fmt.Errorf("no SSO tokens found")
	}
	workers := req.Workers
	if workers == 0 {
		workers = 2
	}
	if workers < 1 || workers > 8 {
		return fmt.Errorf("workers must be between 1 and 8")
	}
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return fmt.Errorf("an import is already running")
	}
	e.running, e.done, e.total, e.success, e.failed = true, 0, len(tokens), 0, 0
	e.startedAt, e.finishedAt, e.results = time.Now().Format(time.RFC3339), "", nil
	e.mu.Unlock()
	go e.run(tokens, workers, strings.TrimSpace(req.Proxy))
	return nil
}

func (e *importEngine) run(tokens []string, workers int, proxy string) {
	jobs := make(chan int)
	results := make(chan importResult, len(tokens))
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				results <- convertAndSave(index+1, tokens[index], proxy)
			}
		}()
	}
	go func() {
		for index := range tokens {
			jobs <- index
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	for result := range results {
		e.mu.Lock()
		e.results = append(e.results, result)
		e.done++
		if result.OK {
			e.success++
		} else {
			e.failed++
		}
		e.mu.Unlock()
	}
	e.mu.Lock()
	sort.Slice(e.results, func(i, j int) bool { return e.results[i].Index < e.results[j].Index })
	e.running = false
	e.finishedAt = time.Now().Format(time.RFC3339)
	e.mu.Unlock()
}

func convertAndSave(index int, sso, proxy string) importResult {
	result := importResult{Index: index}
	token, err := exchangeSSO(sso, proxy)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	credential, fileName, email, subject, err := credentialFromToken(token)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	raw, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		result.Error = "encode credential: " + err.Error()
		return result
	}
	if _, err := callHost(methodHostAuthSave, authSaveRequest{Name: fileName, JSON: append(raw, '\n')}); err != nil {
		result.Error = "import into CPA: " + err.Error()
		return result
	}
	result.OK, result.FileName, result.Email, result.Subject = true, fileName, email, subject
	return result
}

func parseSSOLines(content string) []string {
	seen := make(map[string]struct{})
	var out []string
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "----") {
			parts := strings.Split(line, "----")
			line = strings.TrimSpace(parts[len(parts)-1])
		}
		if line == "" {
			continue
		}
		if _, exists := seen[line]; exists {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out
}
