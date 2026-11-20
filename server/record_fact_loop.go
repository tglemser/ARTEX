package server

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/agent"
)

// recordFactLoopLimit is the number of consecutive record_fact calls refused
// with the same input-contract error after which the intent is stopped.
const recordFactLoopLimit = 2

// recordFactLoopGuard watches one intent run's record_fact results. A model
// that keeps sending a shape the tool refuses (observed: 156 identical
// refusals in one run, 7.3 M input tokens) gets no third attempt: the second
// consecutive refusal of the same class cancels the run with
// agent.AbortWorkRecordFactLoop, and the engine settles the intent as blocked.
// A successful record_fact resets the count; other tools and other error
// classes (an unreachable database, say) are not counted. One guard per run,
// shared across the model_error reruns of that run.
type recordFactLoopGuard struct {
	mu     sync.Mutex
	last   string
	count  int
	label  string
	cancel context.CancelCauseFunc
}

func newRecordFactLoopGuard(label string, cancel context.CancelCauseFunc) *recordFactLoopGuard {
	if cancel == nil {
		return nil
	}
	return &recordFactLoopGuard{label: label, cancel: cancel}
}

// recordFactErrorKey classifies a record_fact result: "" for a success or a
// failure that is not an input-contract error, otherwise a key that is equal
// for errors of the same kind. The result may be wrapped in the untrusted-output
// boundary; only the tool's own text is read.
func recordFactErrorKey(result []byte, isErr bool) string {
	if !isErr {
		return ""
	}
	msg := string(result)
	const prefix = "invalid record_fact input:"
	if i := strings.Index(msg, prefix); i >= 0 {
		msg = msg[i+len(prefix):]
		if end := strings.Index(msg, "; no facts were written"); end >= 0 {
			msg = msg[:end]
		}
		msg = strings.TrimSpace(msg)
		// Map iteration and the model's wording vary which top-level field is
		// named first; the structural mistake is the same one.
		if strings.Contains(msg, "top-level field") || strings.Contains(msg, "top level") {
			return "top-level-fields-in-batch"
		}
		return "input: " + msg
	}
	// A batch refused per item: {"ids":[...],"errors":{"0":"..."},...}. Index
	// and wording aside, the same set of item errors is the same mistake.
	var batch struct {
		Errors map[string]string `json:"errors"`
	}
	if i := strings.Index(msg, "{"); i >= 0 {
		if end := strings.LastIndex(msg, "}"); end > i {
			if json.Unmarshal([]byte(msg[i:end+1]), &batch) == nil && len(batch.Errors) > 0 {
				var errs []string
				for _, e := range batch.Errors {
					errs = append(errs, e)
				}
				sort.Strings(errs)
				return "items: " + strings.Join(errs, " | ")
			}
		}
	}
	return ""
}

func (g *recordFactLoopGuard) observe(name string, result []byte, isErr bool) {
	if g == nil || name != "record_fact" {
		return
	}
	key := recordFactErrorKey(result, isErr)
	g.mu.Lock()
	if key == "" {
		if !isErr {
			g.last, g.count = "", 0 // a written fact is progress; the loop is broken
		}
		g.mu.Unlock()
		return
	}
	if key == g.last {
		g.count++
	} else {
		g.last, g.count = key, 1
	}
	count := g.count
	g.mu.Unlock()
	if count == recordFactLoopLimit {
		log.Printf("[work %s] record_fact refused %d times in a row with the same input error (%s); stopping this intent", g.label, count, key)
		g.cancel(agent.Causef(agent.AbortCodeRecordFactLoop, agent.AbortWorkRecordFactLoop.Short,
			"%s Repeated error class: %s", agent.AbortWorkRecordFactLoop.Text, key))
	}
}
