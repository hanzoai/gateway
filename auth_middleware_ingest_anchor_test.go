package gateway

import (
	"net/http"
	"testing"
)

// The tokenless class is anchored on a SUFFIX, and this is what proves it.
//
// isIngestPath selects the requests the gateway lets through with no JWT, because
// a reporting SDK holds a DSN key and no session. Everything that decides who may
// enter that class lives in one predicate: POST, under an ingest root, ending in
// the wire's own {envelope,store}. Drop any one of those and a READ walks in
// unauthenticated — and the whole suite stayed green while exactly that was true,
// which is why this file exists.
//
// The reads below are the error plane's own: issues, discover, projects, logs,
// traces, stats. They sit UNDER an ingest root, so a prefix check alone admits
// them. They must never be in this class; they carry a session and are gated.
func TestIngestClassIsAnchoredOnTheWireSuffix(t *testing.T) {
	admitted := []string{
		"/v1/event/019f5339/envelope/",
		"/v1/event/019f5339/envelope",
		"/v1/event/019f5339/store/",
		"/v1/event/019f5339/store",
		// A stock SDK appends its own /api/<project>/envelope/ to the DSN path.
		"/v1/o11y/api/019f5339/envelope/",
		"/v1/o11y/api/019f5339/store/",
	}
	for _, p := range admitted {
		if !isIngestPath(http.MethodPost, p) {
			t.Errorf("POST %s is the DSN wire and must enter the tokenless class", p)
		}
	}

	refused := []string{
		// Reads under an ingest root — a prefix-only check would admit every one.
		"/v1/event/issues",
		"/v1/event/019f5339/issues",
		"/v1/event/discover",
		"/v1/o11y/api/v1/health",
		"/v1/o11y/api/019f5339/issues",
		// The door's own root is the PRODUCT event stream, which authenticates.
		"/v1/event",
		"/v1/event/",
		// The face is a face. No spelling of it is ingest.
		"/v1/sentinel/issues",
		"/v1/sentinel/019f5339/envelope/",
		// Suffix present, wrong root.
		"/v1/admin/019f5339/envelope/",
	}
	for _, p := range refused {
		if isIngestPath(http.MethodPost, p) {
			t.Errorf("POST %s is NOT the DSN wire and must stay JWT-gated", p)
		}
	}

	// Ingest is POST. A read verb never enters the class, whatever it addresses.
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if isIngestPath(m, "/v1/event/019f5339/envelope/") {
			t.Errorf("%s on the wire path must stay JWT-gated; ingest is POST", m)
		}
	}
}
