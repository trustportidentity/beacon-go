package beaconhttp

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/trustportidentity/beacon-go/defender"
)

// DefenderMiddleware inspects incoming requests and blocks banned IPs, subnets, or attack heuristics.
func DefenderMiddleware(def *defender.Defender) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if def != nil {
				if blocked, reason := def.CheckRequest(r); blocked {
					incidentID := "inc-" + uuid.New().String()[:8]
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-Beacon-Defender", "blocked")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"error":       "forbidden",
						"code":        "BEACON_DEFENDER_BLOCKED",
						"message":     "Access restricted by TrustPort Beacon AI Defender firewall.",
						"reason":      reason,
						"incident_id": incidentID,
					})
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
