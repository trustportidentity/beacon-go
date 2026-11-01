package beacongin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trustportidentity/beacon-go/defender"
)

// DefenderMiddleware inspects incoming Gin requests and aborts with HTTP 403 Forbidden
// if the client IP is banned or an attack heuristic is detected.
func DefenderMiddleware(def *defender.Defender) gin.HandlerFunc {
	return func(c *gin.Context) {
		if def != nil {
			if blocked, reason := def.CheckRequest(c.Request); blocked {
				incidentID := "inc-" + uuid.New().String()[:8]
				c.Header("X-Beacon-Defender", "blocked")
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":       "forbidden",
					"code":        "BEACON_DEFENDER_BLOCKED",
					"message":     "Access restricted by TrustPort Beacon AI Defender firewall.",
					"reason":      reason,
					"incident_id": incidentID,
				})
				return
			}
		}
		c.Next()
	}
}

