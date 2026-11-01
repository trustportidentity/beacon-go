package beaconfiber

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/trustportidentity/beacon-go/defender"
)

// DefenderMiddleware inspects incoming Fiber requests and blocks banned IPs or attack heuristics.
func DefenderMiddleware(def *defender.Defender) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if def != nil {
			clientIP := c.IP()
			if blocked, reason := def.CheckIP(clientIP); blocked {
				incidentID := "inc-" + uuid.New().String()[:8]
				c.Set("X-Beacon-Defender", "blocked")
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":       "forbidden",
					"code":        "BEACON_DEFENDER_BLOCKED",
					"message":     "Access restricted by TrustPort Beacon AI Defender firewall.",
					"reason":      reason,
					"incident_id": incidentID,
				})
			}

			// Heuristic checks on path and query
			path := strings.ToLower(c.Path())
			origURL := strings.ToLower(c.OriginalURL())
			if strings.Contains(origURL, "../") || strings.Contains(path, "/etc/passwd") ||
				strings.Contains(origURL, "union select") || strings.Contains(origURL, "or 1=1") {
				incidentID := "inc-" + uuid.New().String()[:8]
				c.Set("X-Beacon-Defender", "blocked")
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":       "forbidden",
					"code":        "BEACON_DEFENDER_BLOCKED",
					"message":     "Access restricted by TrustPort Beacon AI Defender firewall.",
					"reason":      "Malicious request pattern detected",
					"incident_id": incidentID,
				})
			}
		}
		return c.Next()
	}
}

