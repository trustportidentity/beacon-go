# trustportidentity/beacon-go

Official TrustPort Beacon APM SDK for Go.

## Install

```bash
go get github.com/trustportidentity/beacon-go@latest
```

## Gin

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/trustportidentity/beacon-go"
    "github.com/trustportidentity/beacon-go/adapter/beacongin"
)

beacon.Init(beacon.Config{
    IngestURL:   "https://beacon-api.trustportidentity.com",
    APIKey:      "tb_live_...",
    ServiceName: "payment-gateway",
    Environment: "production",
})
defer beacon.Close()

r := gin.Default()
r.Use(beacongin.Middleware("payment-gateway"))

r.POST("/api/v1/charge", func(c *gin.Context) {
    ctx := c.Request.Context()
    span := beacon.StartSpan(ctx, "db.postgresql.charge_account")
    span.SetTag("currency", "USD")
    span.End()
    c.JSON(200, gin.H{"trace_id": beacon.TraceID(ctx)})
})
```

Fiber and standard `net/http` adapters live at `adapter/beaconfiber` and `adapter/beaconhttp`.

See the full guide at [beacon.trustportidentity.com/help/go](https://beacon.trustportidentity.com/help/go).
