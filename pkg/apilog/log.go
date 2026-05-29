package apilog

import (
	"maps"
	"net/http"

	log "github.com/sirupsen/logrus"
)

func LogEvent(r *http.Request, endpoint, operation, outcome string, extra log.Fields) {
	fields := log.Fields{
		"component": "services-api",
		"endpoint":  endpoint,
		"operation": operation,
		"source":    r.RemoteAddr,
		"outcome":   outcome,
	}
	maps.Copy(fields, extra)
	log.WithFields(fields).Info("gvproxy API request")
}
