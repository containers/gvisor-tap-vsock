package apilog

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type contextKey string

const fieldsContextKey = contextKey("apilog_fields")

// AddField adds a key-value pair to the audit log for this request.
// If the request was not wrapped by Middleware, this is a no-op.
func AddField(r *http.Request, key string, value interface{}) {
	if fields, ok := r.Context().Value(fieldsContextKey).(log.Fields); ok {
		fields[key] = value
	}
}

// SetError records an error message in the audit log for this request.
// If err is nil or the request was not wrapped by Middleware, this is a no-op.
func SetError(r *http.Request, err error) {
	if err == nil {
		return
	}
	if fields, ok := r.Context().Value(fieldsContextKey).(log.Fields); ok {
		fields["error"] = err.Error()
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	return rw.ResponseWriter.Write(b)
}

// Hijack is needed for endpoints like /tunnel and /connect.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("webserver doesn't support hijacking")
	}
	return hijacker.Hijack()
}

// Middleware is an HTTP middleware that logs API requests with any
// extra fields added by handlers via AddField or SetError.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extra := make(log.Fields)
		ctx := context.WithValue(r.Context(), fieldsContextKey, extra)
		r = r.WithContext(ctx)

		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     0,
		}

		next.ServeHTTP(rw, r)

		outcome := "success"
		if rw.statusCode >= http.StatusBadRequest {
			outcome = "error"
		}
		if _, hasErr := extra["error"]; hasErr {
			outcome = "error"
		}

		fields := log.Fields{}
		for k, v := range extra {
			fields[k] = v
		}
		fields["component"] = "services-api"
		fields["endpoint"] = r.URL.Path
		fields["method"] = r.Method
		fields["source"] = r.RemoteAddr
		fields["outcome"] = outcome

		log.WithFields(fields).Info("gvproxy API request")
	})
}
