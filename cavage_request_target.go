package sigre

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// cavageRequestTargetFromURL returns the :path-equivalent value of a hierarchical
// URL without reparsing or re-encoding its query.
func cavageRequestTargetFromURL(u *url.URL) (string, error) {
	if u == nil {
		return "", fmt.Errorf("%w: %s is included, but request-target is missing because the request URL is nil", ErrInvalidHTTPMessage, CavageRequestTarget)
	}
	if u.Opaque != "" {
		return "", fmt.Errorf("%w: %s is included, but request-target is missing because an opaque URL does not define :path", ErrInvalidHTTPMessage, CavageRequestTarget)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.ForceQuery || u.RawQuery != "" {
		return path + "?" + u.RawQuery, nil
	}
	return path, nil
}

func invalidCavageCONNECTRequestTarget() error {
	return fmt.Errorf("%w: CONNECT request-target does not define the :path required by %s", ErrInvalidHTTPMessage, CavageRequestTarget)
}

// outgoingCavageRequestTarget resolves the :path-equivalent value that is signed
// for a request sent from its URL.
func outgoingCavageRequestTarget(req *http.Request) (string, error) {
	if req == nil {
		return "", fmt.Errorf("%w: %s is included, but request-target is missing", ErrInvalidHTTPMessage, CavageRequestTarget)
	}
	if req.Method == http.MethodConnect {
		return "", invalidCavageCONNECTRequestTarget()
	}
	return cavageRequestTargetFromURL(req.URL)
}

// receivedCavageRequestTarget resolves the :path-equivalent value from the raw
// request-target and parsed URL retained by net/http.
func receivedCavageRequestTarget(req *http.Request) (string, error) {
	if req == nil {
		return "", fmt.Errorf("%w: request-target is required by %s", ErrInvalidHTTPMessage, CavageRequestTarget)
	}
	if req.Method == http.MethodConnect {
		return "", invalidCavageCONNECTRequestTarget()
	}
	if req.RequestURI == "" {
		return "", fmt.Errorf("%w: request-target is required by %s", ErrInvalidHTTPMessage, CavageRequestTarget)
	}
	if req.RequestURI == "*" {
		return "*", nil
	}
	if strings.HasPrefix(req.RequestURI, "/") {
		return req.RequestURI, nil
	}
	if req.URL != nil && req.URL.IsAbs() {
		if req.Method == http.MethodOptions &&
			(req.URL.Scheme == "http" || req.URL.Scheme == "https") &&
			req.URL.Path == "" && req.URL.RawQuery == "" && !req.URL.ForceQuery {
			return "*", nil
		}
		return cavageRequestTargetFromURL(req.URL)
	}
	return "", fmt.Errorf("%w: authority-form request-target does not define the :path required by %s", ErrInvalidHTTPMessage, CavageRequestTarget)
}

// associatedRequestMethod uses the same client-side branch as associatedCavageRequestTarget:
// requests with an empty RequestURI are treated as client requests, for which
// net/http defines an empty method as GET.
func associatedRequestMethod(req *http.Request) string {
	if req.RequestURI == "" && req.Method == "" {
		return http.MethodGet
	}
	return req.Method
}

// associatedCavageRequestTarget distinguishes a received server-side request from
// a client-side request associated with a response.
func associatedCavageRequestTarget(req *http.Request) (string, error) {
	if req == nil {
		return "", fmt.Errorf("%w: associated request is required by %s", ErrInvalidHTTPMessage, CavageRequestTarget)
	}
	if req.RequestURI != "" {
		return receivedCavageRequestTarget(req)
	}
	return outgoingCavageRequestTarget(req)
}
