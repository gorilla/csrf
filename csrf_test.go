package csrf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var testKey = []byte("keep-it-secret-keep-it-safe-----")
var testHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

// TestProtect is a high-level test to make sure the middleware returns the
// wrapped handler with a 200 OK status.
func TestProtect(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)

	r := createRequest("GET", "/", false)

	rr := httptest.NewRecorder()
	p := Protect(testKey)(s)
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
	}

	cookie := rr.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie,
		"Secure") {
		t.Fatalf("cookie does not default to Secure & HttpOnly: got %v", cookie)
	}
}

// TestCookieOptions is a test to make sure the middleware correctly sets cookie options
func TestCookieOptions(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)

	r := createRequest("GET", "/", false)

	rr := httptest.NewRecorder()
	p := Protect(testKey, CookieName("nameoverride"), Secure(false), HttpOnly(false), Path("/pathoverride"), Domain("domainoverride"), MaxAge(173))(s)
	p.ServeHTTP(rr, r)

	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
	}

	cookie := rr.Header().Get("Set-Cookie")
	if strings.Contains(cookie, "HttpOnly") {
		t.Fatalf("cookie does not respect HttpOnly option: got %v do not want HttpOnly", cookie)
	}
	if strings.Contains(cookie, "Secure") {
		t.Fatalf("cookie does not respect Secure option: got %v do not want Secure", cookie)
	}
	if !strings.Contains(cookie, "nameoverride=") {
		t.Fatalf("cookie does not respect CookieName option: got %v want %v", cookie, "nameoverride=")
	}
	if !strings.Contains(cookie, "Domain=domainoverride") {
		t.Fatalf("cookie does not respect Domain option: got %v want %v", cookie, "Domain=domainoverride")
	}
	if !strings.Contains(cookie, "Max-Age=173") {
		t.Fatalf("cookie does not respect MaxAge option: got %v want %v", cookie, "Max-Age=173")
	}
}

// Test that idempotent methods return a 200 OK status and that non-idempotent
// methods return a 403 Forbidden status when a CSRF cookie is not present.
func TestMethods(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey)(s)

	// Test idempontent ("safe") methods
	for _, method := range safeMethods {
		r := createRequest(method, "/", false)

		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, r)

		if rr.Code != http.StatusOK {
			t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
				rr.Code, http.StatusOK)
		}

		if rr.Header().Get("Set-Cookie") == "" {
			t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
		}
	}

	// Test non-idempotent methods (should return a 403 without a cookie set)
	nonIdempotent := []string{"POST", "PUT", "DELETE", "PATCH"}
	for _, method := range nonIdempotent {
		r := createRequest(method, "/", false)

		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, r)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
				rr.Code, http.StatusOK)
		}

		if rr.Header().Get("Set-Cookie") == "" {
			t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
		}
	}
}

// Tests for failure if the cookie containing the session does not exist on a
// POST request.
func TestNoCookie(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	// POST the token back in the header.
	r := createRequest("POST", "/", false)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed to reject a non-existent cookie: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// TestBadCookie tests for failure when a cookie header is modified (malformed).
func TestBadCookie(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r := createRequest("GET", "/", false)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r = createRequest("POST", "/", false)

	// Replace the cookie prefix
	badHeader := strings.Replace(cookieName+"=", rr.Header().Get("Set-Cookie"), "_badCookie", -1)
	r.Header.Set("Cookie", badHeader)
	r.Header.Set("X-CSRF-Token", token)
	r.Header.Set("Referer", "http://www.gorillatoolkit.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed to reject a bad cookie: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// Responses should set a "Vary: Cookie" header to protect client/proxy caching.
func TestVaryHeader(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey)(s)

	r := createRequest("GET", "/", true)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if rr.Header().Get("Vary") != "Cookie" {
		t.Fatalf("vary header not set: got %q want %q", rr.Header().Get("Vary"), "Cookie")
	}
}

// TestNoReferer checks that HTTPS requests with no Referer header fail.
func TestNoReferer(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey)(s)

	r := createRequest("POST", "https://golang.org/", true)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed reject an empty Referer header: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// TestBadReferer checks that HTTPS requests with a Referer that does not
// match the request URL correctly fail CSRF validation.
func TestBadReferer(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r := createRequest("GET", "/", true)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r = createRequest("POST", "/", true)
	setCookie(rr, r)
	r.Header.Set("X-CSRF-Token", token)

	// Set a non-matching Referer header.
	r.Header.Set("Referer", "http://golang.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed reject a non-matching Referer header: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// TestTrustedReferer checks that HTTPS requests with a Referer that does not
// match the request URL correctly but is a trusted origin pass CSRF validation.
func TestTrustedReferer(t *testing.T) {

	testTable := []struct {
		trustedOrigin []string
		shouldPass    bool
	}{
		{[]string{"golang.org"}, true},
		{[]string{"api.example.com", "golang.org"}, true},
		{[]string{"http://golang.org"}, false},
		{[]string{"https://golang.org"}, false},
		{[]string{"http://example.com"}, false},
		{[]string{"example.com"}, false},
	}

	for _, item := range testTable {
		t.Run(fmt.Sprintf("TrustedOrigin: %v", item.trustedOrigin), func(t *testing.T) {

			s := http.NewServeMux()

			p := Protect(testKey, TrustedOrigins(item.trustedOrigin))(s)

			var token string
			s.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				token = Token(r)
			}))

			// Obtain a CSRF cookie via a GET request.
			r := createRequest("GET", "/", true)

			rr := httptest.NewRecorder()
			p.ServeHTTP(rr, r)

			// POST the token back in the header.
			r = createRequest("POST", "/", true)

			setCookie(rr, r)
			r.Header.Set("X-CSRF-Token", token)

			// Set a non-matching Referer header.
			r.Header.Set("Referer", "https://golang.org/")

			rr = httptest.NewRecorder()
			p.ServeHTTP(rr, r)

			if item.shouldPass {
				if rr.Code != http.StatusOK {
					t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
						rr.Code, http.StatusOK)
				}
			} else {
				if rr.Code != http.StatusForbidden {
					t.Fatalf("middleware failed reject a non-matching Referer header: got %v want %v",
						rr.Code, http.StatusForbidden)
				}
			}
		})
	}
}

// Requests with a valid Referer should pass.
func TestWithReferer(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r := createRequest("GET", "/", true)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r = createRequest("POST", "/", true)

	setCookie(rr, r)
	r.Header.Set("X-CSRF-Token", token)
	r.Header.Set("Referer", "https://www.gorillatoolkit.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}
}

// Requests without a token should fail with ErrNoToken.
func TestNoTokenProvided(t *testing.T) {
	var finalErr error

	s := http.NewServeMux()
	p := Protect(testKey, ErrorHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		finalErr = FailureReason(r)
	})))(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))
	// Obtain a CSRF cookie via a GET request.
	r := createRequest("GET", "/", true)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r = createRequest("POST", "/", true)

	setCookie(rr, r)
	// By accident we use the wrong header name for the token...
	r.Header.Set("X-CSRF-nekot", token)
	r.Header.Set("Referer", "https://www.gorillatoolkit.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if finalErr != nil && finalErr != ErrNoToken {
		t.Fatalf("middleware failed to return correct error: got '%v' want '%v'", finalErr, ErrNoToken)
	}
}

func setCookie(rr *httptest.ResponseRecorder, r *http.Request) {
	r.Header.Set("Cookie", rr.Header().Get("Set-Cookie"))
}

func TestProtectScenarios(t *testing.T) {
	tests := []struct {
		name                 string
		safeMethod           bool
		originUntrusted      bool
		originHTTP           bool
		originTrusted        bool
		secureRequest        bool
		refererTrusted       bool
		refererUntrusted     bool
		refererHTTPDowngrade bool
		refererRelative      bool
		tokenValid           bool
		tokenInvalid         bool
		want                 bool
	}{
		{
			name:       "safe method pass",
			safeMethod: true,
			want:       true,
		},
		{
			name:       "cleartext POST with trusted origin & valid token pass",
			originHTTP: true,
			tokenValid: true,
			want:       true,
		},
		{
			name:            "cleartext POST with untrusted origin reject",
			originUntrusted: true,
			tokenValid:      true,
		},
		{
			name:       "cleartext POST with HTTP origin & invalid token reject",
			originHTTP: true,
		},
		{
			name:       "cleartext POST without origin with valid token pass",
			tokenValid: true,
			want:       true,
		},
		{
			name: "cleartext POST without origin with invalid token reject",
		},
		{
			name:          "TLS POST with HTTP origin & no referer & valid token reject",
			tokenValid:    true,
			secureRequest: true,
			originHTTP:    true,
		},
		{
			name:          "TLS POST without origin and without referer reject",
			secureRequest: true,
			tokenValid:    true,
		},
		{
			name:             "TLS POST without origin with untrusted referer reject",
			secureRequest:    true,
			refererUntrusted: true,
			tokenValid:       true,
		},
		{
			name:           "TLS POST without origin with trusted referer & valid token pass",
			secureRequest:  true,
			refererTrusted: true,
			tokenValid:     true,
			want:           true,
		},
		{
			name:                 "TLS POST without origin from _cleartext_ same domain referer with valid token reject",
			secureRequest:        true,
			refererHTTPDowngrade: true,
			tokenValid:           true,
		},
		{
			name:            "TLS POST without origin from relative referer with valid token pass",
			secureRequest:   true,
			refererRelative: true,
			tokenValid:      true,
			want:            true,
		},
		{
			name:            "TLS POST without origin from relative referer with invalid token reject",
			secureRequest:   true,
			refererRelative: true,
			tokenInvalid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var token string
			var flag bool
			mux := http.NewServeMux()
			mux.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				token = Token(r)
			}))
			mux.Handle("/submit", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				flag = true
			}))
			p := Protect(testKey)(mux)

			// Obtain a CSRF cookie via a GET request.
			r := createRequest("GET", "/", tt.secureRequest)
			rr := httptest.NewRecorder()
			p.ServeHTTP(rr, r)

			r = createRequest("POST", "/submit", tt.secureRequest)
			if tt.safeMethod {
				r = createRequest("GET", "/submit", tt.secureRequest)
			}

			// Set the Origin header
			switch {
			case tt.originUntrusted:
				r.Header.Set("Origin", "http://www.untrusted-origin.org")
			case tt.originTrusted:
				r.Header.Set("Origin", "https://www.gorillatoolkit.org")
			case tt.originHTTP:
				r.Header.Set("Origin", "http://www.gorillatoolkit.org")
			}

			// Set the Referer header
			switch {
			case tt.refererTrusted:
				p = Protect(testKey, TrustedOrigins([]string{"external-trusted-origin.test"}))(mux)
				r.Header.Set("Referer", "https://external-trusted-origin.test/foobar")
			case tt.refererUntrusted:
				r.Header.Set("Referer", "http://www.invalid-referer.org")
			case tt.refererHTTPDowngrade:
				r.Header.Set("Referer", "http://www.gorillatoolkit.org/foobar")
			case tt.refererRelative:
				r.Header.Set("Referer", "/foobar")
			}

			// Set the CSRF token & associated cookie
			switch {
			case tt.tokenInvalid:
				setCookie(rr, r)
				r.Header.Set("X-CSRF-Token", "this-is-an-invalid-token")
			case tt.tokenValid:
				setCookie(rr, r)
				r.Header.Set("X-CSRF-Token", token)
			}

			rr = httptest.NewRecorder()
			p.ServeHTTP(rr, r)

			if tt.want && rr.Code != http.StatusOK {
				t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
					rr.Code, http.StatusOK)
			}

			if tt.want && !flag {
				t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
					flag, true)

			}
			if !tt.want && flag {
				t.Fatalf("middleware failed to reject the request: got %v want %v", flag, false)
			}
		})
	}
}

func createRequest(method, path string, useTLS bool) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "www.gorillatoolkit.org"
	if !useTLS {
		return PlaintextHTTPRequest(r)
	}
	return r
}
