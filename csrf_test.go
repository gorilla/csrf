package csrf

import (
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

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

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

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

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
		r, err := http.NewRequest(method, "/", nil)
		if err != nil {
			t.Fatal(err)
		}

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
		r, err := http.NewRequest(method, "/", nil)
		if err != nil {
			t.Fatal(err)
		}

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

	var token string
	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// POST the token back in the header.
	r, err := http.NewRequest("POST", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

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
	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

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

	r, err := http.NewRequest("HEAD", "https://www.golang.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

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

// Requests with no Referer header should fail.
func TestNoReferer(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey)(s)

	r, err := http.NewRequest("POST", "https://golang.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

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
	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "https://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "https://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

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

// Requests with a valid Referer should pass.
func TestWithReferer(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	setCookie(rr, r)
	r.Header.Set("X-CSRF-Token", token)
	r.Header.Set("Referer", "http://www.gorillatoolkit.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}
}

func setCookie(rr *httptest.ResponseRecorder, r *http.Request) {
	r.Header.Set("Cookie", rr.Header().Get("Set-Cookie"))
}
