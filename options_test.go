package csrf

import (
	"net/http"
	"reflect"
	"testing"
)

func eqslice(s1 []string, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}

	for i := range s1 {
		if s1[i] != s2[i] {
			return false
		}
	}

	return true
}

// Tests that options functions are applied to the middleware.
func TestOptions(t *testing.T) {
	var h http.Handler

	age := 86400
	domain := "gorillatoolkit.org"
	exclude := []string{"/path1", "/path2", "/path3"}
	path := "/forms/"
	header := "X-AUTH-TOKEN"
	field := "authenticity_token"
	errorHandler := unauthorizedHandler
	name := "_chimpanzee_csrf"

	testOpts := []Option{
		MaxAge(age),
		Domain(domain),
		Exclude(exclude...),
		Path(path),
		HttpOnly(false),
		Secure(false),
		RequestHeader(header),
		FieldName(field),
		ErrorHandler(http.HandlerFunc(errorHandler)),
		CookieName(name),
	}

	// Parse our test options and check that they set the related struct fields.
	cs := parseOptions(h, testOpts...)

	if cs.opts.MaxAge != age {
		t.Errorf("MaxAge not set correctly: got %v want %v", cs.opts.MaxAge, age)
	}

	if cs.opts.Domain != domain {
		t.Errorf("Domain not set correctly: got %v want %v", cs.opts.Domain, domain)
	}

	if !eqslice(cs.opts.Exclude, exclude) {
		t.Errorf("Exclude not set correctly: got %v want %v", cs.opts.Exclude, exclude)
	}

	if cs.opts.Path != path {
		t.Errorf("Path not set correctly: got %v want %v", cs.opts.Path, path)
	}

	if cs.opts.HttpOnly != false {
		t.Errorf("HttpOnly not set correctly: got %v want %v", cs.opts.HttpOnly, false)
	}

	if cs.opts.Secure != false {
		t.Errorf("Secure not set correctly: got %v want %v", cs.opts.Secure, false)
	}

	if cs.opts.RequestHeader != header {
		t.Errorf("RequestHeader not set correctly: got %v want %v", cs.opts.RequestHeader, header)
	}

	if cs.opts.FieldName != field {
		t.Errorf("FieldName not set correctly: got %v want %v", cs.opts.FieldName, field)
	}

	if !reflect.ValueOf(cs.opts.ErrorHandler).IsValid() {
		t.Errorf("ErrorHandler not set correctly: got %v want %v",
			reflect.ValueOf(cs.opts.ErrorHandler).IsValid(), reflect.ValueOf(errorHandler).IsValid())
	}

	if cs.opts.CookieName != name {
		t.Errorf("CookieName not set correctly: got %v want %v",
			cs.opts.CookieName, name)
	}
}
