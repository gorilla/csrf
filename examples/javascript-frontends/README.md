# JavaScript Frontends

Examples in this directory are intended to provide basic working frontend JavaScript, compatible
with the API backend examples available in the [`examples/api-backends`](../api-backends).

## CSRF and CORS compatibility

In order to be compatible with a CSRF-protected backend, frontend clients must:

1. Be served from a domain allowed by the backend's CORS Allowed Origins configuration.
    1. `http://localhost*` for the backend examples provided
    2. An example server to serve the HTML and JavaScript for the frontend examples from localhost is included in
       [`examples/javascript-frontends/example-frontend-server`](../javascript-frontends/example-frontend-server)
3. Use the HTTP headers expected by the backend to send and receive CSRF Tokens.
   The backends configure this as the Gorilla `csrf.RequestHeader`,
   as well as the CORS Allowed Headers and Exposed Headers.
    1. `X-CSRF-Token` for the backend examples provided
    2. Note that some JavaScript HTTP clients automatically lowercase all received headers,
       so the values must be accessed with the key `"x-csrf-token"` in the frontend code.
