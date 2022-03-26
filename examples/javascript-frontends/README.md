# JavaScript Frontends

Examples in this directory are intended to provide basic frontend JavaScript code.
These examples are compatible with the API backend examples available in the `examples/api-backends` directory.

In order to be compatible with any CSRF-protected backend, the JavaScript must:

1. Be served from a domain allowed by the backend's CORS Allowed Origins configuration.
   1. `http://localhost*` for the backend examples provided
2. Use the HTTP header expected by the backend to send and receive CSRF Tokens.
The backends configure this as the Gorilla `csrf.CookieName`,
as well as the CORS Allowed Headers and Exposed Headers.
   1. `X-CSRF-Token` for the backend examples provided
   2. Note that some JavaScript HTTP clients may automatically lowercase all received headers,
   so the values must be accessed with the key `"x-csrf-token"` in the frontend code.