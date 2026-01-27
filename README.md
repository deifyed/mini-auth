## Motivation

Most authentication libraries are either too complex for simple projects or require extensive configuration. miniauth provides cookie-based JWT authentication with sensible defaults and minimal setup.

Goals:
- Single import, minimal configuration
- Secure by default
- Transparent token refresh (no client-side logic needed)
- Pluggable datastore

## Usage

```go
func main() {
    // Initialize datastore
    db := &miniauth.Sqlite3{Path: "./auth.db"}
    if err := db.Init(); err != nil {
        panic(err)
    }
    defer db.Close()

    // Create middleware
    auth := &miniauth.Middleware{
        Datastore: db,
        Secret:    []byte("your-secret-key"),
    }

    // Setup routes
    mux := http.NewServeMux()
    mux.HandleFunc("POST /login", miniauth.Login(auth))
    mux.HandleFunc("POST /logout", miniauth.Logout(auth))
    mux.Handle("GET /protected", auth.Wrap(http.HandlerFunc(protectedHandler)))

    http.ListenAndServe(":8080", mux)
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
    user, _ := miniauth.UserFromContext(r.Context())
    fmt.Fprintf(w, "Hello, %s!", user.Username)
}
```

Login with POST request:
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}' \
  -c cookies.txt

curl http://localhost:8080/protected -b cookies.txt
```

Logout with POST request:
```bash
curl -X POST http://localhost:8080/logout \
  -c cookies.txt

curl http://localhost:8080/protected -b cookies.txt
```

## Design choices

**JWT access tokens + opaque refresh tokens**

Access tokens are short-lived JWTs (3 min default) validated statelessly. Refresh tokens are random strings stored in the database. This gives fast authentication for most requests while allowing instant revocation of refresh tokens.

**Automatic token refresh**

When an access token expires, the middleware automatically validates the refresh token and issues new tokens. Clients don't need refresh logic.

**Refresh token rotation**

Each time a refresh token is used, it's deleted and replaced with a new one. A stolen token becomes useless after one use.

**Secure cookies by default**

Cookies are set with `HttpOnly`, `Secure`, and `SameSite=Strict`. Set `Insecure: true` only for local development without HTTPS.

**Password handling**

Passwords are pre-hashed with SHA256 before bcrypt to avoid the 72-byte truncation issue. Timing attacks on username enumeration are prevented by always running bcrypt comparison.

**Hashed refresh tokens in database**

Refresh tokens are stored as SHA256 hashes. If the database is compromised, tokens cannot be used directly.

Disclaimer: Mostly made using AI
