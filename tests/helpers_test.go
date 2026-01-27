package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deifyed/mini-auth/miniauth"
)

const (
	testUsername = "testuser"
	testPassword = "testpassword123"
	testSecret   = "test-secret-key-for-testing-only"
)

// testSetup contains the test server and middleware for testing.
type testSetup struct {
	Server     *httptest.Server
	Middleware *miniauth.Middleware
	DB         *miniauth.Sqlite3
	dbPath     string
}

// Close cleans up test resources.
func (ts *testSetup) Close() {
	ts.Server.Close()
	ts.DB.Close()
	os.Remove(ts.dbPath)
}

// newTestSetup creates a new test server with all routes configured.
func newTestSetup(t *testing.T) *testSetup {
	t.Helper()

	// Create temp DB
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db := &miniauth.Sqlite3{Path: dbPath}
	if err := db.Init(); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	// Create test user
	_, err := db.CreateUser(testUsername, testPassword)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Create middleware
	middleware := &miniauth.Middleware{
		Datastore: db,
		Secret:    []byte(testSecret),
		Insecure:  true, // Allow non-HTTPS for testing
	}

	// Create mux with routes
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", miniauth.Login(middleware))
	mux.HandleFunc("POST /logout", miniauth.Logout(middleware))
	mux.Handle("GET /protected", middleware.Wrap(http.HandlerFunc(protectedHandler)))

	server := httptest.NewServer(mux)

	return &testSetup{
		Server:     server,
		Middleware: middleware,
		DB:         db,
		dbPath:     dbPath,
	}
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := miniauth.UserFromContext(r.Context())
	if !ok {
		http.Error(w, "no user in context", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Hello, %s!", user.Username)
}

// loginRequest creates a login request body.
func loginRequest(username, password string) string {
	return fmt.Sprintf(`{"username":"%s","password":"%s"}`, username, password)
}

// doLogin performs a login and returns the response.
func doLogin(t *testing.T, serverURL, username, password string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, serverURL+"/login", strings.NewReader(loginRequest(username, password)))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to do request: %v", err)
	}

	return resp
}

// getCookies extracts cookies from a response.
func getCookies(resp *http.Response) []*http.Cookie {
	return resp.Cookies()
}

// findCookie finds a cookie by name.
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
