package simpleauth

import "context"

type contextKey string

const userContextKey contextKey = "simpleauth_user"

// UserFromContext retrieves the authenticated user from the request context.
// Returns the user and true if authenticated, zero value and false otherwise.
func UserFromContext(ctx context.Context) (User, bool) {
	user, ok := ctx.Value(userContextKey).(User)
	return user, ok
}

func setUserInContext(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}
