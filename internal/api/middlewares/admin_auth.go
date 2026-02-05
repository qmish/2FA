package middlewares

import (
    "net/http"
    "strings"
)

type AdminTokenValidator interface {
    Validate(token string) error
}

func AdminAuth(validator AdminTokenValidator) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            header := r.Header.Get("Authorization")
            if !strings.HasPrefix(header, "Bearer ") {
                w.WriteHeader(http.StatusUnauthorized)
                return
            }
            token := strings.TrimPrefix(header, "Bearer ")
            if err := validator.Validate(token); err != nil {
                w.WriteHeader(http.StatusUnauthorized)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}
