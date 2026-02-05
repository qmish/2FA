package handlers

import "net/http"

func Metrics(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("# metrics placeholder\n"))
}
