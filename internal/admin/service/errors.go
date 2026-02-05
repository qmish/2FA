package service

import "errors"

var (
    ErrConflict = errors.New("conflict")
    ErrNotFound = errors.New("not found")
)
