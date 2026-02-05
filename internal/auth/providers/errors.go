package providers

import "errors"

var ErrProviderNotFound = errors.New("provider not found")
var ErrProviderRequest = errors.New("provider request failed")
