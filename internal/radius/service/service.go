package service

import (
    "context"

    "github.com/qmish/2FA/internal/radius/protocol"
)

type ResponseCode string

const (
    AccessAccept ResponseCode = "Access-Accept"
    AccessReject ResponseCode = "Access-Reject"
)

type AccessResponse struct {
    Code    ResponseCode
    Message string
}

type FirstFactorValidator func(ctx context.Context, username, password string) bool
type SecondFactorVerifier func(ctx context.Context, username string) bool

type RadiusService struct {
    first  FirstFactorValidator
    second SecondFactorVerifier
}

func NewRadiusService(first FirstFactorValidator, second SecondFactorVerifier) *RadiusService {
    return &RadiusService{first: first, second: second}
}

func (s *RadiusService) HandleAccessRequest(ctx context.Context, req protocol.AccessRequest) AccessResponse {
    if s.first == nil || !s.first(ctx, req.Username, req.Password) {
        return AccessResponse{Code: AccessReject, Message: "first_factor_failed"}
    }
    if s.second == nil || !s.second(ctx, req.Username) {
        return AccessResponse{Code: AccessReject, Message: "second_factor_failed"}
    }
    return AccessResponse{Code: AccessAccept, Message: "ok"}
}
