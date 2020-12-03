package server

import (
	// "regexp"
	// "strings"

	"fmt"
	"swagger/apiserver/restapi/operations/oauth"
	v1 "swagger/apiserver/v1"
	"swagger/pkg/helper"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/runtime/middleware"
)

// Token POST /v1/oauth/token
func Token(params oauth.TokenParams) middleware.Responder {

	fmt.Println("server Token")
	// ctx := params.HTTPRequest.Context()
	// user, err := s.db.GetUserByName(ctx, req.Username)
	// if err != nil {
	// 	return &pb.LoginReply{}, status.Errorf(codes.FailedPrecondition, req.Username+" login failed")
	// }
	// ret := s.db.Authenticate(ctx, req.Username, req.Passowrd)
	// if !ret {
	// 	return &pb.LoginReply{}, status.Errorf(codes.Unauthenticated, req.Username+" login failed")
	// }
	now := time.Now()
	expiresAt := now.Add(helper.AccessExpiresIn)
	jwtClaims := helper.JwtClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "cloudstone.com",
			NotBefore: now.Unix(),
			ExpiresAt: expiresAt.Unix(),
		},
		UserClaims: helper.UserClaims{
			ID:   "001",
			Name: "yushk",
		},
	}
	token, _ := helper.CreateToken(jwtClaims)

	accessToken := token["access_token"]
	tokenType := token["token_type"]
	payload := &v1.Token{
		AccessToken: accessToken,
		TokenType:   &tokenType,
		ExpiresIn:   token["expires_in"],
		ExpiresAt:   token["expires_at"],
	}
	fmt.Println("token", token)
	return oauth.NewTokenOK().WithPayload(payload)
}
