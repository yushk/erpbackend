package helper

import (
	"io/ioutil"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
)

var (
	// AccessExpiresIn token access expires in duration
	AccessExpiresIn = 12 * time.Hour
	verifyKeyBuf    []byte // *rsa.PublicKey
	signKeyBuf      []byte // *rsa.PrivateKey
)

// UserClaims 用户信息
type UserClaims struct {
	ClientID string // 客户端ID
	ID       string // 用户ID
	Name     string // 用户名
	// Roles    []string // 所有角色
	// Role     string   // 当前角色
}

// JwtClaims ...
type JwtClaims struct {
	jwt.StandardClaims
	UserClaims
}

// InitCerts 初期化token认证证书
func InitCerts(key, pem string) error {
	var err error
	signKeyBuf, err = ioutil.ReadFile(key)
	if err != nil {
		logrus.WithError(err).Errorln("read private key error")
		return err
	}
	verifyKeyBuf, err = ioutil.ReadFile(pem)
	if err != nil {
		logrus.WithError(err).Errorln("Read public key error")
		return err
	}
	return nil
}

// CreateToken ...
func CreateToken(claims JwtClaims) (token map[string]string, err error) {
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signKeyBuf)
	if err != nil {
		logrus.WithError(err).Errorln("Token ParseRSAPrivateKeyFromPEM Error")
		return
	}
	accessToken, err := jwtToken.SignedString(signKey)
	if err != nil {
		logrus.WithError(err).Errorln("Token SignedString Error")
		return
	}

	expiresAt := strconv.FormatInt(claims.ExpiresAt, 10)
	expiresIn := strconv.FormatInt(int64(AccessExpiresIn/time.Second), 10)
	token = map[string]string{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
		"expires_at":   expiresAt,
	}
	return
}

// ParseToken ...
func ParseToken(token string) (*JwtClaims, error) {
	parsedToken, err := jwt.ParseWithClaims(token, &JwtClaims{}, func(parsedToken *jwt.Token) (interface{}, error) {
		// the key used to validate tokens
		return jwt.ParseRSAPublicKeyFromPEM(verifyKeyBuf)
	})
	if err != nil {
		logrus.WithError(err).Errorln("parseToken ParseWithClaims Error")
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, err
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				// Token is expired
				claims := parsedToken.Claims.(*JwtClaims)
				return claims, err
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, err
			} else {
				return nil, err
			}
		}
	}
	claims, ok := parsedToken.Claims.(*JwtClaims)
	if ok && parsedToken.Valid {
		return claims, nil
	}
	return &JwtClaims{}, err
}
