package server

import (
	// "regexp"
	// "strings"

	"fmt"
	"regexp"
	"strings"
	"swagger/apiserver/components/database"
	"swagger/apiserver/restapi/operations/user"
	v1 "swagger/apiserver/v1"
	"swagger/pkg/config"
	"swagger/pkg/helper"
	"time"

	"github.com/dgrijalva/jwt-go"
	middleware "github.com/go-openapi/runtime/middleware"
	"github.com/rs/xid"
	"github.com/sirupsen/logrus"
)

// ChangeCurrentUserPassword 修改当前用户密码
func ChangeCurrentUserPassword(params user.ChangeCurrentUserPasswordParams, principal *v1.Principal) middleware.Responder {
	// ctx := params.HTTPRequest.Context()
	// c, err := monitor.NewGRPCClient()
	// if err != nil {
	// 	return Error(err)
	// }
	// defer c.Close()
	// if strings.Trim(params.NewPassword, " ") == "" || strings.Trim(params.OldPassword, " ") == "" {
	// 	return BadRequestError("用户密码为空请重新输入")
	// }
	// regx, err := regexp.Compile(`^[a-zA-Z0-9_\-]{5,16}$`)
	// if err != nil {
	// 	return Error(err)
	// }
	// res := regx.MatchString(params.NewPassword)
	// if res == false {
	// 	return BadRequestError("用户密码格式错误，请重新输入")
	// }
	// headerContent := params.HTTPRequest.Header.Get("authorization")
	// // 请求头返回的内容是xxx token的内容 这种格式构成的，因此使用字符串处理，将请求头截分为两部分，第二部分，也就是索引为1的部分是token
	// token := strings.Split(headerContent, " ")[1]
	// authenticate, err := c.User().Authenticate(ctx, &pb.AuthenticateRequest{
	// 	Token: token,
	// })
	// if err != nil {
	// 	return Error(err)
	// }
	// result, _ := c.User().VerifyPassword(ctx, &pb.VerifyPasswordRequest{
	// 	Username: authenticate.Name,
	// 	Password: params.OldPassword,
	// })
	// if result.Result == false {
	// 	return BadRequestError("用户旧密码错误,请重新输入")
	// }
	// _, err = c.User().ChangeUserPassword(ctx, &pb.ChangeUserPasswordRequest{
	// 	User: &pb.User{
	// 		Id:   authenticate.Id,
	// 		Name: authenticate.Name,
	// 	},
	// 	Password: params.NewPassword,
	// })
	// if err != nil {
	// 	return Error(err)
	// }
	return user.NewChangeCurrentUserPasswordOK()
}

// ChangeUserPassword 修改用用户密码
func ChangeUserPassword(params user.ChangeUserPasswordParams, principal *v1.Principal) middleware.Responder {
	// if strings.Trim(params.ID, " ") == "" {
	// 	return BadRequestError("用户ID不能为空")
	// }
	// if strings.Trim(params.Username, " ") == "" {
	// 	return BadRequestError("用户名不能为空")
	// }
	// if strings.Trim(params.Password, " ") == "" {
	// 	return BadRequestError("用户密码不能为空")
	// }
	// regx, err := regexp.Compile(`^[a-zA-Z0-9_\-]{5,16}$`)
	// if err != nil {
	// 	Error(err)
	// }
	// res := regx.MatchString(params.Password)
	// if res == false {
	// 	return BadRequestError("用户密码格式错误,请重新输入")
	// }
	// ctx := params.HTTPRequest.Context()
	// c, err := monitor.NewGRPCClient()
	// if err != nil {
	// 	return Error(err)
	// }
	// defer c.Close()
	// if params.ID == "" || params.Username == "" || params.Password == "" {
	// 	return Error(err)
	// }
	// _, err = c.User().ChangeUserPassword(ctx, &pb.ChangeUserPasswordRequest{
	// 	User: &pb.User{
	// 		Id:   params.ID,
	// 		Name: params.Username,
	// 	},
	// 	Password: params.Password,
	// })
	// if err != nil {
	// 	return Error(err)
	// }
	return user.NewChangeUserPasswordOK()
}

// CreateUser 创建用户
func CreateUser(params user.CreateUserParams, principal *v1.Principal) middleware.Responder {
	logrus.Infoln("CreateUser", params.Body)
	if strings.Trim(*params.Body.Name, " ") == "" {
		return BadRequestError("用户名不能为空")
	}
	if strings.Trim(params.Body.Password, " ") == "" {
		return BadRequestError("用户密码不能为空")
	}
	if strings.Trim(*params.Body.Role, " ") == "" {
		return BadRequestError("用户角色不能为空")
	}
	regxName, err := regexp.Compile(`^[a-zA-Z0-9_]{5,16}$`)
	regxPassword, err := regexp.Compile(`^[a-zA-Z0-9_\-]{5,16}$`)
	if err != nil {
		Error(err)
	}
	resName := regxName.MatchString(*params.Body.Name)
	resPassword := regxPassword.MatchString(params.Body.Password)
	if !resName {
		return BadRequestError("用户名格式错误,请重新输入")
	}
	if !resPassword {
		return BadRequestError("用户密码格式错误,请重新输入")
	}
	if strings.Trim(*params.Body.Telephone, " ") != "" {
		regxPhone, err := regexp.Compile(`^1([38][0-9]|14[579]|5[^4]|16[6]|7[1-35-8]|9[189])\d{8}$`)
		if err != nil {
			Error(err)
		}
		resPhone := regxPhone.MatchString(*params.Body.Telephone)
		if resPhone == false {
			return BadRequestError("电话号码格式错误,请重新输入")
		}
	}
	ctx := params.HTTPRequest.Context()
	var dbType = config.GetString(config.DBType)
	client, err := database.New(database.Type(dbType))
	userCount, err := client.FindUserCount(ctx, *params.Body.Name)
	if userCount > 0 {
		return BadRequestError("用户名已被注册,请重新输入")
	}
	Id := xid.New().String()
	Created := time.Now().UnixNano() / 1e6
	Modified := time.Now().UnixNano() / 1e6
	reguser := &v1.User{
		ID:        &Id,
		Name:      params.Body.Name,
		Email:     params.Body.Email,
		Created:   &Created,
		Modified:  &Modified,
		Role:      params.Body.Role,
		Telephone: params.Body.Telephone,
	}
	resuser, err := client.RegisterUser(ctx, reguser, params.Body.Password)
	if err != nil {
		return BadRequestError("用户名已被注册,请重新输入")
	}
	return user.NewCreateUserOK().WithPayload(resuser)
}

// DeleteUser 删除用户
func DeleteUser(params user.DeleteUserParams, principal *v1.Principal) middleware.Responder {
	// ctx := params.HTTPRequest.Context()
	// c, err := monitor.NewGRPCClient()
	// if err != nil {
	// 	return Error(err)
	// }
	// defer c.Close()
	// reply, err := c.User().DeleteUserById(ctx, &pb.DeleteUserByIdRequest{
	// 	Id: params.ID,
	// })
	// if err != nil {
	// 	return Error(err)
	// }
	payload := pbUserToV1User()
	return user.NewDeleteUserOK().WithPayload(payload)
}

// GetUser 通过id获取用户信息
func GetUser(params user.GetUserParams, principal *v1.Principal) middleware.Responder {
	// ctx := params.HTTPRequest.Context()
	// c, err := monitor.NewGRPCClient()
	// if err != nil {
	// 	return Error(err)
	// }
	// defer c.Close()
	// if params.ID == "" {
	// 	return Error(err)
	// }
	// id := params.ID
	// reply, err := c.User().GetUser(ctx, &pb.GetUserRequest{Id: id})
	// if err != nil {
	// 	return Error(err)
	// }
	payload := pbUserToV1User()
	return user.NewGetUserOK().WithPayload(payload)
}

// GetUserInfo 获取当前用户信息
func GetUserInfo(params user.GetUserInfoParams, principal *v1.Principal) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	var dbType = config.GetString(config.DBType)
	client, err := database.New(database.Type(dbType))
	if err != nil {
		return Error(err)
	}
	ids := []string{"ss", "ss"}
	client.GetUsersByIDs(ctx, ids)
	return user.NewGetUserOK().WithPayload(pbUserToV1User())
}

// GetUsers 获取用户列表
func GetUsers(params user.GetUsersParams, principal *v1.Principal) middleware.Responder {
	// ctx := params.HTTPRequest.Context()
	// c, err := monitor.NewGRPCClient()
	// if err != nil {
	// 	return Error(err)
	// }
	// defer c.Close()
	// limit := int64(0)
	// if params.Limit != nil {
	// 	limit = *params.Limit
	// }
	// skip := int64(0)
	// if params.Skip != nil {
	// 	skip = *params.Skip
	// }
	// sort := `{"created": -1}`
	// if params.Sort != nil {
	// 	sort = *params.Sort
	// }
	// query := `{}`
	// if params.Q != nil {
	// 	query = *params.Q
	// }
	// reply, err := c.User().GetUsers(ctx, &pb.GetUsersRequest{
	// 	Limit: limit,
	// 	Skip:  skip,
	// 	Sort:  sort,
	// 	Query: query,
	// })
	// if err != nil {
	// 	return Error(err)
	// }
	// items := []*v1.User{}
	// for _, v := range reply.Items {
	// 	items = append(items, pbUserToV1User(v))
	// }
	payload := &v1.Users{}
	return user.NewGetUsersOK().WithPayload(payload)
}

// Login 登录
func Login(params user.LoginParams) middleware.Responder {
	fmt.Println("Login", params)
	ctx := params.HTTPRequest.Context()
	var dbType = config.GetString(config.DBType)
	client, _ := database.New(database.Type(dbType))
	verifyPass := client.Authenticate(ctx, params.Username, params.Password)
	if !verifyPass {
		return BadRequestError("用户名或密码错误")
	}
	now := time.Now()
	expiresAt := now.Add(helper.AccessExpiresIn)
	jwtClaims := helper.JwtClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "test.com",
			NotBefore: now.Unix(),
			ExpiresAt: expiresAt.Unix(),
		},
		UserClaims: helper.UserClaims{
			ID:   params.Username,
			Name: params.Password,
		},
	}
	token, _ := helper.CreateToken(jwtClaims)

	accessToken := token["access_token"]
	tokenType := token["token_type"]
	expiresIn := token["expires_in"]
	expires := token["expires_at"]

	payload := &v1.Token{
		AccessToken: accessToken,
		TokenType:   &tokenType,
		ExpiresIn:   expiresIn,
		ExpiresAt:   expires,
	}
	return user.NewLoginOK().WithPayload(payload)
}

// Logout 登出
func Logout(params user.LogoutParams, principal *v1.Principal) middleware.Responder {
	return user.NewLogoutOK()
}

// UpdateUser 编辑用户信息
func UpdateUser(params user.UpdateUserParams, principal *v1.Principal) middleware.Responder {
	// if params.ID == "" {
	// 	return BadRequestError("用户ID不能为空")
	// }
	// if *params.Body.Name == "" {
	// 	return BadRequestError("用户名不能为空")
	// }
	// if *params.Body.Role == "" {
	// 	return BadRequestError("用户角色不能为空")
	// }
	// if strings.Trim(*params.Body.Telephone, " ") != "" {
	// 	regxPhone, err := regexp.Compile(`^1([38][0-9]|14[579]|5[^4]|16[6]|7[1-35-8]|9[189])\d{8}$`)
	// 	if err != nil {
	// 		Error(err)
	// 	}
	// 	resPhone := regxPhone.MatchString(*params.Body.Telephone)
	// 	if resPhone == false {
	// 		return BadRequestError("电话号码的格式错误,请重新输入")
	// 	}
	// }
	// ctx := params.HTTPRequest.Context()
	// c, err := monitor.NewGRPCClient()
	// if err != nil {
	// 	return Error(err)
	// }
	// defer c.Close()
	// if params.ID == "" || *params.Body.Name == "" || *params.Body.Role == "" {
	// 	return Error(err)
	// }
	// reply, err := c.User().UpdateUser(ctx, &pb.UpdateUserRequest{
	// 	User: &pb.User{
	// 		Id:        params.ID,
	// 		Name:      *params.Body.Name,
	// 		Email:     *params.Body.Email,
	// 		Telephone: *params.Body.Telephone,
	// 		Role:      *params.Body.Role,
	// 	},
	// })
	// if err != nil {
	// 	return Error(err)
	// }
	payload := pbUserToV1User()
	return user.NewUpdateUserOK().WithPayload(payload)
}

/******************************************************结构体转换******************************************************/

// pbUserToV1User 结构体转换(User)
func pbUserToV1User() *v1.User {
	s := "s"
	var i int64
	return &v1.User{
		ID:        &s,
		Name:      &s,
		Email:     &s,
		Telephone: &s,
		Role:      &s,
		Created:   &i,
		Modified:  &i,
	}
}
