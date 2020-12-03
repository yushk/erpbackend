package database

import (
	"context"
	"time"

	"swagger/apiserver/components/database/mongo"
	v1 "swagger/apiserver/v1"
)

// Type 数据库类型
type Type string

// 数据库类型枚举
const (
	MongoDB Type = "mongodb"
)

// 数据库连接默认的超时时间
const (
	DefaultTimeout = 10 * time.Second
)

// Database 数据库接口
type Database interface {
	/**********用户管理接口**********/
	// 创建用户
	RegisterUser(ctx context.Context, user *v1.User, password string) (*v1.User, error)
	// 查询所有用户
	FindUserCount(ctx context.Context, username string) (int64, error)
	// 编辑用户信息
	UpdateUsers(ctx context.Context, id string, user *v1.User) (*v1.User, error)
	// 删除用户
	DeleteUser(ctx context.Context, id string) (*v1.User, error)
	// 通过id获取用户信息
	GetUser(ctx context.Context, id string) (*v1.User, error)
	// 通过name获取用户信息
	GetUserByName(ctx context.Context, name string) (*v1.User, error)
	// 获取全部用户信息列表
	GetUsers(ctx context.Context, limit, skip int64, sort string, query string) (int64, []*v1.User, error)
	// 通过id列表获取用户信息列表
	GetUsersByIDs(ctx context.Context, ids []string) (int64, []*v1.User, error)
	// 通过id,name修改用户密码
	ChangeUserPassword(ctx context.Context, user *v1.User, password string) (*v1.User, error)
	// 通过username,password身份验证
	Authenticate(ctx context.Context, username, password string) bool
	Close() error
}

// New 创建数据库句柄
func New(name Type) (Database, error) {
	switch name {
	case MongoDB:
		return mongo.NewDB()
	default:
		return mongo.NewDB()
	}
}
