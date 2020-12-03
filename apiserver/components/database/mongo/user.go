package mongo

import (
	"context"
	"encoding/json"
	"time"

	v1 "swagger/apiserver/v1"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type authorization struct {
	Username   string
	Crenditial string
}

// DeleteUser 删除用户信息
func (m *DB) DeleteUser(ctx context.Context, id string) (*v1.User, error) {
	user := &v1.User{}
	filter := bson.M{"id": id}
	err := m.CUser().FindOneAndDelete(ctx, filter).Decode(user)
	if err != nil {
		return user, err
	}
	// 删除鉴权信息
	err = m.RemoveAuthorization(ctx, *user.Name)
	return user, err
}

// GetUser 通过id获取用户信息
func (m *DB) GetUser(ctx context.Context, id string) (*v1.User, error) {
	user := &v1.User{}
	filter := bson.M{"id": id}
	err := m.CUser().FindOne(ctx, filter).Decode(user)
	return user, err
}

// GetUserByName 根据name获取用户信息
func (m *DB) GetUserByName(ctx context.Context, name string) (*v1.User, error) {
	user := &v1.User{}
	filter := bson.M{"name": name}
	err := m.CUser().FindOne(ctx, filter).Decode(user)
	return user, err
}

// GetUsers 获取用户信息列表
func (m *DB) GetUsers(ctx context.Context, limit, skip int64, sort string, query string) (int64, []*v1.User, error) {
	users := []*v1.User{}
	sortFilter := bson.M{}
	if sort != "" {
		err := json.Unmarshal([]byte(sort), &sortFilter)
		if err != nil {
			return 0, users, err
		}
	}
	findOption := &options.FindOptions{
		Limit: &limit,
		Skip:  &skip,
		Sort:  sortFilter,
	}
	filter := bson.M{}
	if query != "" {
		err := json.Unmarshal([]byte(query), &filter)
		if err != nil {
			return 0, users, err
		}
	}
	cursor, err := m.CUser().Find(ctx, filter, findOption)
	if err != nil {
		return 0, users, err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		user := &v1.User{}
		err := cursor.Decode(user)
		if err != nil {
			logrus.WithError(err).Errorln("User Decode Error")
			return 0, users, err
		}
		users = append(users, user)
	}
	count, err := m.CUser().CountDocuments(ctx, filter)
	if err != nil {
		logrus.WithError(err).Errorln("User Count Documents Error")
		count = int64(0)
	}
	return count, users, nil
}

// AddAuthorization 添加授权
func (m *DB) AddAuthorization(ctx context.Context, username, password string) error {
	logrus.Debugln("Add Authorization", username, password)
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	auth := authorization{
		Username:   username,
		Crenditial: string(bytes),
	}
	_, err = m.CAuth().InsertOne(ctx, &auth)
	return err
}

// RemoveAuthorization 移除授权
func (m *DB) RemoveAuthorization(ctx context.Context, username string) error {
	filter := bson.M{"username": username}
	_, err := m.CAuth().DeleteMany(ctx, filter)
	return err
}

// Authenticate 权限认证
func (m *DB) Authenticate(ctx context.Context, username, password string) bool {
	logrus.Debugln("Authenticate", username, password)
	filter := bson.M{"username": username}
	auth := authorization{}
	err := m.CAuth().FindOne(ctx, filter).Decode(&auth)
	if err != nil {
		logrus.WithError(err).Errorln("Auth Find One Error")
		return false
	}
	err = bcrypt.CompareHashAndPassword([]byte(auth.Crenditial), []byte(password))
	if err != nil {
		logrus.WithError(err).Errorln("CompareHashAndPassword Error")
		return false
	}
	return true
}

// ChangeAuthorization 修改权限
func (m *DB) ChangeAuthorization(ctx context.Context, username, password string) error {
	// unique value check
	filter := bson.M{"username": username}
	logrus.Debugln("change Authorization", username, password)
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	auth := authorization{
		Username:   username,
		Crenditial: string(bytes),
	}
	update := bson.M{"$set": auth}
	err = m.CAuth().FindOneAndUpdate(ctx, filter, update).Err()
	return err
}

// GetUsersByIDs 根据Id列表查询用户信息
func (m *DB) GetUsersByIDs(ctx context.Context, ids []string) (int64, []*v1.User, error) {
	users := []*v1.User{}
	filter := bson.M{"id": bson.M{"$in": ids}}
	cursor, err := m.CUser().Find(ctx, filter)
	if err != nil {
		return 0, users, err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		user := &v1.User{}
		err := cursor.Decode(user)
		if err != nil {
			logrus.WithError(err).Errorln("User Decode Error")
			return 0, users, err
		}
		users = append(users, user)
	}
	count, err := m.CUser().CountDocuments(ctx, filter)
	if err != nil {
		logrus.WithError(err).Errorln("User Count Documents Error")
		count = int64(0)
	}
	return count, users, err
}

// RegisterUser 创建用户
func (m *DB) RegisterUser(ctx context.Context, user *v1.User, password string) (*v1.User, error) {
	err := m.AddAuthorization(ctx, *user.Name, password)
	if err != nil {
		logrus.WithError(err).Errorln("Add Authorization Error")
		return user, err
	}
	_, err = m.CUser().InsertOne(ctx, user)
	if err != nil {
		logrus.WithError(err).Errorln("User Insert One Error")
		return user, err
	}
	return user, nil
}

// ChangeUserPassword 修改用户密码
func (m *DB) ChangeUserPassword(ctx context.Context, user *v1.User, password string) (*v1.User, error) {
	err := m.ChangeAuthorization(ctx, *user.Name, password)
	if err != nil {
		logrus.WithError(err).Errorln("Change Authorization Error")
		return user, err
	}
	return user, nil
}

// UpdateUsers 编辑用户信息 Id/Name/CreateAt should not be update
func (m *DB) UpdateUsers(ctx context.Context, id string, user *v1.User) (*v1.User, error) {
	filter := bson.M{"id": id}
	tmp := &v1.User{}
	err := m.CUser().FindOne(ctx, filter).Decode(tmp)
	if err != nil {
		return user, err
	}
	user.Name = tmp.Name
	user.Created = tmp.Created
	Modified := time.Now().UnixNano() / 1e6
	user.Modified = &Modified
	update := bson.M{"$set": user}
	err = m.CUser().FindOneAndUpdate(ctx, filter, update).Err()
	return user, err
}

// FindUserCount 条件查询用户条数
func (m *DB) FindUserCount(ctx context.Context, username string) (int64, error) {
	filter := bson.M{"name": username}
	count, err := m.CUser().CountDocuments(ctx, filter)
	if err != nil {
		logrus.WithError(err).Errorln("User Count Documents Error")
		count = int64(0)
	}
	return count, err
}
