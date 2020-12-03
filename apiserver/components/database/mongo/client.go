package mongo

import (
	"context"

	opts "swagger/apiserver/components/database/options"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Mongo数据库名和表名定义
const (
	database = "material"
)

const (
	collectionUser                = "user"
	collectionCar                 = "car"
	collectionSupplier            = "supplier"
	collectionConsumer            = "consumer"
	collectionStoreHouse          = "storehouse"
	collectionLogEntry            = "logEntry"
	collectionEvent               = "event"
	collectionReading             = "reading"
	collectionStationDevice       = "stationDevice"
	collectionDeviceTemplate      = "deviceTemplate"
	collectionAuth                = "auth"
	collectionCleaningConfig      = "cleaningConfig"
	collectionAlarmConfig         = "alarmConfig"
	collectionIntelligenceAlarm   = "intelligenceAlarm"
	collectionLimitAlarmConfig    = "limitAlarmConfig"
	collectionLimitAlarm          = "limitAlarm"
	collectionTransferAlarmConfig = "transferAlarmConfig"
	collectionTransferAlarm       = "transferAlarm"
)

type DB struct {
	client *mongo.Client
}

func NewDB(ops *opts.Options) (*DB, error) {
	// Set client options
	clientOptions := options.Client().ApplyURI(ops.Address)

	if ops.Username != "" {
		auth := options.Credential{
			Username: ops.Username,
			Password: ops.Password,
		}
		clientOptions.SetAuth(auth)
	}
	// Connect to MongoDB
	client, err := mongo.Connect(context.TODO(), clientOptions)

	if err != nil {
		logrus.Fatalln(err)
	}
	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		logrus.Fatalln(err)
	}
	logrus.Infoln("MongoDB Is Connected ...")

	m := &DB{
		client: client,
	}
	return m, nil
}

type index struct {
	Key  map[string]int
	NS   string
	Name string
}

func (m *DB) Close() error {
	if m.client != nil {
		return m.client.Disconnect(context.TODO())
	}
	return nil
}

// DB 数据库句柄
func (m *DB) DB(name string, opts ...*options.DatabaseOptions) *mongo.Database {
	return m.client.Database(name)
}

// C 集合句柄
func (m *DB) C(name string, opts ...*options.CollectionOptions) *mongo.Collection {
	return m.client.Database(database).Collection(name, opts...)
}

// CUser 用户集合句柄
func (m *DB) CUser() *mongo.Collection {
	return m.client.Database(database).Collection(collectionUser)
}