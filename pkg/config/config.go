package config

import (
	"fmt"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// viper keys
const (
	envPrefix = "iomas"

	EnvKey = "env"
	// DNSServer local,docker-compose,k8s
	DNSServer = "dns_server"
	// PodName k8s pod name example: iomas-analysis-57cd5998b5-pjbqb
	PodName = "pod.name"
	// PodNamespace k8s pod namespae example: default
	PodNamespace = "pod.namespace"

	DBType     = "db.type" // json;mongodb;mysql;sqlite3
	DBAddress  = "db.address"
	DBUsername = "db.username"
	DBPassword = "db.password"

	RootUsername = "root.username"
	RootPassword = "root.password"

	MonitorHost  = "monitor.service.host"
	MonitorPort  = "monitor.service.port"
	ArresterHost = "arrester.service.host"
	ArresterPort = "arrester.service.port"
	AlarmHost    = "alarm.service.host"
	AlarmPort    = "alarm.service.port"
	DGAHost      = "dga.service.host"
	DGAPort      = "dga.service.port"

	BusProducerHost = "bus.producer.host"
	BusProducerPort = "bus.producer.port"
	BusConsumerHost = "bus.consumer.host"
	BusConsumerPort = "bus.consumer.port"

	CaPemPath = "ca.pem"
	CaKeyPath = "ca.key"
	CaCrtPath = "ca.crt"
)

var viperInitOnce sync.Once
var config *viper.Viper

// Init 初期化token认证证书
func Init() {
	viperInitOnce.Do(func() {
		config = viper.New()
		config.SetConfigType("yaml")

		config.SetEnvPrefix(envPrefix) // will be uppercased automatically
		config.AutomaticEnv()
		config.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

		config.SetDefault(EnvKey, "prod")
		config.SetDefault(DNSServer, "local")
		config.SetDefault(PodName, "manager")
		config.SetDefault(PodNamespace, "iomas")
		config.SetDefault(DBType, "mongodb")
		config.SetDefault(DBAddress, "mongodb://localhost:27017")
		config.SetDefault(DBUsername, "")
		config.SetDefault(DBPassword, "")

		config.SetDefault(CaPemPath, "./certs/ca.pem")
		config.SetDefault(CaKeyPath, "./certs/ca.key")
		config.SetDefault(CaCrtPath, "./certs/ca.crt")

		config.SetDefault(RootUsername, "admin")
		config.SetDefault(RootPassword, "admin@123456")

		config.SetDefault(MonitorHost, "localhost")
		config.SetDefault(MonitorPort, "30033")

		config.SetDefault(ArresterHost, "localhost")
		config.SetDefault(ArresterPort, "30034")

		config.SetDefault(AlarmHost, "localhost")
		config.SetDefault(AlarmPort, "30035")

		config.SetDefault(BusProducerHost, "")
		config.SetDefault(BusProducerPort, "")

		config.SetDefault(BusConsumerHost, "")
		config.SetDefault(BusConsumerPort, "")
		config.SetDefault(DGAHost, "localhost")
		config.SetDefault(DGAPort, "30036")
		configFile := fmt.Sprintf("config-%s", config.Get(EnvKey))
		logrus.Infof("config file is %s", configFile+".yaml")
		config.SetConfigName(configFile) // name of config file (without extension)
		config.AddConfigPath("/iomas/")
		config.AddConfigPath("/etc/iomas/")
		config.AddConfigPath("$HOME/.iomas")
		config.AddConfigPath(".")
		config.AddConfigPath("./bin")

		err := config.ReadInConfig()
		if err != nil {
			switch err := err.(type) {
			case viper.ConfigFileNotFoundError:
				logrus.Debugf("No config file '%s' found. Using environment variables only.", configFile)
			case viper.ConfigParseError:
				logrus.Panicf("Cannot read config file: %s: %s\n", configFile, err)
			default:
				logrus.Debugf("Read config file error: %s: %s\n", configFile, err)
			}
		} else {
			logrus.Infof("Loading config from file %s\n", config.ConfigFileUsed())
		}
	})
}

// GetString returns the value associated with the key as a string.
func GetString(key string) string {
	return config.GetString(key)
}
