// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"swagger/apiserver/restapi/operations"
	"swagger/apiserver/restapi/operations/alarm"
	"swagger/apiserver/restapi/operations/analysis"
	"swagger/apiserver/restapi/operations/config"
	"swagger/apiserver/restapi/operations/data"
	"swagger/apiserver/restapi/operations/device"
	"swagger/apiserver/restapi/operations/dga"
	"swagger/apiserver/restapi/operations/file"
	"swagger/apiserver/restapi/operations/logr"
	"swagger/apiserver/restapi/operations/oauth"
	"swagger/apiserver/restapi/operations/system"
	"swagger/apiserver/restapi/operations/template"
	"swagger/apiserver/restapi/operations/user"
	"swagger/apiserver/server"
	v1 "swagger/apiserver/v1"
)

//go:generate swagger generate server --target ../../apiserver --name Material --spec ../swagger/swagger.yaml --model-package v1 --principal v1.Principal

func configureFlags(api *operations.MaterialAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *operations.MaterialAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	api.UseSwaggerUI()
	// To continue using redoc as your UI, uncomment the following line
	// api.UseRedoc()

	api.JSONConsumer = runtime.JSONConsumer()
	api.UrlformConsumer = runtime.DiscardConsumer

	api.BinProducer = runtime.ByteStreamProducer()
	api.JSONProducer = runtime.JSONProducer()

	if api.OAuth2Auth == nil {
		api.OAuth2Auth = func(token string, scopes []string) (*v1.Principal, error) {
			return nil, errors.NotImplemented("oauth2 bearer auth (OAuth2) has not yet been implemented")
		}
	}

	// Set your custom authorizer if needed. Default one is security.Authorized()
	// Expected interface runtime.Authorizer
	//
	// Example:
	// api.APIAuthorizer = security.Authorized()
	if api.AnalysisAggregateHandler == nil {
		api.AnalysisAggregateHandler = analysis.AggregateHandlerFunc(func(params analysis.AggregateParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation analysis.Aggregate has not yet been implemented")
		})
	}
	if api.UserChangeCurrentUserPasswordHandler == nil {
		api.UserChangeCurrentUserPasswordHandler = user.ChangeCurrentUserPasswordHandlerFunc(func(params user.ChangeCurrentUserPasswordParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation user.ChangeCurrentUserPassword has not yet been implemented")
		})
	}
	if api.UserChangeUserPasswordHandler == nil {
		api.UserChangeUserPasswordHandler = user.ChangeUserPasswordHandlerFunc(func(params user.ChangeUserPasswordParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation user.ChangeUserPassword has not yet been implemented")
		})
	}
	if api.DeviceCheckBasicsDevicePhaseHandler == nil {
		api.DeviceCheckBasicsDevicePhaseHandler = device.CheckBasicsDevicePhaseHandlerFunc(func(params device.CheckBasicsDevicePhaseParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation device.CheckBasicsDevicePhase has not yet been implemented")
		})
	}
	if api.SystemConfigHandler == nil {
		api.SystemConfigHandler = system.ConfigHandlerFunc(func(params system.ConfigParams) middleware.Responder {
			return middleware.NotImplemented("operation system.Config has not yet been implemented")
		})
	}
	if api.DgaConfirmEarlyAlarmHandler == nil {
		api.DgaConfirmEarlyAlarmHandler = dga.ConfirmEarlyAlarmHandlerFunc(func(params dga.ConfirmEarlyAlarmParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation dga.ConfirmEarlyAlarm has not yet been implemented")
		})
	}
	if api.AlarmConfirmIntelligenceAlarmHandler == nil {
		api.AlarmConfirmIntelligenceAlarmHandler = alarm.ConfirmIntelligenceAlarmHandlerFunc(func(params alarm.ConfirmIntelligenceAlarmParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation alarm.ConfirmIntelligenceAlarm has not yet been implemented")
		})
	}
	if api.AlarmConfirmLimitAlarmHandler == nil {
		api.AlarmConfirmLimitAlarmHandler = alarm.ConfirmLimitAlarmHandlerFunc(func(params alarm.ConfirmLimitAlarmParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation alarm.ConfirmLimitAlarm has not yet been implemented")
		})
	}
	if api.AlarmConfirmTransferAlarmHandler == nil {
		api.AlarmConfirmTransferAlarmHandler = alarm.ConfirmTransferAlarmHandlerFunc(func(params alarm.ConfirmTransferAlarmParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation alarm.ConfirmTransferAlarm has not yet been implemented")
		})
	}
	if api.ConfigControlAlarmTaskHandler == nil {
		api.ConfigControlAlarmTaskHandler = config.ControlAlarmTaskHandlerFunc(func(params config.ControlAlarmTaskParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation config.ControlAlarmTask has not yet been implemented")
		})
	}
	if api.ConfigCreateCleaningConfigsHandler == nil {
		api.ConfigCreateCleaningConfigsHandler = config.CreateCleaningConfigsHandlerFunc(func(params config.CreateCleaningConfigsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation config.CreateCleaningConfigs has not yet been implemented")
		})
	}
	if api.DeviceCreateDeviceHandler == nil {
		api.DeviceCreateDeviceHandler = device.CreateDeviceHandlerFunc(func(params device.CreateDeviceParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation device.CreateDevice has not yet been implemented")
		})
	}
	api.UserCreateUserHandler = user.CreateUserHandlerFunc(func(params user.CreateUserParams, principal *v1.Principal) middleware.Responder {
		return server.CreateUser(params, principal)
	})
	if api.ConfigDeleteCleaningConfigsHandler == nil {
		api.ConfigDeleteCleaningConfigsHandler = config.DeleteCleaningConfigsHandlerFunc(func(params config.DeleteCleaningConfigsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation config.DeleteCleaningConfigs has not yet been implemented")
		})
	}
	if api.DeviceDeleteDeviceHandler == nil {
		api.DeviceDeleteDeviceHandler = device.DeleteDeviceHandlerFunc(func(params device.DeleteDeviceParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation device.DeleteDevice has not yet been implemented")
		})
	}
	if api.UserDeleteUserHandler == nil {
		api.UserDeleteUserHandler = user.DeleteUserHandlerFunc(func(params user.DeleteUserParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation user.DeleteUser has not yet been implemented")
		})
	}
	if api.FileDownloadFileHandler == nil {
		api.FileDownloadFileHandler = file.DownloadFileHandlerFunc(func(params file.DownloadFileParams) middleware.Responder {
			return middleware.NotImplemented("operation file.DownloadFile has not yet been implemented")
		})
	}
	if api.ConfigGetAlarmConfigsHandler == nil {
		api.ConfigGetAlarmConfigsHandler = config.GetAlarmConfigsHandlerFunc(func(params config.GetAlarmConfigsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation config.GetAlarmConfigs has not yet been implemented")
		})
	}
	if api.DeviceGetBasicsDevicesHandler == nil {
		api.DeviceGetBasicsDevicesHandler = device.GetBasicsDevicesHandlerFunc(func(params device.GetBasicsDevicesParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation device.GetBasicsDevices has not yet been implemented")
		})
	}
	if api.ConfigGetCleaningConfigsHandler == nil {
		api.ConfigGetCleaningConfigsHandler = config.GetCleaningConfigsHandlerFunc(func(params config.GetCleaningConfigsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation config.GetCleaningConfigs has not yet been implemented")
		})
	}
	if api.AlarmGetDeviceAlarmsHandler == nil {
		api.AlarmGetDeviceAlarmsHandler = alarm.GetDeviceAlarmsHandlerFunc(func(params alarm.GetDeviceAlarmsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation alarm.GetDeviceAlarms has not yet been implemented")
		})
	}
	if api.DataGetDeviceChartsHandler == nil {
		api.DataGetDeviceChartsHandler = data.GetDeviceChartsHandlerFunc(func(params data.GetDeviceChartsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation data.GetDeviceCharts has not yet been implemented")
		})
	}
	if api.TemplateGetDeviceFieldInfosHandler == nil {
		api.TemplateGetDeviceFieldInfosHandler = template.GetDeviceFieldInfosHandlerFunc(func(params template.GetDeviceFieldInfosParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation template.GetDeviceFieldInfos has not yet been implemented")
		})
	}
	if api.TemplateGetDeviceTemplateInfosHandler == nil {
		api.TemplateGetDeviceTemplateInfosHandler = template.GetDeviceTemplateInfosHandlerFunc(func(params template.GetDeviceTemplateInfosParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation template.GetDeviceTemplateInfos has not yet been implemented")
		})
	}
	if api.DataGetDeviceValuesHandler == nil {
		api.DataGetDeviceValuesHandler = data.GetDeviceValuesHandlerFunc(func(params data.GetDeviceValuesParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation data.GetDeviceValues has not yet been implemented")
		})
	}
	if api.DeviceGetDevicesHandler == nil {
		api.DeviceGetDevicesHandler = device.GetDevicesHandlerFunc(func(params device.GetDevicesParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation device.GetDevices has not yet been implemented")
		})
	}
	if api.DgaGetEarlyAlarmConfigHandler == nil {
		api.DgaGetEarlyAlarmConfigHandler = dga.GetEarlyAlarmConfigHandlerFunc(func(params dga.GetEarlyAlarmConfigParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation dga.GetEarlyAlarmConfig has not yet been implemented")
		})
	}
	if api.DgaGetEarlyAlarmsHandler == nil {
		api.DgaGetEarlyAlarmsHandler = dga.GetEarlyAlarmsHandlerFunc(func(params dga.GetEarlyAlarmsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation dga.GetEarlyAlarms has not yet been implemented")
		})
	}
	if api.DgaGetEarlyHistoryAlarmsHandler == nil {
		api.DgaGetEarlyHistoryAlarmsHandler = dga.GetEarlyHistoryAlarmsHandlerFunc(func(params dga.GetEarlyHistoryAlarmsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation dga.GetEarlyHistoryAlarms has not yet been implemented")
		})
	}
	if api.AlarmGetHistoryLimitAlarmsHandler == nil {
		api.AlarmGetHistoryLimitAlarmsHandler = alarm.GetHistoryLimitAlarmsHandlerFunc(func(params alarm.GetHistoryLimitAlarmsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation alarm.GetHistoryLimitAlarms has not yet been implemented")
		})
	}
	if api.AlarmGetHistoryTransferAlarmsHandler == nil {
		api.AlarmGetHistoryTransferAlarmsHandler = alarm.GetHistoryTransferAlarmsHandlerFunc(func(params alarm.GetHistoryTransferAlarmsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation alarm.GetHistoryTransferAlarms has not yet been implemented")
		})
	}
	if api.AlarmGetIntelligenceAlarmsHandler == nil {
		api.AlarmGetIntelligenceAlarmsHandler = alarm.GetIntelligenceAlarmsHandlerFunc(func(params alarm.GetIntelligenceAlarmsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation alarm.GetIntelligenceAlarms has not yet been implemented")
		})
	}
	if api.AlarmGetLimitAlarmConfigHandler == nil {
		api.AlarmGetLimitAlarmConfigHandler = alarm.GetLimitAlarmConfigHandlerFunc(func(params alarm.GetLimitAlarmConfigParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation alarm.GetLimitAlarmConfig has not yet been implemented")
		})
	}
	if api.AlarmGetLimitAlarmsHandler == nil {
		api.AlarmGetLimitAlarmsHandler = alarm.GetLimitAlarmsHandlerFunc(func(params alarm.GetLimitAlarmsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation alarm.GetLimitAlarms has not yet been implemented")
		})
	}
	if api.LogrGetLogsHandler == nil {
		api.LogrGetLogsHandler = logr.GetLogsHandlerFunc(func(params logr.GetLogsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation logr.GetLogs has not yet been implemented")
		})
	}
	if api.DataGetLongitudinalChartsHandler == nil {
		api.DataGetLongitudinalChartsHandler = data.GetLongitudinalChartsHandlerFunc(func(params data.GetLongitudinalChartsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation data.GetLongitudinalCharts has not yet been implemented")
		})
	}
	if api.DeviceGetSimilarTestingDevicesHandler == nil {
		api.DeviceGetSimilarTestingDevicesHandler = device.GetSimilarTestingDevicesHandlerFunc(func(params device.GetSimilarTestingDevicesParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation device.GetSimilarTestingDevices has not yet been implemented")
		})
	}
	if api.ConfigGetTransferAlarmConfigHandler == nil {
		api.ConfigGetTransferAlarmConfigHandler = config.GetTransferAlarmConfigHandlerFunc(func(params config.GetTransferAlarmConfigParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation config.GetTransferAlarmConfig has not yet been implemented")
		})
	}
	if api.AlarmGetTransferAlarmsHandler == nil {
		api.AlarmGetTransferAlarmsHandler = alarm.GetTransferAlarmsHandlerFunc(func(params alarm.GetTransferAlarmsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation alarm.GetTransferAlarms has not yet been implemented")
		})
	}
	if api.DataGetTransverseChartsHandler == nil {
		api.DataGetTransverseChartsHandler = data.GetTransverseChartsHandlerFunc(func(params data.GetTransverseChartsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation data.GetTransverseCharts has not yet been implemented")
		})
	}
	if api.UserGetUserHandler == nil {
		api.UserGetUserHandler = user.GetUserHandlerFunc(func(params user.GetUserParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation user.GetUser has not yet been implemented")
		})
	}
	api.UserGetUserInfoHandler = user.GetUserInfoHandlerFunc(func(params user.GetUserInfoParams, principal *v1.Principal) middleware.Responder {
		return server.GetUserInfo(params, principal)
	})
	if api.UserGetUsersHandler == nil {
		api.UserGetUsersHandler = user.GetUsersHandlerFunc(func(params user.GetUsersParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation user.GetUsers has not yet been implemented")
		})
	}
	api.UserLoginHandler = user.LoginHandlerFunc(func(params user.LoginParams) middleware.Responder {
		return server.Login(params)
	})
	if api.UserLogoutHandler == nil {
		api.UserLogoutHandler = user.LogoutHandlerFunc(func(params user.LogoutParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation user.Logout has not yet been implemented")
		})
	}
	if api.DgaModifyEarlyAlarmConfigHandler == nil {
		api.DgaModifyEarlyAlarmConfigHandler = dga.ModifyEarlyAlarmConfigHandlerFunc(func(params dga.ModifyEarlyAlarmConfigParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation dga.ModifyEarlyAlarmConfig has not yet been implemented")
		})
	}
	if api.AlarmModifyLimitAlarmConfigHandler == nil {
		api.AlarmModifyLimitAlarmConfigHandler = alarm.ModifyLimitAlarmConfigHandlerFunc(func(params alarm.ModifyLimitAlarmConfigParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation alarm.ModifyLimitAlarmConfig has not yet been implemented")
		})
	}
	if api.ConfigModifyTransferAlarmConfigHandler == nil {
		api.ConfigModifyTransferAlarmConfigHandler = config.ModifyTransferAlarmConfigHandlerFunc(func(params config.ModifyTransferAlarmConfigParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation config.ModifyTransferAlarmConfig has not yet been implemented")
		})
	}
	if api.SystemPingHandler == nil {
		api.SystemPingHandler = system.PingHandlerFunc(func(params system.PingParams) middleware.Responder {
			return middleware.NotImplemented("operation system.Ping has not yet been implemented")
		})
	}
	if api.DgaReceiveDataHandler == nil {
		api.DgaReceiveDataHandler = dga.ReceiveDataHandlerFunc(func(params dga.ReceiveDataParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation dga.ReceiveData has not yet been implemented")
		})
	}
	if api.OauthRefreshTokenHandler == nil {
		api.OauthRefreshTokenHandler = oauth.RefreshTokenHandlerFunc(func(params oauth.RefreshTokenParams) middleware.Responder {
			return middleware.NotImplemented("operation oauth.RefreshToken has not yet been implemented")
		})
	}
	if api.TemplateSynchronizeDeviceTemplateInfoHandler == nil {
		api.TemplateSynchronizeDeviceTemplateInfoHandler = template.SynchronizeDeviceTemplateInfoHandlerFunc(func(params template.SynchronizeDeviceTemplateInfoParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation template.SynchronizeDeviceTemplateInfo has not yet been implemented")
		})
	}
	api.OauthTokenHandler = oauth.TokenHandlerFunc(func(params oauth.TokenParams) middleware.Responder {
		return server.Token(params)
	})
	if api.ConfigUpdateAlarmConfigsHandler == nil {
		api.ConfigUpdateAlarmConfigsHandler = config.UpdateAlarmConfigsHandlerFunc(func(params config.UpdateAlarmConfigsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation config.UpdateAlarmConfigs has not yet been implemented")
		})
	}
	if api.ConfigUpdateCleaningActiveRuleHandler == nil {
		api.ConfigUpdateCleaningActiveRuleHandler = config.UpdateCleaningActiveRuleHandlerFunc(func(params config.UpdateCleaningActiveRuleParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation config.UpdateCleaningActiveRule has not yet been implemented")
		})
	}
	if api.ConfigUpdateCleaningConfigsHandler == nil {
		api.ConfigUpdateCleaningConfigsHandler = config.UpdateCleaningConfigsHandlerFunc(func(params config.UpdateCleaningConfigsParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation config.UpdateCleaningConfigs has not yet been implemented")
		})
	}
	if api.DeviceUpdateDeviceHandler == nil {
		api.DeviceUpdateDeviceHandler = device.UpdateDeviceHandlerFunc(func(params device.UpdateDeviceParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation device.UpdateDevice has not yet been implemented")
		})
	}
	if api.TemplateUpdateDeviceFieldInfoHandler == nil {
		api.TemplateUpdateDeviceFieldInfoHandler = template.UpdateDeviceFieldInfoHandlerFunc(func(params template.UpdateDeviceFieldInfoParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation template.UpdateDeviceFieldInfo has not yet been implemented")
		})
	}
	if api.TemplateUpdateDeviceProfileInfoHandler == nil {
		api.TemplateUpdateDeviceProfileInfoHandler = template.UpdateDeviceProfileInfoHandlerFunc(func(params template.UpdateDeviceProfileInfoParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation template.UpdateDeviceProfileInfo has not yet been implemented")
		})
	}
	if api.DgaUpdateEarlyAlarmConfigHandler == nil {
		api.DgaUpdateEarlyAlarmConfigHandler = dga.UpdateEarlyAlarmConfigHandlerFunc(func(params dga.UpdateEarlyAlarmConfigParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation dga.UpdateEarlyAlarmConfig has not yet been implemented")
		})
	}
	if api.AlarmUpdateLimitAlarmConfigHandler == nil {
		api.AlarmUpdateLimitAlarmConfigHandler = alarm.UpdateLimitAlarmConfigHandlerFunc(func(params alarm.UpdateLimitAlarmConfigParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation alarm.UpdateLimitAlarmConfig has not yet been implemented")
		})
	}
	if api.ConfigUpdateTransferAlarmConfigHandler == nil {
		api.ConfigUpdateTransferAlarmConfigHandler = config.UpdateTransferAlarmConfigHandlerFunc(func(params config.UpdateTransferAlarmConfigParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation config.UpdateTransferAlarmConfig has not yet been implemented")
		})
	}
	if api.UserUpdateUserHandler == nil {
		api.UserUpdateUserHandler = user.UpdateUserHandlerFunc(func(params user.UpdateUserParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation user.UpdateUser has not yet been implemented")
		})
	}
	if api.DeviceUploadDevicesHandler == nil {
		api.DeviceUploadDevicesHandler = device.UploadDevicesHandlerFunc(func(params device.UploadDevicesParams, principal *v1.Principal) middleware.Responder {
			return middleware.NotImplemented("operation device.UploadDevices has not yet been implemented")
		})
	}
	if api.SystemVersionHandler == nil {
		api.SystemVersionHandler = system.VersionHandlerFunc(func(params system.VersionParams) middleware.Responder {
			return middleware.NotImplemented("operation system.Version has not yet been implemented")
		})
	}

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}
