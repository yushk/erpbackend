package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-openapi/runtime"
	middleware "github.com/go-openapi/runtime/middleware"
	gateway "github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/status"
)

// Error 返回错误信息
func Error(err error) middleware.Responder {
	logrus.WithError(err).Errorln("Returning Error")
	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		s := status.Convert(err)
		code := gateway.HTTPStatusFromCode(s.Code())
		w.WriteHeader(code)
		payload, _ := json.Marshal(map[string]interface{}{
			"error":   s.Message(),
			"message": s.Message(),
			"code":    code,
			"details": s.Proto().GetDetails(),
		})
		_, err := w.Write(payload)
		if err != nil {
			logrus.WithError(err).Errorln("Write Payload Error")
		}
	})
}

// BadRequestError 返回400状态码
func BadRequestError(message string) middleware.Responder {
	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		w.WriteHeader(http.StatusBadRequest)
		payload, _ := json.Marshal(map[string]interface{}{
			"error":   message,
			"message": message,
			"code":    http.StatusBadRequest,
			"details": "Bad Request",
		})
		_, err := w.Write(payload)
		if err != nil {
			logrus.WithError(err).Errorln("Write Payload Error")
		}
	})
}

// TimeConvert 将时间统一为毫秒级别
func TimeConvert(time *int64) *int64 {
	timeLen := len(strconv.FormatInt(*time, 10))
	switch timeLen {
	case 10:
		time := *time * 1000
		return &time
	case 13:
		return time
	default:
		time := int64(0)
		return &time
	}
}

// ErrorMessage 返回error中的msg
func ErrorMessage(err error) string {
	return status.Convert(err).Message()
}
