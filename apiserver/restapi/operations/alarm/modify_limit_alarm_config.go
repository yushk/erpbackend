// Code generated by go-swagger; DO NOT EDIT.

package alarm

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"
	v1 "swagger/apiserver/v1"

	"github.com/go-openapi/runtime/middleware"
)

// ModifyLimitAlarmConfigHandlerFunc turns a function with the right signature into a modify limit alarm config handler
type ModifyLimitAlarmConfigHandlerFunc func(ModifyLimitAlarmConfigParams, *v1.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn ModifyLimitAlarmConfigHandlerFunc) Handle(params ModifyLimitAlarmConfigParams, principal *v1.Principal) middleware.Responder {
	return fn(params, principal)
}

// ModifyLimitAlarmConfigHandler interface for that can handle valid modify limit alarm config params
type ModifyLimitAlarmConfigHandler interface {
	Handle(ModifyLimitAlarmConfigParams, *v1.Principal) middleware.Responder
}

// NewModifyLimitAlarmConfig creates a new http.Handler for the modify limit alarm config operation
func NewModifyLimitAlarmConfig(ctx *middleware.Context, handler ModifyLimitAlarmConfigHandler) *ModifyLimitAlarmConfig {
	return &ModifyLimitAlarmConfig{Context: ctx, Handler: handler}
}

/*ModifyLimitAlarmConfig swagger:route PUT /v1/alarms/limit/config/field alarm modifyLimitAlarmConfig

修改超限告警配置

修改超限告警配置

*/
type ModifyLimitAlarmConfig struct {
	Context *middleware.Context
	Handler ModifyLimitAlarmConfigHandler
}

func (o *ModifyLimitAlarmConfig) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewModifyLimitAlarmConfigParams()

	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		r = aCtx
	}
	var principal *v1.Principal
	if uprinc != nil {
		principal = uprinc.(*v1.Principal) // this is really a v1.Principal, I promise
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
