// Code generated by go-swagger; DO NOT EDIT.

package alarm

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"
	v1 "swagger/apiserver/v1"

	"github.com/go-openapi/runtime/middleware"
)

// UpdateLimitAlarmConfigHandlerFunc turns a function with the right signature into a update limit alarm config handler
type UpdateLimitAlarmConfigHandlerFunc func(UpdateLimitAlarmConfigParams, *v1.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn UpdateLimitAlarmConfigHandlerFunc) Handle(params UpdateLimitAlarmConfigParams, principal *v1.Principal) middleware.Responder {
	return fn(params, principal)
}

// UpdateLimitAlarmConfigHandler interface for that can handle valid update limit alarm config params
type UpdateLimitAlarmConfigHandler interface {
	Handle(UpdateLimitAlarmConfigParams, *v1.Principal) middleware.Responder
}

// NewUpdateLimitAlarmConfig creates a new http.Handler for the update limit alarm config operation
func NewUpdateLimitAlarmConfig(ctx *middleware.Context, handler UpdateLimitAlarmConfigHandler) *UpdateLimitAlarmConfig {
	return &UpdateLimitAlarmConfig{Context: ctx, Handler: handler}
}

/*UpdateLimitAlarmConfig swagger:route PUT /v1/alarms/limit/config alarm updateLimitAlarmConfig

更新超限告警配置

更新超限告警配置

*/
type UpdateLimitAlarmConfig struct {
	Context *middleware.Context
	Handler UpdateLimitAlarmConfigHandler
}

func (o *UpdateLimitAlarmConfig) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewUpdateLimitAlarmConfigParams()

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
