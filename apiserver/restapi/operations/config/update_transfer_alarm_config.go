// Code generated by go-swagger; DO NOT EDIT.

package config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"
	v1 "swagger/apiserver/v1"

	"github.com/go-openapi/runtime/middleware"
)

// UpdateTransferAlarmConfigHandlerFunc turns a function with the right signature into a update transfer alarm config handler
type UpdateTransferAlarmConfigHandlerFunc func(UpdateTransferAlarmConfigParams, *v1.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn UpdateTransferAlarmConfigHandlerFunc) Handle(params UpdateTransferAlarmConfigParams, principal *v1.Principal) middleware.Responder {
	return fn(params, principal)
}

// UpdateTransferAlarmConfigHandler interface for that can handle valid update transfer alarm config params
type UpdateTransferAlarmConfigHandler interface {
	Handle(UpdateTransferAlarmConfigParams, *v1.Principal) middleware.Responder
}

// NewUpdateTransferAlarmConfig creates a new http.Handler for the update transfer alarm config operation
func NewUpdateTransferAlarmConfig(ctx *middleware.Context, handler UpdateTransferAlarmConfigHandler) *UpdateTransferAlarmConfig {
	return &UpdateTransferAlarmConfig{Context: ctx, Handler: handler}
}

/*UpdateTransferAlarmConfig swagger:route PUT /v1/configs/alarms/transfer config updateTransferAlarmConfig

更新传输告警配置信息

更新传输告警配置信息

*/
type UpdateTransferAlarmConfig struct {
	Context *middleware.Context
	Handler UpdateTransferAlarmConfigHandler
}

func (o *UpdateTransferAlarmConfig) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewUpdateTransferAlarmConfigParams()

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
