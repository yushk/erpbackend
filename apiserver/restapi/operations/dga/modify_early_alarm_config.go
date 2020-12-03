// Code generated by go-swagger; DO NOT EDIT.

package dga

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// ModifyEarlyAlarmConfigHandlerFunc turns a function with the right signature into a modify early alarm config handler
type ModifyEarlyAlarmConfigHandlerFunc func(ModifyEarlyAlarmConfigParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn ModifyEarlyAlarmConfigHandlerFunc) Handle(params ModifyEarlyAlarmConfigParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// ModifyEarlyAlarmConfigHandler interface for that can handle valid modify early alarm config params
type ModifyEarlyAlarmConfigHandler interface {
	Handle(ModifyEarlyAlarmConfigParams, interface{}) middleware.Responder
}

// NewModifyEarlyAlarmConfig creates a new http.Handler for the modify early alarm config operation
func NewModifyEarlyAlarmConfig(ctx *middleware.Context, handler ModifyEarlyAlarmConfigHandler) *ModifyEarlyAlarmConfig {
	return &ModifyEarlyAlarmConfig{Context: ctx, Handler: handler}
}

/*ModifyEarlyAlarmConfig swagger:route PUT /v1/dga/early/config/field dga modifyEarlyAlarmConfig

修改油中溶解预告警配置

修改超限告警配置

*/
type ModifyEarlyAlarmConfig struct {
	Context *middleware.Context
	Handler ModifyEarlyAlarmConfigHandler
}

func (o *ModifyEarlyAlarmConfig) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewModifyEarlyAlarmConfigParams()

	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		r = aCtx
	}
	var principal interface{}
	if uprinc != nil {
		principal = uprinc
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}