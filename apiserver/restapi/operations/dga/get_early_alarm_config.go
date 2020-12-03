// Code generated by go-swagger; DO NOT EDIT.

package dga

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"
	v1 "swagger/apiserver/v1"

	"github.com/go-openapi/runtime/middleware"
)

// GetEarlyAlarmConfigHandlerFunc turns a function with the right signature into a get early alarm config handler
type GetEarlyAlarmConfigHandlerFunc func(GetEarlyAlarmConfigParams, *v1.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn GetEarlyAlarmConfigHandlerFunc) Handle(params GetEarlyAlarmConfigParams, principal *v1.Principal) middleware.Responder {
	return fn(params, principal)
}

// GetEarlyAlarmConfigHandler interface for that can handle valid get early alarm config params
type GetEarlyAlarmConfigHandler interface {
	Handle(GetEarlyAlarmConfigParams, *v1.Principal) middleware.Responder
}

// NewGetEarlyAlarmConfig creates a new http.Handler for the get early alarm config operation
func NewGetEarlyAlarmConfig(ctx *middleware.Context, handler GetEarlyAlarmConfigHandler) *GetEarlyAlarmConfig {
	return &GetEarlyAlarmConfig{Context: ctx, Handler: handler}
}

/*GetEarlyAlarmConfig swagger:route GET /v1/dga/early/config dga getEarlyAlarmConfig

获取油中溶解预警配置

获取油中溶解预警配置

*/
type GetEarlyAlarmConfig struct {
	Context *middleware.Context
	Handler GetEarlyAlarmConfigHandler
}

func (o *GetEarlyAlarmConfig) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetEarlyAlarmConfigParams()

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
