// Code generated by go-swagger; DO NOT EDIT.

package dga

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"
	v1 "swagger/apiserver/v1"

	"github.com/go-openapi/runtime/middleware"
)

// GetEarlyHistoryAlarmsHandlerFunc turns a function with the right signature into a get early history alarms handler
type GetEarlyHistoryAlarmsHandlerFunc func(GetEarlyHistoryAlarmsParams, *v1.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn GetEarlyHistoryAlarmsHandlerFunc) Handle(params GetEarlyHistoryAlarmsParams, principal *v1.Principal) middleware.Responder {
	return fn(params, principal)
}

// GetEarlyHistoryAlarmsHandler interface for that can handle valid get early history alarms params
type GetEarlyHistoryAlarmsHandler interface {
	Handle(GetEarlyHistoryAlarmsParams, *v1.Principal) middleware.Responder
}

// NewGetEarlyHistoryAlarms creates a new http.Handler for the get early history alarms operation
func NewGetEarlyHistoryAlarms(ctx *middleware.Context, handler GetEarlyHistoryAlarmsHandler) *GetEarlyHistoryAlarms {
	return &GetEarlyHistoryAlarms{Context: ctx, Handler: handler}
}

/*GetEarlyHistoryAlarms swagger:route GET /v1/alarms/early/history dga getEarlyHistoryAlarms

获取油中溶解预警列表

获取油中溶解预警列表

*/
type GetEarlyHistoryAlarms struct {
	Context *middleware.Context
	Handler GetEarlyHistoryAlarmsHandler
}

func (o *GetEarlyHistoryAlarms) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetEarlyHistoryAlarmsParams()

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
