// Code generated by go-swagger; DO NOT EDIT.

package alarm

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// GetHistoryLimitAlarmsHandlerFunc turns a function with the right signature into a get history limit alarms handler
type GetHistoryLimitAlarmsHandlerFunc func(GetHistoryLimitAlarmsParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn GetHistoryLimitAlarmsHandlerFunc) Handle(params GetHistoryLimitAlarmsParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// GetHistoryLimitAlarmsHandler interface for that can handle valid get history limit alarms params
type GetHistoryLimitAlarmsHandler interface {
	Handle(GetHistoryLimitAlarmsParams, interface{}) middleware.Responder
}

// NewGetHistoryLimitAlarms creates a new http.Handler for the get history limit alarms operation
func NewGetHistoryLimitAlarms(ctx *middleware.Context, handler GetHistoryLimitAlarmsHandler) *GetHistoryLimitAlarms {
	return &GetHistoryLimitAlarms{Context: ctx, Handler: handler}
}

/*GetHistoryLimitAlarms swagger:route GET /v1/alarms/limit/history alarm getHistoryLimitAlarms

获取历史超限告警列表

获取历史超限告警列表

*/
type GetHistoryLimitAlarms struct {
	Context *middleware.Context
	Handler GetHistoryLimitAlarmsHandler
}

func (o *GetHistoryLimitAlarms) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetHistoryLimitAlarmsParams()

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
