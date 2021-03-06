// Code generated by go-swagger; DO NOT EDIT.

package alarm

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"
	v1 "swagger/apiserver/v1"

	"github.com/go-openapi/runtime/middleware"
)

// GetIntelligenceAlarmsHandlerFunc turns a function with the right signature into a get intelligence alarms handler
type GetIntelligenceAlarmsHandlerFunc func(GetIntelligenceAlarmsParams, *v1.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn GetIntelligenceAlarmsHandlerFunc) Handle(params GetIntelligenceAlarmsParams, principal *v1.Principal) middleware.Responder {
	return fn(params, principal)
}

// GetIntelligenceAlarmsHandler interface for that can handle valid get intelligence alarms params
type GetIntelligenceAlarmsHandler interface {
	Handle(GetIntelligenceAlarmsParams, *v1.Principal) middleware.Responder
}

// NewGetIntelligenceAlarms creates a new http.Handler for the get intelligence alarms operation
func NewGetIntelligenceAlarms(ctx *middleware.Context, handler GetIntelligenceAlarmsHandler) *GetIntelligenceAlarms {
	return &GetIntelligenceAlarms{Context: ctx, Handler: handler}
}

/*GetIntelligenceAlarms swagger:route GET /v1/alarms/intelligence alarm getIntelligenceAlarms

获取智能告警列表

获取智能告警列表

*/
type GetIntelligenceAlarms struct {
	Context *middleware.Context
	Handler GetIntelligenceAlarmsHandler
}

func (o *GetIntelligenceAlarms) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetIntelligenceAlarmsParams()

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
