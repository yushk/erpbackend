// Code generated by go-swagger; DO NOT EDIT.

package data

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"
	v1 "swagger/apiserver/v1"

	"github.com/go-openapi/runtime/middleware"
)

// GetDeviceValuesHandlerFunc turns a function with the right signature into a get device values handler
type GetDeviceValuesHandlerFunc func(GetDeviceValuesParams, *v1.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn GetDeviceValuesHandlerFunc) Handle(params GetDeviceValuesParams, principal *v1.Principal) middleware.Responder {
	return fn(params, principal)
}

// GetDeviceValuesHandler interface for that can handle valid get device values params
type GetDeviceValuesHandler interface {
	Handle(GetDeviceValuesParams, *v1.Principal) middleware.Responder
}

// NewGetDeviceValues creates a new http.Handler for the get device values operation
func NewGetDeviceValues(ctx *middleware.Context, handler GetDeviceValuesHandler) *GetDeviceValues {
	return &GetDeviceValues{Context: ctx, Handler: handler}
}

/*GetDeviceValues swagger:route GET /v1/devices/values data getDeviceValues

获取设备属性值列表

获取设备属性值列表

*/
type GetDeviceValues struct {
	Context *middleware.Context
	Handler GetDeviceValuesHandler
}

func (o *GetDeviceValues) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetDeviceValuesParams()

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
