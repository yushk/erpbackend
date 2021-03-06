// Code generated by go-swagger; DO NOT EDIT.

package template

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	v1 "swagger/apiserver/v1"
)

// GetDeviceFieldInfosHandlerFunc turns a function with the right signature into a get device field infos handler
type GetDeviceFieldInfosHandlerFunc func(GetDeviceFieldInfosParams, *v1.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn GetDeviceFieldInfosHandlerFunc) Handle(params GetDeviceFieldInfosParams, principal *v1.Principal) middleware.Responder {
	return fn(params, principal)
}

// GetDeviceFieldInfosHandler interface for that can handle valid get device field infos params
type GetDeviceFieldInfosHandler interface {
	Handle(GetDeviceFieldInfosParams, *v1.Principal) middleware.Responder
}

// NewGetDeviceFieldInfos creates a new http.Handler for the get device field infos operation
func NewGetDeviceFieldInfos(ctx *middleware.Context, handler GetDeviceFieldInfosHandler) *GetDeviceFieldInfos {
	return &GetDeviceFieldInfos{Context: ctx, Handler: handler}
}

/*GetDeviceFieldInfos swagger:route GET /v1/devices/templates/fields template getDeviceFieldInfos

获取设备属性信息

获取设备属性信息

*/
type GetDeviceFieldInfos struct {
	Context *middleware.Context
	Handler GetDeviceFieldInfosHandler
}

func (o *GetDeviceFieldInfos) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetDeviceFieldInfosParams()

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
