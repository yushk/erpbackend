// Code generated by go-swagger; DO NOT EDIT.

package device

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// DeleteDeviceHandlerFunc turns a function with the right signature into a delete device handler
type DeleteDeviceHandlerFunc func(DeleteDeviceParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn DeleteDeviceHandlerFunc) Handle(params DeleteDeviceParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// DeleteDeviceHandler interface for that can handle valid delete device params
type DeleteDeviceHandler interface {
	Handle(DeleteDeviceParams, interface{}) middleware.Responder
}

// NewDeleteDevice creates a new http.Handler for the delete device operation
func NewDeleteDevice(ctx *middleware.Context, handler DeleteDeviceHandler) *DeleteDevice {
	return &DeleteDevice{Context: ctx, Handler: handler}
}

/*DeleteDevice swagger:route DELETE /v1/devices device deleteDevice

删除设备

删除设备

*/
type DeleteDevice struct {
	Context *middleware.Context
	Handler DeleteDeviceHandler
}

func (o *DeleteDevice) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewDeleteDeviceParams()

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