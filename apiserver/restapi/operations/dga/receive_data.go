// Code generated by go-swagger; DO NOT EDIT.

package dga

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"
	v1 "swagger/apiserver/v1"

	"github.com/go-openapi/runtime/middleware"
)

// ReceiveDataHandlerFunc turns a function with the right signature into a receive data handler
type ReceiveDataHandlerFunc func(ReceiveDataParams, *v1.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn ReceiveDataHandlerFunc) Handle(params ReceiveDataParams, principal *v1.Principal) middleware.Responder {
	return fn(params, principal)
}

// ReceiveDataHandler interface for that can handle valid receive data params
type ReceiveDataHandler interface {
	Handle(ReceiveDataParams, *v1.Principal) middleware.Responder
}

// NewReceiveData creates a new http.Handler for the receive data operation
func NewReceiveData(ctx *middleware.Context, handler ReceiveDataHandler) *ReceiveData {
	return &ReceiveData{Context: ctx, Handler: handler}
}

/*ReceiveData swagger:route POST /v1/dga/receive dga receiveData

接受设备数据(油中溶解)

接受油中溶解设备数据

*/
type ReceiveData struct {
	Context *middleware.Context
	Handler ReceiveDataHandler
}

func (o *ReceiveData) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewReceiveDataParams()

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
