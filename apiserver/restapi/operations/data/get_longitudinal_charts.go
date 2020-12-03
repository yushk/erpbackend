// Code generated by go-swagger; DO NOT EDIT.

package data

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// GetLongitudinalChartsHandlerFunc turns a function with the right signature into a get longitudinal charts handler
type GetLongitudinalChartsHandlerFunc func(GetLongitudinalChartsParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn GetLongitudinalChartsHandlerFunc) Handle(params GetLongitudinalChartsParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// GetLongitudinalChartsHandler interface for that can handle valid get longitudinal charts params
type GetLongitudinalChartsHandler interface {
	Handle(GetLongitudinalChartsParams, interface{}) middleware.Responder
}

// NewGetLongitudinalCharts creates a new http.Handler for the get longitudinal charts operation
func NewGetLongitudinalCharts(ctx *middleware.Context, handler GetLongitudinalChartsHandler) *GetLongitudinalCharts {
	return &GetLongitudinalCharts{Context: ctx, Handler: handler}
}

/*GetLongitudinalCharts swagger:route GET /v1/devices/charts/longitudinal data getLongitudinalCharts

获取纵向比较曲线图

获取纵向比较曲线图

*/
type GetLongitudinalCharts struct {
	Context *middleware.Context
	Handler GetLongitudinalChartsHandler
}

func (o *GetLongitudinalCharts) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetLongitudinalChartsParams()

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