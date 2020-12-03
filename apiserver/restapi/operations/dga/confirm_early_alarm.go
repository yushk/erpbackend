// Code generated by go-swagger; DO NOT EDIT.

package dga

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ConfirmEarlyAlarmHandlerFunc turns a function with the right signature into a confirm early alarm handler
type ConfirmEarlyAlarmHandlerFunc func(ConfirmEarlyAlarmParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn ConfirmEarlyAlarmHandlerFunc) Handle(params ConfirmEarlyAlarmParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// ConfirmEarlyAlarmHandler interface for that can handle valid confirm early alarm params
type ConfirmEarlyAlarmHandler interface {
	Handle(ConfirmEarlyAlarmParams, interface{}) middleware.Responder
}

// NewConfirmEarlyAlarm creates a new http.Handler for the confirm early alarm operation
func NewConfirmEarlyAlarm(ctx *middleware.Context, handler ConfirmEarlyAlarmHandler) *ConfirmEarlyAlarm {
	return &ConfirmEarlyAlarm{Context: ctx, Handler: handler}
}

/*ConfirmEarlyAlarm swagger:route PUT /v1/alarms/early/confirm dga confirmEarlyAlarm

确认获取油中溶解预警

确认获取油中溶解预警

*/
type ConfirmEarlyAlarm struct {
	Context *middleware.Context
	Handler ConfirmEarlyAlarmHandler
}

func (o *ConfirmEarlyAlarm) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewConfirmEarlyAlarmParams()

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

// ConfirmEarlyAlarmBody confirm early alarm body
//
// swagger:model ConfirmEarlyAlarmBody
type ConfirmEarlyAlarmBody struct {

	// 超限告警ID
	UUID string `json:"uuid,omitempty"`
}

// Validate validates this confirm early alarm body
func (o *ConfirmEarlyAlarmBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *ConfirmEarlyAlarmBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *ConfirmEarlyAlarmBody) UnmarshalBinary(b []byte) error {
	var res ConfirmEarlyAlarmBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}