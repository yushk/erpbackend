// Code generated by go-swagger; DO NOT EDIT.

package alarm

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ConfirmLimitAlarmHandlerFunc turns a function with the right signature into a confirm limit alarm handler
type ConfirmLimitAlarmHandlerFunc func(ConfirmLimitAlarmParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn ConfirmLimitAlarmHandlerFunc) Handle(params ConfirmLimitAlarmParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// ConfirmLimitAlarmHandler interface for that can handle valid confirm limit alarm params
type ConfirmLimitAlarmHandler interface {
	Handle(ConfirmLimitAlarmParams, interface{}) middleware.Responder
}

// NewConfirmLimitAlarm creates a new http.Handler for the confirm limit alarm operation
func NewConfirmLimitAlarm(ctx *middleware.Context, handler ConfirmLimitAlarmHandler) *ConfirmLimitAlarm {
	return &ConfirmLimitAlarm{Context: ctx, Handler: handler}
}

/*ConfirmLimitAlarm swagger:route PUT /v1/alarms/limit/confirm alarm confirmLimitAlarm

确认超限告警

确认超限告警

*/
type ConfirmLimitAlarm struct {
	Context *middleware.Context
	Handler ConfirmLimitAlarmHandler
}

func (o *ConfirmLimitAlarm) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewConfirmLimitAlarmParams()

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

// ConfirmLimitAlarmBody confirm limit alarm body
//
// swagger:model ConfirmLimitAlarmBody
type ConfirmLimitAlarmBody struct {

	// 超限告警ID
	UUID string `json:"uuid,omitempty"`
}

// Validate validates this confirm limit alarm body
func (o *ConfirmLimitAlarmBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *ConfirmLimitAlarmBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *ConfirmLimitAlarmBody) UnmarshalBinary(b []byte) error {
	var res ConfirmLimitAlarmBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
