// Code generated by go-swagger; DO NOT EDIT.

package config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"
	v1 "swagger/apiserver/v1"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// UpdateCleaningConfigsHandlerFunc turns a function with the right signature into a update cleaning configs handler
type UpdateCleaningConfigsHandlerFunc func(UpdateCleaningConfigsParams, *v1.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn UpdateCleaningConfigsHandlerFunc) Handle(params UpdateCleaningConfigsParams, principal *v1.Principal) middleware.Responder {
	return fn(params, principal)
}

// UpdateCleaningConfigsHandler interface for that can handle valid update cleaning configs params
type UpdateCleaningConfigsHandler interface {
	Handle(UpdateCleaningConfigsParams, *v1.Principal) middleware.Responder
}

// NewUpdateCleaningConfigs creates a new http.Handler for the update cleaning configs operation
func NewUpdateCleaningConfigs(ctx *middleware.Context, handler UpdateCleaningConfigsHandler) *UpdateCleaningConfigs {
	return &UpdateCleaningConfigs{Context: ctx, Handler: handler}
}

/*UpdateCleaningConfigs swagger:route PUT /v1/configs/cleaning config updateCleaningConfigs

修改系统配置-数据清洗信息

修改系统配置-数据清洗信息

*/
type UpdateCleaningConfigs struct {
	Context *middleware.Context
	Handler UpdateCleaningConfigsHandler
}

func (o *UpdateCleaningConfigs) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewUpdateCleaningConfigsParams()

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

// UpdateCleaningConfigsBody update cleaning configs body
//
// swagger:model UpdateCleaningConfigsBody
type UpdateCleaningConfigsBody struct {

	// 配置ID
	ConfigID string `json:"configId,omitempty"`

	// rule
	Rule *v1.CleaningRules `json:"rule,omitempty"`
}

// Validate validates this update cleaning configs body
func (o *UpdateCleaningConfigsBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateRule(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *UpdateCleaningConfigsBody) validateRule(formats strfmt.Registry) error {

	if swag.IsZero(o.Rule) { // not required
		return nil
	}

	if o.Rule != nil {
		if err := o.Rule.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "rule")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *UpdateCleaningConfigsBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *UpdateCleaningConfigsBody) UnmarshalBinary(b []byte) error {
	var res UpdateCleaningConfigsBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
