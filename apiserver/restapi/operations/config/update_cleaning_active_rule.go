// Code generated by go-swagger; DO NOT EDIT.

package config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"
	v1 "swagger/apiserver/v1"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// UpdateCleaningActiveRuleHandlerFunc turns a function with the right signature into a update cleaning active rule handler
type UpdateCleaningActiveRuleHandlerFunc func(UpdateCleaningActiveRuleParams, *v1.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn UpdateCleaningActiveRuleHandlerFunc) Handle(params UpdateCleaningActiveRuleParams, principal *v1.Principal) middleware.Responder {
	return fn(params, principal)
}

// UpdateCleaningActiveRuleHandler interface for that can handle valid update cleaning active rule params
type UpdateCleaningActiveRuleHandler interface {
	Handle(UpdateCleaningActiveRuleParams, *v1.Principal) middleware.Responder
}

// NewUpdateCleaningActiveRule creates a new http.Handler for the update cleaning active rule operation
func NewUpdateCleaningActiveRule(ctx *middleware.Context, handler UpdateCleaningActiveRuleHandler) *UpdateCleaningActiveRule {
	return &UpdateCleaningActiveRule{Context: ctx, Handler: handler}
}

/*UpdateCleaningActiveRule swagger:route PUT /v1/configs/cleaning/active config updateCleaningActiveRule

修改激活规则与初始值计算周期

修改激活规则与初始值计算周期

*/
type UpdateCleaningActiveRule struct {
	Context *middleware.Context
	Handler UpdateCleaningActiveRuleHandler
}

func (o *UpdateCleaningActiveRule) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewUpdateCleaningActiveRuleParams()

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

// UpdateCleaningActiveRuleBody update cleaning active rule body
//
// swagger:model UpdateCleaningActiveRuleBody
type UpdateCleaningActiveRuleBody struct {

	// 激活规则ID
	ActiveRule string `json:"activeRule,omitempty"`

	// 配置ID
	ConfigID string `json:"configId,omitempty"`

	// 初始值计算周期
	InitValueCycle int64 `json:"initValueCycle,omitempty"`
}

// Validate validates this update cleaning active rule body
func (o *UpdateCleaningActiveRuleBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *UpdateCleaningActiveRuleBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *UpdateCleaningActiveRuleBody) UnmarshalBinary(b []byte) error {
	var res UpdateCleaningActiveRuleBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
