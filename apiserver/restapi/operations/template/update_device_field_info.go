// Code generated by go-swagger; DO NOT EDIT.

package template

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	v1 "swagger/apiserver/v1"
)

// UpdateDeviceFieldInfoHandlerFunc turns a function with the right signature into a update device field info handler
type UpdateDeviceFieldInfoHandlerFunc func(UpdateDeviceFieldInfoParams, *v1.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn UpdateDeviceFieldInfoHandlerFunc) Handle(params UpdateDeviceFieldInfoParams, principal *v1.Principal) middleware.Responder {
	return fn(params, principal)
}

// UpdateDeviceFieldInfoHandler interface for that can handle valid update device field info params
type UpdateDeviceFieldInfoHandler interface {
	Handle(UpdateDeviceFieldInfoParams, *v1.Principal) middleware.Responder
}

// NewUpdateDeviceFieldInfo creates a new http.Handler for the update device field info operation
func NewUpdateDeviceFieldInfo(ctx *middleware.Context, handler UpdateDeviceFieldInfoHandler) *UpdateDeviceFieldInfo {
	return &UpdateDeviceFieldInfo{Context: ctx, Handler: handler}
}

/*UpdateDeviceFieldInfo swagger:route PUT /v1/devices/templates/fields template updateDeviceFieldInfo

修改设备属性信息

修改设备属性信息

*/
type UpdateDeviceFieldInfo struct {
	Context *middleware.Context
	Handler UpdateDeviceFieldInfoHandler
}

func (o *UpdateDeviceFieldInfo) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewUpdateDeviceFieldInfoParams()

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

// UpdateDeviceFieldInfoBody update device field info body
//
// swagger:model UpdateDeviceFieldInfoBody
type UpdateDeviceFieldInfoBody struct {

	// 设备种类ID
	DeviceProfileID string `json:"deviceProfileId,omitempty"`

	v1.FieldInfo
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *UpdateDeviceFieldInfoBody) UnmarshalJSON(raw []byte) error {
	// UpdateDeviceFieldInfoParamsBodyAO0
	var dataUpdateDeviceFieldInfoParamsBodyAO0 struct {
		DeviceProfileID string `json:"deviceProfileId,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataUpdateDeviceFieldInfoParamsBodyAO0); err != nil {
		return err
	}

	o.DeviceProfileID = dataUpdateDeviceFieldInfoParamsBodyAO0.DeviceProfileID

	// UpdateDeviceFieldInfoParamsBodyAO1
	var updateDeviceFieldInfoParamsBodyAO1 v1.FieldInfo
	if err := swag.ReadJSON(raw, &updateDeviceFieldInfoParamsBodyAO1); err != nil {
		return err
	}
	o.FieldInfo = updateDeviceFieldInfoParamsBodyAO1

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o UpdateDeviceFieldInfoBody) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	var dataUpdateDeviceFieldInfoParamsBodyAO0 struct {
		DeviceProfileID string `json:"deviceProfileId,omitempty"`
	}

	dataUpdateDeviceFieldInfoParamsBodyAO0.DeviceProfileID = o.DeviceProfileID

	jsonDataUpdateDeviceFieldInfoParamsBodyAO0, errUpdateDeviceFieldInfoParamsBodyAO0 := swag.WriteJSON(dataUpdateDeviceFieldInfoParamsBodyAO0)
	if errUpdateDeviceFieldInfoParamsBodyAO0 != nil {
		return nil, errUpdateDeviceFieldInfoParamsBodyAO0
	}
	_parts = append(_parts, jsonDataUpdateDeviceFieldInfoParamsBodyAO0)

	updateDeviceFieldInfoParamsBodyAO1, err := swag.WriteJSON(o.FieldInfo)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, updateDeviceFieldInfoParamsBodyAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this update device field info body
func (o *UpdateDeviceFieldInfoBody) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with v1.FieldInfo
	if err := o.FieldInfo.Validate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (o *UpdateDeviceFieldInfoBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *UpdateDeviceFieldInfoBody) UnmarshalBinary(b []byte) error {
	var res UpdateDeviceFieldInfoBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
