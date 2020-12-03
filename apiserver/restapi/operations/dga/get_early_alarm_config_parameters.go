// Code generated by go-swagger; DO NOT EDIT.

package dga

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
)

// NewGetEarlyAlarmConfigParams creates a new GetEarlyAlarmConfigParams object
// no default values defined in spec.
func NewGetEarlyAlarmConfigParams() GetEarlyAlarmConfigParams {

	return GetEarlyAlarmConfigParams{}
}

// GetEarlyAlarmConfigParams contains all the bound params for the get early alarm config operation
// typically these are obtained from a http.Request
//
// swagger:parameters GetEarlyAlarmConfig
type GetEarlyAlarmConfigParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*设备类型
	  In: query
	*/
	DeviceType *string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewGetEarlyAlarmConfigParams() beforehand.
func (o *GetEarlyAlarmConfigParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	qDeviceType, qhkDeviceType, _ := qs.GetOK("deviceType")
	if err := o.bindDeviceType(qDeviceType, qhkDeviceType, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindDeviceType binds and validates parameter DeviceType from query.
func (o *GetEarlyAlarmConfigParams) bindDeviceType(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false
	if raw == "" { // empty values pass all other validations
		return nil
	}

	o.DeviceType = &raw

	return nil
}