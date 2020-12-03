// Code generated by go-swagger; DO NOT EDIT.

package config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
)

// NewGetAlarmConfigsParams creates a new GetAlarmConfigsParams object
// no default values defined in spec.
func NewGetAlarmConfigsParams() GetAlarmConfigsParams {

	return GetAlarmConfigsParams{}
}

// GetAlarmConfigsParams contains all the bound params for the get alarm configs operation
// typically these are obtained from a http.Request
//
// swagger:parameters GetAlarmConfigs
type GetAlarmConfigsParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*设备类型
	  In: query
	*/
	DeviceProfile *string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewGetAlarmConfigsParams() beforehand.
func (o *GetAlarmConfigsParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	qDeviceProfile, qhkDeviceProfile, _ := qs.GetOK("deviceProfile")
	if err := o.bindDeviceProfile(qDeviceProfile, qhkDeviceProfile, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindDeviceProfile binds and validates parameter DeviceProfile from query.
func (o *GetAlarmConfigsParams) bindDeviceProfile(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false
	if raw == "" { // empty values pass all other validations
		return nil
	}

	o.DeviceProfile = &raw

	return nil
}
