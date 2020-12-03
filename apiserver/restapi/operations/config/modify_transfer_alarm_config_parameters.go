// Code generated by go-swagger; DO NOT EDIT.

package config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"io"
	"net/http"
	v1 "swagger/apiserver/v1"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
)

// NewModifyTransferAlarmConfigParams creates a new ModifyTransferAlarmConfigParams object
// no default values defined in spec.
func NewModifyTransferAlarmConfigParams() ModifyTransferAlarmConfigParams {

	return ModifyTransferAlarmConfigParams{}
}

// ModifyTransferAlarmConfigParams contains all the bound params for the modify transfer alarm config operation
// typically these are obtained from a http.Request
//
// swagger:parameters ModifyTransferAlarmConfig
type ModifyTransferAlarmConfigParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*请求参数
	  Required: true
	  In: body
	*/
	Body *v1.TransferAlarmConfig
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewModifyTransferAlarmConfigParams() beforehand.
func (o *ModifyTransferAlarmConfigParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	if runtime.HasBody(r) {
		defer r.Body.Close()
		var body v1.TransferAlarmConfig
		if err := route.Consumer.Consume(r.Body, &body); err != nil {
			if err == io.EOF {
				res = append(res, errors.Required("body", "body", ""))
			} else {
				res = append(res, errors.NewParseError("body", "body", "", err))
			}
		} else {
			// validate body object
			if err := body.Validate(route.Formats); err != nil {
				res = append(res, err)
			}

			if len(res) == 0 {
				o.Body = &body
			}
		}
	} else {
		res = append(res, errors.Required("body", "body", ""))
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
