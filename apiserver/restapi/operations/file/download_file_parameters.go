// Code generated by go-swagger; DO NOT EDIT.

package file

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
)

// NewDownloadFileParams creates a new DownloadFileParams object
// no default values defined in spec.
func NewDownloadFileParams() DownloadFileParams {

	return DownloadFileParams{}
}

// DownloadFileParams contains all the bound params for the download file operation
// typically these are obtained from a http.Request
//
// swagger:parameters DownloadFile
type DownloadFileParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*搜索条件
	  In: query
	*/
	Q *string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewDownloadFileParams() beforehand.
func (o *DownloadFileParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	qQ, qhkQ, _ := qs.GetOK("q")
	if err := o.bindQ(qQ, qhkQ, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindQ binds and validates parameter Q from query.
func (o *DownloadFileParams) bindQ(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false
	if raw == "" { // empty values pass all other validations
		return nil
	}

	o.Q = &raw

	return nil
}