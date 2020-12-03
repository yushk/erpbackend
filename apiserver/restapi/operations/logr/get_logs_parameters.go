// Code generated by go-swagger; DO NOT EDIT.

package logr

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewGetLogsParams creates a new GetLogsParams object
// no default values defined in spec.
func NewGetLogsParams() GetLogsParams {

	return GetLogsParams{}
}

// GetLogsParams contains all the bound params for the get logs operation
// typically these are obtained from a http.Request
//
// swagger:parameters GetLogs
type GetLogsParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*每页列表的项目数
	  In: query
	*/
	Limit *int64
	/*搜索列表条件
	  In: query
	*/
	Q *string
	/*跳过列表的项目数
	  In: query
	*/
	Skip *int64
	/*排序
	  In: query
	*/
	Sort *string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewGetLogsParams() beforehand.
func (o *GetLogsParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	qLimit, qhkLimit, _ := qs.GetOK("limit")
	if err := o.bindLimit(qLimit, qhkLimit, route.Formats); err != nil {
		res = append(res, err)
	}

	qQ, qhkQ, _ := qs.GetOK("q")
	if err := o.bindQ(qQ, qhkQ, route.Formats); err != nil {
		res = append(res, err)
	}

	qSkip, qhkSkip, _ := qs.GetOK("skip")
	if err := o.bindSkip(qSkip, qhkSkip, route.Formats); err != nil {
		res = append(res, err)
	}

	qSort, qhkSort, _ := qs.GetOK("sort")
	if err := o.bindSort(qSort, qhkSort, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindLimit binds and validates parameter Limit from query.
func (o *GetLogsParams) bindLimit(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false
	if raw == "" { // empty values pass all other validations
		return nil
	}

	value, err := swag.ConvertInt64(raw)
	if err != nil {
		return errors.InvalidType("limit", "query", "int64", raw)
	}
	o.Limit = &value

	return nil
}

// bindQ binds and validates parameter Q from query.
func (o *GetLogsParams) bindQ(rawData []string, hasKey bool, formats strfmt.Registry) error {
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

// bindSkip binds and validates parameter Skip from query.
func (o *GetLogsParams) bindSkip(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false
	if raw == "" { // empty values pass all other validations
		return nil
	}

	value, err := swag.ConvertInt64(raw)
	if err != nil {
		return errors.InvalidType("skip", "query", "int64", raw)
	}
	o.Skip = &value

	return nil
}

// bindSort binds and validates parameter Sort from query.
func (o *GetLogsParams) bindSort(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false
	if raw == "" { // empty values pass all other validations
		return nil
	}

	o.Sort = &raw

	return nil
}
