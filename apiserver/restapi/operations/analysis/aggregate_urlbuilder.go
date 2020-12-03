// Code generated by go-swagger; DO NOT EDIT.

package analysis

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"errors"
	"net/url"
	golangswaggerpaths "path"
	"strings"

	"github.com/go-openapi/swag"
)

// AggregateURL generates an URL for the aggregate operation
type AggregateURL struct {
	Operation string

	Limit *int64
	Q     *string
	Skip  *int64

	_basePath string
	// avoid unkeyed usage
	_ struct{}
}

// WithBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *AggregateURL) WithBasePath(bp string) *AggregateURL {
	o.SetBasePath(bp)
	return o
}

// SetBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *AggregateURL) SetBasePath(bp string) {
	o._basePath = bp
}

// Build a url path and query string
func (o *AggregateURL) Build() (*url.URL, error) {
	var _result url.URL

	var _path = "/v1/analysis/aggregate/{operation}"

	operation := o.Operation
	if operation != "" {
		_path = strings.Replace(_path, "{operation}", operation, -1)
	} else {
		return nil, errors.New("operation is required on AggregateURL")
	}

	_basePath := o._basePath
	if _basePath == "" {
		_basePath = "/api"
	}
	_result.Path = golangswaggerpaths.Join(_basePath, _path)

	qs := make(url.Values)

	var limitQ string
	if o.Limit != nil {
		limitQ = swag.FormatInt64(*o.Limit)
	}
	if limitQ != "" {
		qs.Set("limit", limitQ)
	}

	var qQ string
	if o.Q != nil {
		qQ = *o.Q
	}
	if qQ != "" {
		qs.Set("q", qQ)
	}

	var skipQ string
	if o.Skip != nil {
		skipQ = swag.FormatInt64(*o.Skip)
	}
	if skipQ != "" {
		qs.Set("skip", skipQ)
	}

	_result.RawQuery = qs.Encode()

	return &_result, nil
}

// Must is a helper function to panic when the url builder returns an error
func (o *AggregateURL) Must(u *url.URL, err error) *url.URL {
	if err != nil {
		panic(err)
	}
	if u == nil {
		panic("url can't be nil")
	}
	return u
}

// String returns the string representation of the path with query string
func (o *AggregateURL) String() string {
	return o.Must(o.Build()).String()
}

// BuildFull builds a full url with scheme, host, path and query string
func (o *AggregateURL) BuildFull(scheme, host string) (*url.URL, error) {
	if scheme == "" {
		return nil, errors.New("scheme is required for a full url on AggregateURL")
	}
	if host == "" {
		return nil, errors.New("host is required for a full url on AggregateURL")
	}

	base, err := o.Build()
	if err != nil {
		return nil, err
	}

	base.Scheme = scheme
	base.Host = host
	return base, nil
}

// StringFull returns the string representation of a complete url
func (o *AggregateURL) StringFull(scheme, host string) string {
	return o.Must(o.BuildFull(scheme, host)).String()
}
