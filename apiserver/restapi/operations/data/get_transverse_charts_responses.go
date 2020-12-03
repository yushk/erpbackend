// Code generated by go-swagger; DO NOT EDIT.

package data

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	v1 "swagger/apiserver/v1"
)

// GetTransverseChartsOKCode is the HTTP code returned for type GetTransverseChartsOK
const GetTransverseChartsOKCode int = 200

/*GetTransverseChartsOK A successful response.

swagger:response getTransverseChartsOK
*/
type GetTransverseChartsOK struct {

	/*
	  In: Body
	*/
	Payload *v1.TransverseValuesInfo `json:"body,omitempty"`
}

// NewGetTransverseChartsOK creates GetTransverseChartsOK with default headers values
func NewGetTransverseChartsOK() *GetTransverseChartsOK {

	return &GetTransverseChartsOK{}
}

// WithPayload adds the payload to the get transverse charts o k response
func (o *GetTransverseChartsOK) WithPayload(payload *v1.TransverseValuesInfo) *GetTransverseChartsOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get transverse charts o k response
func (o *GetTransverseChartsOK) SetPayload(payload *v1.TransverseValuesInfo) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetTransverseChartsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}