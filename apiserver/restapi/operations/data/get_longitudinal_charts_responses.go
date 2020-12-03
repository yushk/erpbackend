// Code generated by go-swagger; DO NOT EDIT.

package data

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	v1 "swagger/apiserver/v1"
)

// GetLongitudinalChartsOKCode is the HTTP code returned for type GetLongitudinalChartsOK
const GetLongitudinalChartsOKCode int = 200

/*GetLongitudinalChartsOK A successful response.

swagger:response getLongitudinalChartsOK
*/
type GetLongitudinalChartsOK struct {

	/*
	  In: Body
	*/
	Payload *v1.LongitudinalValuesInfo `json:"body,omitempty"`
}

// NewGetLongitudinalChartsOK creates GetLongitudinalChartsOK with default headers values
func NewGetLongitudinalChartsOK() *GetLongitudinalChartsOK {

	return &GetLongitudinalChartsOK{}
}

// WithPayload adds the payload to the get longitudinal charts o k response
func (o *GetLongitudinalChartsOK) WithPayload(payload *v1.LongitudinalValuesInfo) *GetLongitudinalChartsOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get longitudinal charts o k response
func (o *GetLongitudinalChartsOK) SetPayload(payload *v1.LongitudinalValuesInfo) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetLongitudinalChartsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}