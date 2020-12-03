// Code generated by go-swagger; DO NOT EDIT.

package device

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	v1 "swagger/apiserver/v1"
)

// GetDevicesOKCode is the HTTP code returned for type GetDevicesOK
const GetDevicesOKCode int = 200

/*GetDevicesOK A successful response.

swagger:response getDevicesOK
*/
type GetDevicesOK struct {

	/*
	  In: Body
	*/
	Payload *v1.Substations `json:"body,omitempty"`
}

// NewGetDevicesOK creates GetDevicesOK with default headers values
func NewGetDevicesOK() *GetDevicesOK {

	return &GetDevicesOK{}
}

// WithPayload adds the payload to the get devices o k response
func (o *GetDevicesOK) WithPayload(payload *v1.Substations) *GetDevicesOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get devices o k response
func (o *GetDevicesOK) SetPayload(payload *v1.Substations) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetDevicesOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}