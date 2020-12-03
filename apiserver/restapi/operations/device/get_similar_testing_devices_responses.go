// Code generated by go-swagger; DO NOT EDIT.

package device

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	v1 "swagger/apiserver/v1"
)

// GetSimilarTestingDevicesOKCode is the HTTP code returned for type GetSimilarTestingDevicesOK
const GetSimilarTestingDevicesOKCode int = 200

/*GetSimilarTestingDevicesOK A successful response.

swagger:response getSimilarTestingDevicesOK
*/
type GetSimilarTestingDevicesOK struct {

	/*
	  In: Body
	*/
	Payload *v1.SimilarTestingDevices `json:"body,omitempty"`
}

// NewGetSimilarTestingDevicesOK creates GetSimilarTestingDevicesOK with default headers values
func NewGetSimilarTestingDevicesOK() *GetSimilarTestingDevicesOK {

	return &GetSimilarTestingDevicesOK{}
}

// WithPayload adds the payload to the get similar testing devices o k response
func (o *GetSimilarTestingDevicesOK) WithPayload(payload *v1.SimilarTestingDevices) *GetSimilarTestingDevicesOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get similar testing devices o k response
func (o *GetSimilarTestingDevicesOK) SetPayload(payload *v1.SimilarTestingDevices) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetSimilarTestingDevicesOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
