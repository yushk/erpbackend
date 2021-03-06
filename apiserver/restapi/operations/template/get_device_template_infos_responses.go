// Code generated by go-swagger; DO NOT EDIT.

package template

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	v1 "swagger/apiserver/v1"
)

// GetDeviceTemplateInfosOKCode is the HTTP code returned for type GetDeviceTemplateInfosOK
const GetDeviceTemplateInfosOKCode int = 200

/*GetDeviceTemplateInfosOK A successful response.

swagger:response getDeviceTemplateInfosOK
*/
type GetDeviceTemplateInfosOK struct {

	/*
	  In: Body
	*/
	Payload *v1.DeviceTemplates `json:"body,omitempty"`
}

// NewGetDeviceTemplateInfosOK creates GetDeviceTemplateInfosOK with default headers values
func NewGetDeviceTemplateInfosOK() *GetDeviceTemplateInfosOK {

	return &GetDeviceTemplateInfosOK{}
}

// WithPayload adds the payload to the get device template infos o k response
func (o *GetDeviceTemplateInfosOK) WithPayload(payload *v1.DeviceTemplates) *GetDeviceTemplateInfosOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get device template infos o k response
func (o *GetDeviceTemplateInfosOK) SetPayload(payload *v1.DeviceTemplates) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetDeviceTemplateInfosOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
