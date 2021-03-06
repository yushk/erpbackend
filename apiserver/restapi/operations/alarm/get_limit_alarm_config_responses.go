// Code generated by go-swagger; DO NOT EDIT.

package alarm

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	v1 "swagger/apiserver/v1"
)

// GetLimitAlarmConfigOKCode is the HTTP code returned for type GetLimitAlarmConfigOK
const GetLimitAlarmConfigOKCode int = 200

/*GetLimitAlarmConfigOK A successful response.

swagger:response getLimitAlarmConfigOK
*/
type GetLimitAlarmConfigOK struct {

	/*
	  In: Body
	*/
	Payload *v1.LimitAlarmConfig `json:"body,omitempty"`
}

// NewGetLimitAlarmConfigOK creates GetLimitAlarmConfigOK with default headers values
func NewGetLimitAlarmConfigOK() *GetLimitAlarmConfigOK {

	return &GetLimitAlarmConfigOK{}
}

// WithPayload adds the payload to the get limit alarm config o k response
func (o *GetLimitAlarmConfigOK) WithPayload(payload *v1.LimitAlarmConfig) *GetLimitAlarmConfigOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get limit alarm config o k response
func (o *GetLimitAlarmConfigOK) SetPayload(payload *v1.LimitAlarmConfig) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetLimitAlarmConfigOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
