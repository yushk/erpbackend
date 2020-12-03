// Code generated by go-swagger; DO NOT EDIT.

package alarm

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	v1 "swagger/apiserver/v1"
)

// GetHistoryLimitAlarmsOKCode is the HTTP code returned for type GetHistoryLimitAlarmsOK
const GetHistoryLimitAlarmsOKCode int = 200

/*GetHistoryLimitAlarmsOK A successful response.

swagger:response getHistoryLimitAlarmsOK
*/
type GetHistoryLimitAlarmsOK struct {

	/*
	  In: Body
	*/
	Payload *v1.Alarms `json:"body,omitempty"`
}

// NewGetHistoryLimitAlarmsOK creates GetHistoryLimitAlarmsOK with default headers values
func NewGetHistoryLimitAlarmsOK() *GetHistoryLimitAlarmsOK {

	return &GetHistoryLimitAlarmsOK{}
}

// WithPayload adds the payload to the get history limit alarms o k response
func (o *GetHistoryLimitAlarmsOK) WithPayload(payload *v1.Alarms) *GetHistoryLimitAlarmsOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get history limit alarms o k response
func (o *GetHistoryLimitAlarmsOK) SetPayload(payload *v1.Alarms) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetHistoryLimitAlarmsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
