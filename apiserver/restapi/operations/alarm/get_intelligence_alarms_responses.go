// Code generated by go-swagger; DO NOT EDIT.

package alarm

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	v1 "swagger/apiserver/v1"
)

// GetIntelligenceAlarmsOKCode is the HTTP code returned for type GetIntelligenceAlarmsOK
const GetIntelligenceAlarmsOKCode int = 200

/*GetIntelligenceAlarmsOK A successful response.

swagger:response getIntelligenceAlarmsOK
*/
type GetIntelligenceAlarmsOK struct {

	/*
	  In: Body
	*/
	Payload *v1.IntelligenceAlarms `json:"body,omitempty"`
}

// NewGetIntelligenceAlarmsOK creates GetIntelligenceAlarmsOK with default headers values
func NewGetIntelligenceAlarmsOK() *GetIntelligenceAlarmsOK {

	return &GetIntelligenceAlarmsOK{}
}

// WithPayload adds the payload to the get intelligence alarms o k response
func (o *GetIntelligenceAlarmsOK) WithPayload(payload *v1.IntelligenceAlarms) *GetIntelligenceAlarmsOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get intelligence alarms o k response
func (o *GetIntelligenceAlarmsOK) SetPayload(payload *v1.IntelligenceAlarms) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetIntelligenceAlarmsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
