// Code generated by go-swagger; DO NOT EDIT.

package alarm

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// ConfirmLimitAlarmOKCode is the HTTP code returned for type ConfirmLimitAlarmOK
const ConfirmLimitAlarmOKCode int = 200

/*ConfirmLimitAlarmOK A successful response.

swagger:response confirmLimitAlarmOK
*/
type ConfirmLimitAlarmOK struct {
}

// NewConfirmLimitAlarmOK creates ConfirmLimitAlarmOK with default headers values
func NewConfirmLimitAlarmOK() *ConfirmLimitAlarmOK {

	return &ConfirmLimitAlarmOK{}
}

// WriteResponse to the client
func (o *ConfirmLimitAlarmOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}
