// Code generated by go-swagger; DO NOT EDIT.

package alarm

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// ConfirmTransferAlarmOKCode is the HTTP code returned for type ConfirmTransferAlarmOK
const ConfirmTransferAlarmOKCode int = 200

/*ConfirmTransferAlarmOK A successful response.

swagger:response confirmTransferAlarmOK
*/
type ConfirmTransferAlarmOK struct {
}

// NewConfirmTransferAlarmOK creates ConfirmTransferAlarmOK with default headers values
func NewConfirmTransferAlarmOK() *ConfirmTransferAlarmOK {

	return &ConfirmTransferAlarmOK{}
}

// WriteResponse to the client
func (o *ConfirmTransferAlarmOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}
