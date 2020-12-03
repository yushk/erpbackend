// Code generated by go-swagger; DO NOT EDIT.

package config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// ModifyTransferAlarmConfigOKCode is the HTTP code returned for type ModifyTransferAlarmConfigOK
const ModifyTransferAlarmConfigOKCode int = 200

/*ModifyTransferAlarmConfigOK A successful response.

swagger:response modifyTransferAlarmConfigOK
*/
type ModifyTransferAlarmConfigOK struct {
}

// NewModifyTransferAlarmConfigOK creates ModifyTransferAlarmConfigOK with default headers values
func NewModifyTransferAlarmConfigOK() *ModifyTransferAlarmConfigOK {

	return &ModifyTransferAlarmConfigOK{}
}

// WriteResponse to the client
func (o *ModifyTransferAlarmConfigOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}
