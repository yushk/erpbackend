// Code generated by go-swagger; DO NOT EDIT.

package config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// UpdateAlarmConfigsOKCode is the HTTP code returned for type UpdateAlarmConfigsOK
const UpdateAlarmConfigsOKCode int = 200

/*UpdateAlarmConfigsOK A successful response.

swagger:response updateAlarmConfigsOK
*/
type UpdateAlarmConfigsOK struct {
}

// NewUpdateAlarmConfigsOK creates UpdateAlarmConfigsOK with default headers values
func NewUpdateAlarmConfigsOK() *UpdateAlarmConfigsOK {

	return &UpdateAlarmConfigsOK{}
}

// WriteResponse to the client
func (o *UpdateAlarmConfigsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}
