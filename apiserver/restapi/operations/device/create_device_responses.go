// Code generated by go-swagger; DO NOT EDIT.

package device

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// CreateDeviceOKCode is the HTTP code returned for type CreateDeviceOK
const CreateDeviceOKCode int = 200

/*CreateDeviceOK A successful response.

swagger:response createDeviceOK
*/
type CreateDeviceOK struct {
}

// NewCreateDeviceOK creates CreateDeviceOK with default headers values
func NewCreateDeviceOK() *CreateDeviceOK {

	return &CreateDeviceOK{}
}

// WriteResponse to the client
func (o *CreateDeviceOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}
