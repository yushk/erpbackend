// Code generated by go-swagger; DO NOT EDIT.

package system

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// PingOKCode is the HTTP code returned for type PingOK
const PingOKCode int = 200

/*PingOK A successful response.

swagger:response pingOK
*/
type PingOK struct {
}

// NewPingOK creates PingOK with default headers values
func NewPingOK() *PingOK {

	return &PingOK{}
}

// WriteResponse to the client
func (o *PingOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}
