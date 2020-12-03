// Code generated by go-swagger; DO NOT EDIT.

package dga

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// ReceiveDataOKCode is the HTTP code returned for type ReceiveDataOK
const ReceiveDataOKCode int = 200

/*ReceiveDataOK A successful response.

swagger:response receiveDataOK
*/
type ReceiveDataOK struct {
}

// NewReceiveDataOK creates ReceiveDataOK with default headers values
func NewReceiveDataOK() *ReceiveDataOK {

	return &ReceiveDataOK{}
}

// WriteResponse to the client
func (o *ReceiveDataOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}