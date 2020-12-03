// Code generated by go-swagger; DO NOT EDIT.

package device

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// UploadDevicesOKCode is the HTTP code returned for type UploadDevicesOK
const UploadDevicesOKCode int = 200

/*UploadDevicesOK A successful response.

swagger:response uploadDevicesOK
*/
type UploadDevicesOK struct {
}

// NewUploadDevicesOK creates UploadDevicesOK with default headers values
func NewUploadDevicesOK() *UploadDevicesOK {

	return &UploadDevicesOK{}
}

// WriteResponse to the client
func (o *UploadDevicesOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}