// Code generated by go-swagger; DO NOT EDIT.

package user

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// ChangeCurrentUserPasswordOKCode is the HTTP code returned for type ChangeCurrentUserPasswordOK
const ChangeCurrentUserPasswordOKCode int = 200

/*ChangeCurrentUserPasswordOK successful operation

swagger:response changeCurrentUserPasswordOK
*/
type ChangeCurrentUserPasswordOK struct {
}

// NewChangeCurrentUserPasswordOK creates ChangeCurrentUserPasswordOK with default headers values
func NewChangeCurrentUserPasswordOK() *ChangeCurrentUserPasswordOK {

	return &ChangeCurrentUserPasswordOK{}
}

// WriteResponse to the client
func (o *ChangeCurrentUserPasswordOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}
