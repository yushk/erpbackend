// Code generated by go-swagger; DO NOT EDIT.

package user

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"
	v1 "swagger/apiserver/v1"

	"github.com/go-openapi/runtime"
)

// DeleteUserOKCode is the HTTP code returned for type DeleteUserOK
const DeleteUserOKCode int = 200

/*DeleteUserOK A successful response.

swagger:response deleteUserOK
*/
type DeleteUserOK struct {

	/*
	  In: Body
	*/
	Payload *v1.User `json:"body,omitempty"`
}

// NewDeleteUserOK creates DeleteUserOK with default headers values
func NewDeleteUserOK() *DeleteUserOK {

	return &DeleteUserOK{}
}

// WithPayload adds the payload to the delete user o k response
func (o *DeleteUserOK) WithPayload(payload *v1.User) *DeleteUserOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete user o k response
func (o *DeleteUserOK) SetPayload(payload *v1.User) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteUserOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
