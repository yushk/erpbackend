// Code generated by go-swagger; DO NOT EDIT.

package user

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	v1 "swagger/apiserver/v1"
)

// CreateUserOKCode is the HTTP code returned for type CreateUserOK
const CreateUserOKCode int = 200

/*CreateUserOK A successful response.

swagger:response createUserOK
*/
type CreateUserOK struct {

	/*
	  In: Body
	*/
	Payload *v1.User `json:"body,omitempty"`
}

// NewCreateUserOK creates CreateUserOK with default headers values
func NewCreateUserOK() *CreateUserOK {

	return &CreateUserOK{}
}

// WithPayload adds the payload to the create user o k response
func (o *CreateUserOK) WithPayload(payload *v1.User) *CreateUserOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create user o k response
func (o *CreateUserOK) SetPayload(payload *v1.User) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateUserOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}