// Code generated by go-swagger; DO NOT EDIT.

package oauth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	v1 "swagger/apiserver/v1"
)

// RefreshTokenOKCode is the HTTP code returned for type RefreshTokenOK
const RefreshTokenOKCode int = 200

/*RefreshTokenOK A successful response.

swagger:response refreshTokenOK
*/
type RefreshTokenOK struct {

	/*
	  In: Body
	*/
	Payload *v1.Token `json:"body,omitempty"`
}

// NewRefreshTokenOK creates RefreshTokenOK with default headers values
func NewRefreshTokenOK() *RefreshTokenOK {

	return &RefreshTokenOK{}
}

// WithPayload adds the payload to the refresh token o k response
func (o *RefreshTokenOK) WithPayload(payload *v1.Token) *RefreshTokenOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the refresh token o k response
func (o *RefreshTokenOK) SetPayload(payload *v1.Token) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *RefreshTokenOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
