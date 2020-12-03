// Code generated by go-swagger; DO NOT EDIT.

package config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// UpdateCleaningActiveRuleOKCode is the HTTP code returned for type UpdateCleaningActiveRuleOK
const UpdateCleaningActiveRuleOKCode int = 200

/*UpdateCleaningActiveRuleOK A successful response.

swagger:response updateCleaningActiveRuleOK
*/
type UpdateCleaningActiveRuleOK struct {
}

// NewUpdateCleaningActiveRuleOK creates UpdateCleaningActiveRuleOK with default headers values
func NewUpdateCleaningActiveRuleOK() *UpdateCleaningActiveRuleOK {

	return &UpdateCleaningActiveRuleOK{}
}

// WriteResponse to the client
func (o *UpdateCleaningActiveRuleOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}
