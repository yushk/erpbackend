// Code generated by go-swagger; DO NOT EDIT.

package v1

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// TransverseValues 横向分析数值信息
//
// swagger:model TransverseValues
type TransverseValues struct {

	// 检测设备名称
	// Required: true
	TestingDeviceName *string `json:"testingDeviceName"`

	// value items
	ValueItems *ValueItem `json:"valueItems,omitempty"`
}

// Validate validates this transverse values
func (m *TransverseValues) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateTestingDeviceName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValueItems(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TransverseValues) validateTestingDeviceName(formats strfmt.Registry) error {

	if err := validate.Required("testingDeviceName", "body", m.TestingDeviceName); err != nil {
		return err
	}

	return nil
}

func (m *TransverseValues) validateValueItems(formats strfmt.Registry) error {

	if swag.IsZero(m.ValueItems) { // not required
		return nil
	}

	if m.ValueItems != nil {
		if err := m.ValueItems.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("valueItems")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TransverseValues) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TransverseValues) UnmarshalBinary(b []byte) error {
	var res TransverseValues
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
