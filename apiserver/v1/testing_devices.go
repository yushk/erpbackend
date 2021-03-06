// Code generated by go-swagger; DO NOT EDIT.

package v1

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// TestingDevices 检测设备信息
//
// swagger:model testingDevices
type TestingDevices struct {

	// 基础设备信息
	BasicsDevices []*BasicsDevices `json:"basicsDevices"`

	// 检测设备名称
	// Required: true
	Name *string `json:"name"`

	// 检测设备状态
	// Required: true
	Status *int8 `json:"status"`

	// 检测设备ID
	// Required: true
	UUID *string `json:"uuid"`
}

// Validate validates this testing devices
func (m *TestingDevices) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBasicsDevices(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUUID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TestingDevices) validateBasicsDevices(formats strfmt.Registry) error {

	if swag.IsZero(m.BasicsDevices) { // not required
		return nil
	}

	for i := 0; i < len(m.BasicsDevices); i++ {
		if swag.IsZero(m.BasicsDevices[i]) { // not required
			continue
		}

		if m.BasicsDevices[i] != nil {
			if err := m.BasicsDevices[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("basicsDevices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *TestingDevices) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *TestingDevices) validateStatus(formats strfmt.Registry) error {

	if err := validate.Required("status", "body", m.Status); err != nil {
		return err
	}

	return nil
}

func (m *TestingDevices) validateUUID(formats strfmt.Registry) error {

	if err := validate.Required("uuid", "body", m.UUID); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TestingDevices) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TestingDevices) UnmarshalBinary(b []byte) error {
	var res TestingDevices
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
