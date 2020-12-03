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

// SingleRule 数据清洗配置单相位规则信息
//
// swagger:model SingleRule
type SingleRule struct {

	// 属性名称
	// Required: true
	FieldName *string `json:"fieldName"`

	// 操作符
	// Required: true
	Operator *string `json:"operator"`

	// 相位
	// Required: true
	Phase *string `json:"phase"`

	// 值
	// Required: true
	Value *string `json:"value"`
}

// Validate validates this single rule
func (m *SingleRule) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFieldName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOperator(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePhase(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValue(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SingleRule) validateFieldName(formats strfmt.Registry) error {

	if err := validate.Required("fieldName", "body", m.FieldName); err != nil {
		return err
	}

	return nil
}

func (m *SingleRule) validateOperator(formats strfmt.Registry) error {

	if err := validate.Required("operator", "body", m.Operator); err != nil {
		return err
	}

	return nil
}

func (m *SingleRule) validatePhase(formats strfmt.Registry) error {

	if err := validate.Required("phase", "body", m.Phase); err != nil {
		return err
	}

	return nil
}

func (m *SingleRule) validateValue(formats strfmt.Registry) error {

	if err := validate.Required("value", "body", m.Value); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SingleRule) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SingleRule) UnmarshalBinary(b []byte) error {
	var res SingleRule
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
