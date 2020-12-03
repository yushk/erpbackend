// Code generated by go-swagger; DO NOT EDIT.

package v1

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Log 日志信息
//
// swagger:model Log
type Log struct {

	// 参数列表
	Args []string `json:"args"`

	// 创建时间
	// Required: true
	Created *int64 `json:"created"`

	// 日志级别
	// Required: true
	// Enum: [ERROR INFO DEBUG WARN TRACE]
	Level *string `json:"level"`

	// 日志信息
	// Required: true
	Message *string `json:"message"`

	// 服务名
	// Required: true
	OriginService *string `json:"origin_service"`
}

// Validate validates this log
func (m *Log) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreated(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLevel(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMessage(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOriginService(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Log) validateCreated(formats strfmt.Registry) error {

	if err := validate.Required("created", "body", m.Created); err != nil {
		return err
	}

	return nil
}

var logTypeLevelPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["ERROR","INFO","DEBUG","WARN","TRACE"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		logTypeLevelPropEnum = append(logTypeLevelPropEnum, v)
	}
}

const (

	// LogLevelERROR captures enum value "ERROR"
	LogLevelERROR string = "ERROR"

	// LogLevelINFO captures enum value "INFO"
	LogLevelINFO string = "INFO"

	// LogLevelDEBUG captures enum value "DEBUG"
	LogLevelDEBUG string = "DEBUG"

	// LogLevelWARN captures enum value "WARN"
	LogLevelWARN string = "WARN"

	// LogLevelTRACE captures enum value "TRACE"
	LogLevelTRACE string = "TRACE"
)

// prop value enum
func (m *Log) validateLevelEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, logTypeLevelPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Log) validateLevel(formats strfmt.Registry) error {

	if err := validate.Required("level", "body", m.Level); err != nil {
		return err
	}

	// value enum
	if err := m.validateLevelEnum("level", "body", *m.Level); err != nil {
		return err
	}

	return nil
}

func (m *Log) validateMessage(formats strfmt.Registry) error {

	if err := validate.Required("message", "body", m.Message); err != nil {
		return err
	}

	return nil
}

func (m *Log) validateOriginService(formats strfmt.Registry) error {

	if err := validate.Required("origin_service", "body", m.OriginService); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Log) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Log) UnmarshalBinary(b []byte) error {
	var res Log
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
