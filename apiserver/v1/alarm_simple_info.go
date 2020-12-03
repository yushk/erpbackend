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

// AlarmSimpleInfo 智能告警简略信息（用于纵横比跳转）
//
// swagger:model AlarmSimpleInfo
type AlarmSimpleInfo struct {

	// 告警描述
	// Required: true
	AlarmDescription *string `json:"alarmDescription"`

	// 告警级别
	// Required: true
	// Enum: [CRITICAL NORMAL]
	AlarmSeverity *string `json:"alarmSeverity"`

	// 告警时间
	// Required: true
	AlarmTime *int64 `json:"alarmTime"`
}

// Validate validates this alarm simple info
func (m *AlarmSimpleInfo) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAlarmDescription(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAlarmSeverity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAlarmTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AlarmSimpleInfo) validateAlarmDescription(formats strfmt.Registry) error {

	if err := validate.Required("alarmDescription", "body", m.AlarmDescription); err != nil {
		return err
	}

	return nil
}

var alarmSimpleInfoTypeAlarmSeverityPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["CRITICAL","NORMAL"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		alarmSimpleInfoTypeAlarmSeverityPropEnum = append(alarmSimpleInfoTypeAlarmSeverityPropEnum, v)
	}
}

const (

	// AlarmSimpleInfoAlarmSeverityCRITICAL captures enum value "CRITICAL"
	AlarmSimpleInfoAlarmSeverityCRITICAL string = "CRITICAL"

	// AlarmSimpleInfoAlarmSeverityNORMAL captures enum value "NORMAL"
	AlarmSimpleInfoAlarmSeverityNORMAL string = "NORMAL"
)

// prop value enum
func (m *AlarmSimpleInfo) validateAlarmSeverityEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, alarmSimpleInfoTypeAlarmSeverityPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AlarmSimpleInfo) validateAlarmSeverity(formats strfmt.Registry) error {

	if err := validate.Required("alarmSeverity", "body", m.AlarmSeverity); err != nil {
		return err
	}

	// value enum
	if err := m.validateAlarmSeverityEnum("alarmSeverity", "body", *m.AlarmSeverity); err != nil {
		return err
	}

	return nil
}

func (m *AlarmSimpleInfo) validateAlarmTime(formats strfmt.Registry) error {

	if err := validate.Required("alarmTime", "body", m.AlarmTime); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AlarmSimpleInfo) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AlarmSimpleInfo) UnmarshalBinary(b []byte) error {
	var res AlarmSimpleInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
