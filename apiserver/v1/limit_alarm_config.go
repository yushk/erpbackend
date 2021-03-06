// Code generated by go-swagger; DO NOT EDIT.

package v1

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// LimitAlarmConfig 设备超限告警配置
//
// swagger:model LimitAlarmConfig
type LimitAlarmConfig struct {

	// 数值周期
	Cycle int64 `json:"cycle"`

	// 设备名称
	DeviceName string `json:"deviceName"`

	// 属性超限配置列表
	FieldLimits []*FieldLimit `json:"fieldLimits"`

	// 超限告警类型Default(默认告警)、MovingAvg(移动平均值告警)、CycleAvg(周期平均值告警)
	// Enum: [Default MovingAvg CycleAvg]
	Type string `json:"type"`

	// 配置ID
	UUID string `json:"uuid"`
}

// Validate validates this limit alarm config
func (m *LimitAlarmConfig) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFieldLimits(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *LimitAlarmConfig) validateFieldLimits(formats strfmt.Registry) error {

	if swag.IsZero(m.FieldLimits) { // not required
		return nil
	}

	for i := 0; i < len(m.FieldLimits); i++ {
		if swag.IsZero(m.FieldLimits[i]) { // not required
			continue
		}

		if m.FieldLimits[i] != nil {
			if err := m.FieldLimits[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("fieldLimits" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

var limitAlarmConfigTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Default","MovingAvg","CycleAvg"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		limitAlarmConfigTypeTypePropEnum = append(limitAlarmConfigTypeTypePropEnum, v)
	}
}

const (

	// LimitAlarmConfigTypeDefault captures enum value "Default"
	LimitAlarmConfigTypeDefault string = "Default"

	// LimitAlarmConfigTypeMovingAvg captures enum value "MovingAvg"
	LimitAlarmConfigTypeMovingAvg string = "MovingAvg"

	// LimitAlarmConfigTypeCycleAvg captures enum value "CycleAvg"
	LimitAlarmConfigTypeCycleAvg string = "CycleAvg"
)

// prop value enum
func (m *LimitAlarmConfig) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, limitAlarmConfigTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *LimitAlarmConfig) validateType(formats strfmt.Registry) error {

	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *LimitAlarmConfig) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LimitAlarmConfig) UnmarshalBinary(b []byte) error {
	var res LimitAlarmConfig
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
