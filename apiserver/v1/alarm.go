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

// Alarm 传输告警信息
//
// swagger:model Alarm
type Alarm struct {

	// 设备可视化名称
	BasicsDeviceName string `json:"basicsDeviceName"`

	// 确认状态(1:已确认，0:未确认)
	// Enum: [0 1]
	ConfirmStatus int64 `json:"confirmStatus"`

	// 确认人
	ConfirmUser string `json:"confirmUser"`

	// 告警描述
	Description string `json:"description"`

	// 设备名
	DeviceName string `json:"deviceName"`

	// 设备类型
	DeviceProfile string `json:"deviceProfile"`

	// 告警结束时间
	EndTime int64 `json:"endTime"`

	// 设备属性
	FieldName string `json:"fieldName"`

	// 设备类型可视化名称
	ProfileName string `json:"profileName"`

	// 告警级别
	// Enum: [CRITICAL NORMAL]
	Severity string `json:"severity"`

	// 告警开始时间
	StartTime int64 `json:"startTime"`

	// 变电站名称
	StationName string `json:"stationName"`

	// 一次设备名称
	TestingDeviceName string `json:"testingDeviceName"`

	// 唯一编码
	UUID string `json:"uuid"`

	// 属性可视化名称
	ViewName string `json:"viewName"`
}

// Validate validates this alarm
func (m *Alarm) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateConfirmStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSeverity(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var alarmTypeConfirmStatusPropEnum []interface{}

func init() {
	var res []int64
	if err := json.Unmarshal([]byte(`[0,1]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		alarmTypeConfirmStatusPropEnum = append(alarmTypeConfirmStatusPropEnum, v)
	}
}

// prop value enum
func (m *Alarm) validateConfirmStatusEnum(path, location string, value int64) error {
	if err := validate.EnumCase(path, location, value, alarmTypeConfirmStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Alarm) validateConfirmStatus(formats strfmt.Registry) error {

	if swag.IsZero(m.ConfirmStatus) { // not required
		return nil
	}

	// value enum
	if err := m.validateConfirmStatusEnum("confirmStatus", "body", m.ConfirmStatus); err != nil {
		return err
	}

	return nil
}

var alarmTypeSeverityPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["CRITICAL","NORMAL"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		alarmTypeSeverityPropEnum = append(alarmTypeSeverityPropEnum, v)
	}
}

const (

	// AlarmSeverityCRITICAL captures enum value "CRITICAL"
	AlarmSeverityCRITICAL string = "CRITICAL"

	// AlarmSeverityNORMAL captures enum value "NORMAL"
	AlarmSeverityNORMAL string = "NORMAL"
)

// prop value enum
func (m *Alarm) validateSeverityEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, alarmTypeSeverityPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Alarm) validateSeverity(formats strfmt.Registry) error {

	if swag.IsZero(m.Severity) { // not required
		return nil
	}

	// value enum
	if err := m.validateSeverityEnum("severity", "body", m.Severity); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Alarm) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Alarm) UnmarshalBinary(b []byte) error {
	var res Alarm
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
