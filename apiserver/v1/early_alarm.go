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

// EarlyAlarm 超限告警信息
//
// swagger:model EarlyAlarm
type EarlyAlarm struct {

	// 基础设备名称
	// Required: true
	BasicsDeviceName *string `json:"basicsDeviceName"`

	// 确认状态(1:已确认，0:未确认)
	// Required: true
	ConfirmStatus *int64 `json:"confirmStatus"`

	// 确认人
	// Required: true
	ConfirmUser *string `json:"confirmUser"`

	// 告警描述
	// Required: true
	Description *string `json:"description"`

	// 设备类型
	// Required: true
	DeviceProfile *string `json:"deviceProfile"`

	// 结束告警时间
	// Required: true
	EndTime *int64 `json:"endTime"`

	// 属性名称
	FieldName string `json:"fieldName,omitempty"`

	// 设备类型
	ProfileName string `json:"profileName,omitempty"`

	// 告警级别
	// Required: true
	// Enum: [CRITICAL NORMAL]
	Severity *string `json:"severity"`

	// 开始告警时间
	// Required: true
	StartTime *int64 `json:"startTime"`

	// 变电站名称
	// Required: true
	StationName *string `json:"stationName"`

	// 检测设备名称
	// Required: true
	TestingDeviceName *string `json:"testingDeviceName"`

	// 唯一编码
	// Required: true
	UUID *string `json:"uuid"`

	// 属性展示名称
	// Required: true
	ViewName *string `json:"viewName"`
}

// Validate validates this early alarm
func (m *EarlyAlarm) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBasicsDeviceName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConfirmStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConfirmUser(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDescription(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeviceProfile(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEndTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSeverity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStartTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStationName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTestingDeviceName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUUID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateViewName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EarlyAlarm) validateBasicsDeviceName(formats strfmt.Registry) error {

	if err := validate.Required("basicsDeviceName", "body", m.BasicsDeviceName); err != nil {
		return err
	}

	return nil
}

func (m *EarlyAlarm) validateConfirmStatus(formats strfmt.Registry) error {

	if err := validate.Required("confirmStatus", "body", m.ConfirmStatus); err != nil {
		return err
	}

	return nil
}

func (m *EarlyAlarm) validateConfirmUser(formats strfmt.Registry) error {

	if err := validate.Required("confirmUser", "body", m.ConfirmUser); err != nil {
		return err
	}

	return nil
}

func (m *EarlyAlarm) validateDescription(formats strfmt.Registry) error {

	if err := validate.Required("description", "body", m.Description); err != nil {
		return err
	}

	return nil
}

func (m *EarlyAlarm) validateDeviceProfile(formats strfmt.Registry) error {

	if err := validate.Required("deviceProfile", "body", m.DeviceProfile); err != nil {
		return err
	}

	return nil
}

func (m *EarlyAlarm) validateEndTime(formats strfmt.Registry) error {

	if err := validate.Required("endTime", "body", m.EndTime); err != nil {
		return err
	}

	return nil
}

var earlyAlarmTypeSeverityPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["CRITICAL","NORMAL"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		earlyAlarmTypeSeverityPropEnum = append(earlyAlarmTypeSeverityPropEnum, v)
	}
}

const (

	// EarlyAlarmSeverityCRITICAL captures enum value "CRITICAL"
	EarlyAlarmSeverityCRITICAL string = "CRITICAL"

	// EarlyAlarmSeverityNORMAL captures enum value "NORMAL"
	EarlyAlarmSeverityNORMAL string = "NORMAL"
)

// prop value enum
func (m *EarlyAlarm) validateSeverityEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, earlyAlarmTypeSeverityPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *EarlyAlarm) validateSeverity(formats strfmt.Registry) error {

	if err := validate.Required("severity", "body", m.Severity); err != nil {
		return err
	}

	// value enum
	if err := m.validateSeverityEnum("severity", "body", *m.Severity); err != nil {
		return err
	}

	return nil
}

func (m *EarlyAlarm) validateStartTime(formats strfmt.Registry) error {

	if err := validate.Required("startTime", "body", m.StartTime); err != nil {
		return err
	}

	return nil
}

func (m *EarlyAlarm) validateStationName(formats strfmt.Registry) error {

	if err := validate.Required("stationName", "body", m.StationName); err != nil {
		return err
	}

	return nil
}

func (m *EarlyAlarm) validateTestingDeviceName(formats strfmt.Registry) error {

	if err := validate.Required("testingDeviceName", "body", m.TestingDeviceName); err != nil {
		return err
	}

	return nil
}

func (m *EarlyAlarm) validateUUID(formats strfmt.Registry) error {

	if err := validate.Required("uuid", "body", m.UUID); err != nil {
		return err
	}

	return nil
}

func (m *EarlyAlarm) validateViewName(formats strfmt.Registry) error {

	if err := validate.Required("viewName", "body", m.ViewName); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *EarlyAlarm) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EarlyAlarm) UnmarshalBinary(b []byte) error {
	var res EarlyAlarm
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
