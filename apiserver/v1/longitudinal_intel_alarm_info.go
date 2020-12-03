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

// LongitudinalIntelAlarmInfo 智能告警信息
//
// swagger:model LongitudinalIntelAlarmInfo
type LongitudinalIntelAlarmInfo struct {

	// 某相智能告警信息列表
	AlarmItems []*AlarmSimpleInfo `json:"alarmItems"`

	// 设备类型(A项、B项、C项)
	// Required: true
	DeviceType *string `json:"deviceType"`
}

// Validate validates this longitudinal intel alarm info
func (m *LongitudinalIntelAlarmInfo) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAlarmItems(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeviceType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *LongitudinalIntelAlarmInfo) validateAlarmItems(formats strfmt.Registry) error {

	if swag.IsZero(m.AlarmItems) { // not required
		return nil
	}

	for i := 0; i < len(m.AlarmItems); i++ {
		if swag.IsZero(m.AlarmItems[i]) { // not required
			continue
		}

		if m.AlarmItems[i] != nil {
			if err := m.AlarmItems[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("alarmItems" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *LongitudinalIntelAlarmInfo) validateDeviceType(formats strfmt.Registry) error {

	if err := validate.Required("deviceType", "body", m.DeviceType); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *LongitudinalIntelAlarmInfo) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LongitudinalIntelAlarmInfo) UnmarshalBinary(b []byte) error {
	var res LongitudinalIntelAlarmInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
