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

// TransverseValuesInfo 设备横向分析曲线图
//
// swagger:model TransverseValuesInfo
type TransverseValuesInfo struct {

	// 横向分析均差列表
	AverageDeviationItems []*TransverseValues `json:"averageDeviationItems"`

	// 横向分析变化率列表
	ChangeRateItems []*TransverseValues `json:"changeRateItems"`

	// 设备类型(A项、B项、C项)
	// Required: true
	DeviceType *string `json:"deviceType"`

	// 属性名称
	// Required: true
	FieldName *string `json:"fieldName"`

	// 属性单位
	// Required: true
	FieldUnit *string `json:"fieldUnit"`

	// 智能告警列表
	IntelligenceAlarmItems []*TransverseIntelAlarmInfo `json:"intelligenceAlarmItems"`

	// 横向分析数值列表
	NumericalValueItems []*TransverseValues `json:"numericalValueItems"`
}

// Validate validates this transverse values info
func (m *TransverseValuesInfo) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAverageDeviationItems(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateChangeRateItems(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeviceType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFieldName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFieldUnit(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIntelligenceAlarmItems(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNumericalValueItems(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TransverseValuesInfo) validateAverageDeviationItems(formats strfmt.Registry) error {

	if swag.IsZero(m.AverageDeviationItems) { // not required
		return nil
	}

	for i := 0; i < len(m.AverageDeviationItems); i++ {
		if swag.IsZero(m.AverageDeviationItems[i]) { // not required
			continue
		}

		if m.AverageDeviationItems[i] != nil {
			if err := m.AverageDeviationItems[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("averageDeviationItems" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *TransverseValuesInfo) validateChangeRateItems(formats strfmt.Registry) error {

	if swag.IsZero(m.ChangeRateItems) { // not required
		return nil
	}

	for i := 0; i < len(m.ChangeRateItems); i++ {
		if swag.IsZero(m.ChangeRateItems[i]) { // not required
			continue
		}

		if m.ChangeRateItems[i] != nil {
			if err := m.ChangeRateItems[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("changeRateItems" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *TransverseValuesInfo) validateDeviceType(formats strfmt.Registry) error {

	if err := validate.Required("deviceType", "body", m.DeviceType); err != nil {
		return err
	}

	return nil
}

func (m *TransverseValuesInfo) validateFieldName(formats strfmt.Registry) error {

	if err := validate.Required("fieldName", "body", m.FieldName); err != nil {
		return err
	}

	return nil
}

func (m *TransverseValuesInfo) validateFieldUnit(formats strfmt.Registry) error {

	if err := validate.Required("fieldUnit", "body", m.FieldUnit); err != nil {
		return err
	}

	return nil
}

func (m *TransverseValuesInfo) validateIntelligenceAlarmItems(formats strfmt.Registry) error {

	if swag.IsZero(m.IntelligenceAlarmItems) { // not required
		return nil
	}

	for i := 0; i < len(m.IntelligenceAlarmItems); i++ {
		if swag.IsZero(m.IntelligenceAlarmItems[i]) { // not required
			continue
		}

		if m.IntelligenceAlarmItems[i] != nil {
			if err := m.IntelligenceAlarmItems[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("intelligenceAlarmItems" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *TransverseValuesInfo) validateNumericalValueItems(formats strfmt.Registry) error {

	if swag.IsZero(m.NumericalValueItems) { // not required
		return nil
	}

	for i := 0; i < len(m.NumericalValueItems); i++ {
		if swag.IsZero(m.NumericalValueItems[i]) { // not required
			continue
		}

		if m.NumericalValueItems[i] != nil {
			if err := m.NumericalValueItems[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("numericalValueItems" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *TransverseValuesInfo) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TransverseValuesInfo) UnmarshalBinary(b []byte) error {
	var res TransverseValuesInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
