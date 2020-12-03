// Code generated by go-swagger; DO NOT EDIT.

package v1

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TransferAlarmConfig 传输告警配置
//
// swagger:model TransferAlarmConfig
type TransferAlarmConfig struct {

	// 设备类型
	DeviceProfile string `json:"deviceProfile"`

	// 属性传输告警配置列表
	FieldTransfers []*FieldTransfer `json:"fieldTransfers"`

	// 传输告警配置ID
	UUID string `json:"uuid"`
}

// Validate validates this transfer alarm config
func (m *TransferAlarmConfig) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFieldTransfers(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TransferAlarmConfig) validateFieldTransfers(formats strfmt.Registry) error {

	if swag.IsZero(m.FieldTransfers) { // not required
		return nil
	}

	for i := 0; i < len(m.FieldTransfers); i++ {
		if swag.IsZero(m.FieldTransfers[i]) { // not required
			continue
		}

		if m.FieldTransfers[i] != nil {
			if err := m.FieldTransfers[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("fieldTransfers" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *TransferAlarmConfig) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TransferAlarmConfig) UnmarshalBinary(b []byte) error {
	var res TransferAlarmConfig
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
