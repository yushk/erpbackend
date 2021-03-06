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

// AlarmConfigs 解析告警配置
//
// swagger:model AlarmConfigs
type AlarmConfigs struct {

	// 配置状态（1:已生效，0:未生效）
	// Required: true
	ConfigStatus *int64 `json:"configStatus"`

	// 解析告警周期
	// Required: true
	CronCycle *int64 `json:"cronCycle"`

	// 设备类型
	// Required: true
	DeviceProfile *string `json:"deviceProfile"`

	// 初始值计算周期
	// Required: true
	InitCycle *int64 `json:"initCycle"`

	// 纵比-均差偏差率-阈值
	// Required: true
	LMDDRThreshold *string `json:"lMDDRThreshold"`

	// 纵比-均差-阈值
	// Required: true
	LMDThreshold *string `json:"lMDThreshold"`

	// 纵比-数值变化率-阈值
	// Required: true
	LValCRThreshold *string `json:"lValCRThreshold"`

	// 纵比-数值偏差率-阈值
	// Required: true
	LValDRThreshold *string `json:"lValDRThreshold"`

	// 最小持续时间
	// Required: true
	MinDuration *int64 `json:"minDuration"`

	// 横比-数值偏差率-阈值
	// Required: true
	TValDRThreshold *string `json:"tValDRThreshold"`

	// 任务状态（1:启动中，0:暂停中）
	// Required: true
	TaskStatus *int64 `json:"taskStatus"`

	// 横向比较设备选择
	// Required: true
	TransverseDevices []string `json:"transverseDevices"`

	// 设备上传数据周期
	// Required: true
	UploadCycle *int64 `json:"uploadCycle"`

	// 解析告警配置ID
	// Required: true
	UUID *string `json:"uuid"`
}

// Validate validates this alarm configs
func (m *AlarmConfigs) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateConfigStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCronCycle(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeviceProfile(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInitCycle(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLMDDRThreshold(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLMDThreshold(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLValCRThreshold(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLValDRThreshold(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMinDuration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTValDRThreshold(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTaskStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTransverseDevices(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUploadCycle(formats); err != nil {
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

func (m *AlarmConfigs) validateConfigStatus(formats strfmt.Registry) error {

	if err := validate.Required("configStatus", "body", m.ConfigStatus); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateCronCycle(formats strfmt.Registry) error {

	if err := validate.Required("cronCycle", "body", m.CronCycle); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateDeviceProfile(formats strfmt.Registry) error {

	if err := validate.Required("deviceProfile", "body", m.DeviceProfile); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateInitCycle(formats strfmt.Registry) error {

	if err := validate.Required("initCycle", "body", m.InitCycle); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateLMDDRThreshold(formats strfmt.Registry) error {

	if err := validate.Required("lMDDRThreshold", "body", m.LMDDRThreshold); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateLMDThreshold(formats strfmt.Registry) error {

	if err := validate.Required("lMDThreshold", "body", m.LMDThreshold); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateLValCRThreshold(formats strfmt.Registry) error {

	if err := validate.Required("lValCRThreshold", "body", m.LValCRThreshold); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateLValDRThreshold(formats strfmt.Registry) error {

	if err := validate.Required("lValDRThreshold", "body", m.LValDRThreshold); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateMinDuration(formats strfmt.Registry) error {

	if err := validate.Required("minDuration", "body", m.MinDuration); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateTValDRThreshold(formats strfmt.Registry) error {

	if err := validate.Required("tValDRThreshold", "body", m.TValDRThreshold); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateTaskStatus(formats strfmt.Registry) error {

	if err := validate.Required("taskStatus", "body", m.TaskStatus); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateTransverseDevices(formats strfmt.Registry) error {

	if err := validate.Required("transverseDevices", "body", m.TransverseDevices); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateUploadCycle(formats strfmt.Registry) error {

	if err := validate.Required("uploadCycle", "body", m.UploadCycle); err != nil {
		return err
	}

	return nil
}

func (m *AlarmConfigs) validateUUID(formats strfmt.Registry) error {

	if err := validate.Required("uuid", "body", m.UUID); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AlarmConfigs) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AlarmConfigs) UnmarshalBinary(b []byte) error {
	var res AlarmConfigs
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
