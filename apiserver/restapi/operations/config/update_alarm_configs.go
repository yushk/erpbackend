// Code generated by go-swagger; DO NOT EDIT.

package config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// UpdateAlarmConfigsHandlerFunc turns a function with the right signature into a update alarm configs handler
type UpdateAlarmConfigsHandlerFunc func(UpdateAlarmConfigsParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn UpdateAlarmConfigsHandlerFunc) Handle(params UpdateAlarmConfigsParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// UpdateAlarmConfigsHandler interface for that can handle valid update alarm configs params
type UpdateAlarmConfigsHandler interface {
	Handle(UpdateAlarmConfigsParams, interface{}) middleware.Responder
}

// NewUpdateAlarmConfigs creates a new http.Handler for the update alarm configs operation
func NewUpdateAlarmConfigs(ctx *middleware.Context, handler UpdateAlarmConfigsHandler) *UpdateAlarmConfigs {
	return &UpdateAlarmConfigs{Context: ctx, Handler: handler}
}

/*UpdateAlarmConfigs swagger:route PUT /v1/configs/alarms config updateAlarmConfigs

修改解析告警配置信息

修改解析告警配置信息

*/
type UpdateAlarmConfigs struct {
	Context *middleware.Context
	Handler UpdateAlarmConfigsHandler
}

func (o *UpdateAlarmConfigs) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewUpdateAlarmConfigsParams()

	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		r = aCtx
	}
	var principal interface{}
	if uprinc != nil {
		principal = uprinc
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}

// UpdateAlarmConfigsBody update alarm configs body
//
// swagger:model UpdateAlarmConfigsBody
type UpdateAlarmConfigsBody struct {

	// 解析告警周期
	CronCycle int64 `json:"cronCycle,omitempty"`

	// 初始值计算周期
	InitCycle int64 `json:"initCycle,omitempty"`

	// 纵比-均差偏差率-阈值
	LMDDRThreshold string `json:"lMDDRThreshold,omitempty"`

	// 纵比-均差-阈值
	LMDThreshold string `json:"lMDThreshold,omitempty"`

	// 纵比-数值变化率-阈值
	LValCRThreshold string `json:"lValCRThreshold,omitempty"`

	// 纵比-数值偏差率-阈值
	LValDRThreshold string `json:"lValDRThreshold,omitempty"`

	// 最小持续时间
	MinDuration int64 `json:"minDuration,omitempty"`

	// 横比-数值偏差率-阈值
	TValDRThreshold string `json:"tValDRThreshold,omitempty"`

	// 横向比较设备选择
	TransverseDevices []string `json:"transverseDevices"`

	// 设备上传数据周期
	UploadCycle int64 `json:"uploadCycle,omitempty"`

	// 解析告警配置ID
	UUID string `json:"uuid,omitempty"`
}

// Validate validates this update alarm configs body
func (o *UpdateAlarmConfigsBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *UpdateAlarmConfigsBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *UpdateAlarmConfigsBody) UnmarshalBinary(b []byte) error {
	var res UpdateAlarmConfigsBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
