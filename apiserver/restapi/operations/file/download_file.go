// Code generated by go-swagger; DO NOT EDIT.

package file

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// DownloadFileHandlerFunc turns a function with the right signature into a download file handler
type DownloadFileHandlerFunc func(DownloadFileParams) middleware.Responder

// Handle executing the request and returning a response
func (fn DownloadFileHandlerFunc) Handle(params DownloadFileParams) middleware.Responder {
	return fn(params)
}

// DownloadFileHandler interface for that can handle valid download file params
type DownloadFileHandler interface {
	Handle(DownloadFileParams) middleware.Responder
}

// NewDownloadFile creates a new http.Handler for the download file operation
func NewDownloadFile(ctx *middleware.Context, handler DownloadFileHandler) *DownloadFile {
	return &DownloadFile{Context: ctx, Handler: handler}
}

/*DownloadFile swagger:route GET /v1/file/download file downloadFile

获取文件

获取文件

*/
type DownloadFile struct {
	Context *middleware.Context
	Handler DownloadFileHandler
}

func (o *DownloadFile) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewDownloadFileParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
