package paramlogger

import (
	"encoding/json"
	"mime/multipart"
	"net/url"
	"strings"

	"github.com/gobuffalo/buffalo"
	"github.com/pkg/errors"
)

// ParameterExclusionList is the list of parameter names that will be filtered
// from the application logs (see maskSecrets).
// Important: this list will be used in case insensitive.
var ParameterExclusionList = []string{
	"Password",
	"PasswordConfirmation",
	"CreditCard",
	"CVC",
}

var filteredIndicator = []string{"[FILTERED]"}

// Middleware is a buffalo middleware function to connect this parameter filterer with buffalo
func Middleware(next buffalo.Handler) buffalo.Handler {
	return func(c buffalo.Context) error {
		defer func() {
			req := c.Request()
			if req.Method != "GET" {
				if err := logForm(c); err != nil {
					c.Logger().Error(err)
				}
			}

			b, err := json.Marshal(c.Params())
			if err != nil {
				c.Logger().Error(err)
			}

			c.LogField("params", string(b))
		}()

		return next(c)
	}
}

func logForm(c buffalo.Context) error {
	req := c.Request()
	mp := req.MultipartForm
	if mp != nil {
		return multipartParamLogger(mp, c)
	}

	if err := addFormFieldTo(c, req.Form); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func multipartParamLogger(mp *multipart.Form, c buffalo.Context) error {
	uv := url.Values{}
	for k, v := range mp.Value {
		for _, vv := range v {
			uv.Add(k, vv)
		}
	}
	for k, v := range mp.File {
		for _, vv := range v {
			uv.Add(k, vv.Filename)
		}
	}

	if err := addFormFieldTo(c, uv); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func addFormFieldTo(c buffalo.Context, form url.Values) error {
	maskedForm := maskSecrets(form)
	b, err := json.Marshal(maskedForm)

	if err != nil {
		return err
	}

	c.LogField("form", string(b))
	return nil
}

// maskSecrets matches ParameterExclusionList against parameters passed in the
// request, and returns a copy of the request parameters replacing excluded params
// with [FILTERED].
func maskSecrets(form url.Values) url.Values {
	copy := url.Values{}
	for key, values := range form {
	exclcheck:
		for _, excluded := range ParameterExclusionList {
			copy[key] = values
			if strings.EqualFold(key, excluded) {
				copy[key] = filteredIndicator
				break exclcheck
			}

		}
	}
	return copy
}
