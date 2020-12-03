package options

// Options database options
type Options struct {
	Address  string
	Username string
	Password string
}

// NewOptions new options
func NewOptions() *Options {
	return &Options{}
}

// SetAddress set address
func (o *Options) SetAddress(address string) *Options {
	o.Address = address
	return o
}

// SetUsername set username
func (o *Options) SetUsername(username string) *Options {
	o.Username = username
	return o
}

// SetPassword set password
func (o *Options) SetPassword(password string) *Options {
	o.Password = password
	return o
}
