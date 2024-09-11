module golang.zx2c4.com/wireguard/windows

go 1.18

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.21.0
	golang.org/x/net v0.22.0
	golang.org/x/sys v0.18.0
	golang.org/x/text v0.14.0
)

require (
	github.com/miekg/dns v1.1.59 // indirect
	golang.org/x/mod v0.16.0 // indirect
	golang.org/x/tools v0.19.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
)