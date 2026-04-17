# mDNS

mDNS implementation with service discovery and advertisement.

## Features

- Service discovery (one-shot and continuous queries)
- Service advertisement with conflict probing
- Exponential backoff announcements
- Goodbye packets on shutdown
- IPv4/IPv6 dual-stack support

## Usage

```bash
go get github.com/cyberxnomad/mdns
```

See [examples](./examples/) for more usage examples.

### Query  

```go
ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
defer cancel()

ch, err := mdns.Query(ctx, []mdns.Question{{Type: "_http._tcp"}})
if err != nil {
    log.Fatal(err)
}

for entry := range ch {
    fmt.Printf("%s at %s:%d\n", entry.Instance, entry.Host, entry.Port)
}
```

### Respond  

```go
type myService struct{}

func (s *myService) Hostname() string        { return "my-device" }
func (s *myService) Port() uint16            { return 8080 }
func (s *myService) IPAddrs() []net.IPAddr   { return nil }
func (s *myService) Text() map[string]string { return map[string]string{"v": "1.0"} }

func main() {
    r := mdns.NewResponder()
    r.Serve()
    defer r.Shutdown()

    r.Register(mdns.Service{
        Instance: "My Server",
        Type:     "_http._tcp",
    }, &myService{})

    // ...
}
```

## Status

API is not yet stable. Some features are incomplete:

- TC (truncated) bit is not supported
- Simultaneous probe tiebreaking is not implemented
- Known-Answer Suppression only covers PTR records
- Cache is not implemented
- Logging is not yet implemented

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License  

[MIT](./LICENSE)
