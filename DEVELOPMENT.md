### Debugging test

#### MacOS

You could debug test with [Delve](https://github.com/go-delve/delve) debugger.
Run:
```shell
make test-mac-debug
```
This command will run build `gvisor` binary with debugger enabled.

>Note: By default it would use `--continue` `dlv` option to not pause `givisor` execution on start, if debugger is not connected.
> To pause `gvisor` execution until debugger is connected just remove `"--continue"` parameter from this [line](./test-vfkit/vfkit_suite_test.go#L93) 

And debug sever with `2345` port, you could use any `delve` client to interact with debugger

##### CLI Example

Connect to debugger sever with:
```shell
dlv connect :2345
```
Example of usage:
```shell
Type 'help' for list of commands.
(dlv) break main.main
Breakpoint 1 set at 0xe735776 for main.main() ./work/redhat/gvisor-tap-vsock/cmd/gvproxy/main.go:59
(dlv) continue
> [Breakpoint 1] main.main() ./work/redhat/gvisor-tap-vsock/cmd/gvproxy/main.go:59 (hits goroutine(1):1 total:1) (PC: 0xe735776)
    54:         hostIP      = "192.168.127.254"
    55:         host        = "host"
    56:         gateway     = "gateway"
    57: )
    58:
=>  59: func main() {
    60:         version := types.NewVersion("gvproxy")
    61:         version.AddFlag()
    62:         flag.Var(&endpoints, "listen", "control endpoint")
    63:         flag.BoolVar(&debug, "debug", false, "Print debug info")
    64:         flag.IntVar(&mtu, "mtu", 1500, "Set the MTU")
```
More info about CLI client [here](https://github.com/go-delve/delve/blob/master/Documentation/cli/README.md)

#### Editor integration

For available editor integration look [there](https://github.com/go-delve/delve/blob/master/Documentation/EditorIntegration.md)