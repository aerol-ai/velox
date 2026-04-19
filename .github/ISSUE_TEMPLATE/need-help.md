---
name: Need help
about: You encounter an issue you can't solve
title: ''
labels: 'help wanted'
---


(ノಠ益ಠ)ノ彡┻━┻  

==> Read and try the examples first before requesting help <==

https://github.com/aerol-ai/velox?#examples

If you have trouble with wireguard  https://github.com/aerol-ai/velox?#wireguard-and-velox-
```
If velox cannot connect to server while wireguard is on,
be sure you have added a static route via your main gateway for the ip of velox server.
Else if you forward all the traffic without putting a static route,
you will endup looping your traffic wireguard interface -> velox client -> wireguard interface
If you have trouble making it works on windows, please check this issue #252
```

(ノಠ益ಠ)ノ彡┻━┻






## Describe the goal
A clear and concise description of `what` you try to achieve.
Describe if you are behind a proxy, if you use some kind relay, what protocol/app you want to forward

## Describe what does not work
A clear and concise description of why you can't reach your goal.


## Describe your velox setup
Paste your logs of velox, started with `--log-lvl=DEBUG`, and with the `command line used`
 - client
 - server

## Desktop (please complete the following information):
 - OS: [e.g. iOS]
 - Version [e.g. 22]
