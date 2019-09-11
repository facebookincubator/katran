# wireshark plugin to parse GUE variant 1 encapsulation

## instalation:
in your home dir create this directory:
```
mkdir -p ~/.config/wireshark/plugins/guev1
```

then copy guev1.lua into it. wireshark on startup automatically enables this plugin and would try to parse everything w/ UDP destination port 6080 as GUEv1 encapsulated