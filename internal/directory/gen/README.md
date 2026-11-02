# Generated PiRectory clients

These files are the output of `make generate` in the PiRectory repository,
mirrored here so the `pirectory` identity source can talk to `accounts.v1` and
`credentials.v1` over ConnectRPC.

PiRectory's protos are not published to the Buf Schema Registry and the module
path `go.pilab.hu/cloud/pirectory` does not resolve over the network, so the
adapter carries its generated clients in-tree rather than depending on a
`replace` directive that would only work in a checkout that has both
repositories.

Regenerate with:

```bash
hack/gen-directory-protos.sh              # ../../pirectory by default
hack/gen-directory-protos.sh /path/to/pirectory
```

The script rewrites the module path in the **import block only**. The same
path also appears inside each file's serialized descriptor (the file's
`go_package` option), and changing it there would alter the byte length
without fixing the length prefix in front of it — which corrupts the
descriptor and panics the protobuf runtime during `init`. The script checks
that nothing outside the import block changed and fails if it did.

Do not edit these files by hand.
