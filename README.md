// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

# Terraform Provider for Pulse Secure Virtual Traffic Manager

## Introduction

`terraform-provider-vtm` is a Terraform "provider" to facilitate the configuration of Pulse 
vTM from within Terraform templates.  It supports a comprehensive range of
"resources" and "data sources" to allow almost any vTM configuration to be expressed 
in Terraform format.


## Building the provider

To build the terraform provider simply run build.sh for one of the supported API
versions.

You will need to have golang 1.9 or higher and have GOPATH and GOROOT set
appropriately.

```shell
$ ./build.sh
```

See the included PDF manual for more details on using the provider.

## Copyright and License Acknowledgement

Copyright &copy; 2018, Pulse Secure LLC. Licensed under the terms of the
MPL 2.0. See the LICENSE file for details.

The Virtual Traffic Manager Terraform provider depends on a number of
open-source packages. The licenses for these packages can be found in the
appropriate sub-directory of the vendor directory.
