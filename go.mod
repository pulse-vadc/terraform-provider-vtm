module github.com/pulse-vadc/terraform-provider-vtm

require (
	github.com/hashicorp/terraform v0.12.2
	github.com/pulse-vadc/go-vtm v0.0.0-20190730120709-e8c8deea3bb4
)

replace github.com/pulse-vadc/go-vtm => ../go-vtm

replace git.apache.org/thrift.git => github.com/apache/thrift v0.0.0-20180902110319-2566ecd5d999
