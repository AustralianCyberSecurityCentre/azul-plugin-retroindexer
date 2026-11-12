package main

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/plugin"
)

func TestGeneratedBinary(t *testing.T) {
	pr := plugin.NewPluginRunner(&AzulPluginRetroindexer{})

	binary := make([]byte, 2216)
	for i := 0; i < 2216; i++ {
		binary[i] = 'a'
	}

	result := pr.RunTest(t, &plugin.RunTestOptions{
		ContentFileBytes:            binary,
		DisableUncartingContentFile: true,
	}, "Single A character binary.")
	result.AssertJobResultEqual(t, &plugin.TestJobResult{
		Status: "completed",
		Events: []plugin.TestJobEvent{
			plugin.TestJobEvent{
				ChildrenSha256: []string{
					"1c24fd61e61c98f2788ea3b6f19d330079ded26eb6471b330fc58ee4aad48cd9",
				},
				Features: map[string][]plugin.TestBinaryEntityFeature{
					"datetime_feature": []plugin.TestBinaryEntityFeature{
						plugin.TestBinaryEntityFeature{
							Value: "2021-03-29T14:24:08.54928032+11:00",
						},
					},
					"float_feature": []plugin.TestBinaryEntityFeature{
						plugin.TestBinaryEntityFeature{
							Value: "987.123",
						},
					},
					"int_feature": []plugin.TestBinaryEntityFeature{
						plugin.TestBinaryEntityFeature{
							Value: "10",
						},
					},
					"string_feature": []plugin.TestBinaryEntityFeature{
						plugin.TestBinaryEntityFeature{
							Value: "hello",
						},
					},
				},
				AugmentedStreams: []plugin.ResultStream{
					plugin.ResultStream{
						Label:  "text",
						Sha256: "b36ad9c57f2f3b616ac50bd790ea44e6149256a51def0639a8fb593ca659e813",
						Size:   17,
					},
				},
			},
			plugin.TestJobEvent{
				Features: map[string][]plugin.TestBinaryEntityFeature{
					"string_feature": []plugin.TestBinaryEntityFeature{
						plugin.TestBinaryEntityFeature{
							Value: "hello",
						},
					},
				},
				AugmentedStreams: []plugin.ResultStream{
					plugin.ResultStream{
						Relationship: map[string]string{
							"child": "extracted",
						},
						Label:  "content",
						Sha256: "1c24fd61e61c98f2788ea3b6f19d330079ded26eb6471b330fc58ee4aad48cd9",
						Size:   20,
					},
				},
			},
		},
	})
}

func TestSimpleExe(t *testing.T) {
	pr := plugin.NewPluginRunner(&AzulPluginRetroindexer{})
	result := pr.RunTest(t, &plugin.RunTestOptions{
		DownloadSha256: "702e31ed1537c279459a255460f12f0f2863f973e121cd9194957f4f3e7b0994",
	}, "Benign Windows 32EXE, python library executable python_mcp.exe")
	result.AssertJobResultEqual(t, &plugin.TestJobResult{
		Status: "completed",
		Events: []plugin.TestJobEvent{
			plugin.TestJobEvent{
				ChildrenSha256: []string{
					"1c24fd61e61c98f2788ea3b6f19d330079ded26eb6471b330fc58ee4aad48cd9",
				},
				Features: map[string][]plugin.TestBinaryEntityFeature{
					"datetime_feature": []plugin.TestBinaryEntityFeature{
						plugin.TestBinaryEntityFeature{
							Value: "2021-03-29T14:24:08.54928032+11:00",
						},
					},
					"float_feature": []plugin.TestBinaryEntityFeature{
						plugin.TestBinaryEntityFeature{
							Value: "987.123",
						},
					},
					"int_feature": []plugin.TestBinaryEntityFeature{
						plugin.TestBinaryEntityFeature{
							Value: "10",
						},
					},
					"string_feature": []plugin.TestBinaryEntityFeature{
						plugin.TestBinaryEntityFeature{
							Value: "hello",
						},
					},
				},
				AugmentedStreams: []plugin.ResultStream{
					plugin.ResultStream{
						Label:  "text",
						Sha256: "b36ad9c57f2f3b616ac50bd790ea44e6149256a51def0639a8fb593ca659e813",
						Size:   17,
					},
				},
			},
			plugin.TestJobEvent{
				Features: map[string][]plugin.TestBinaryEntityFeature{
					"string_feature": []plugin.TestBinaryEntityFeature{
						plugin.TestBinaryEntityFeature{
							Value: "hello",
						},
					},
				},
				AugmentedStreams: []plugin.ResultStream{
					plugin.ResultStream{
						Relationship: map[string]string{
							"child": "extracted",
						},
						Label:  "content",
						Sha256: "1c24fd61e61c98f2788ea3b6f19d330079ded26eb6471b330fc58ee4aad48cd9",
						Size:   20,
					},
				},
			},
		},
	})
}