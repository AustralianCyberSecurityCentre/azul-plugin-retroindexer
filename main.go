package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/plugin"
	"github.com/goretk/gore"
)

type AzulPluginRetroindexer struct {
	// The last panic error from a recovered panic.
	panicError string
}

func (gi *AzulPluginRetroindexer) GetName() string {
	return "Retroindexer"
}

func (gi *AzulPluginRetroindexer) GetVersion() string {
	return "2026.11.12"
}

func (gi *AzulPluginRetroindexer) GetDescription() string {
	return "Go-Based Retrohunt Ingestion And Biggrep Indexing Plugin."
}

func (gi *AzulPluginRetroindexer) GetFeatures() []events.PluginEntityFeature {
	return []events.PluginEntityFeature{
		{Name: "string_feature", Type: events.FeatureString, Description: "Example string feature"},
		{Name: "datetime_feature", Type: events.FeatureDatetime, Description: "Example DateTime feature"},
		{Name: "int_feature", Type: events.FeatureInteger, Description: "Example int feature"},
		{Name: "float_feature", Type: events.FeatureFloat, Description: "Example float feature"},
	}
}

func (gi *AzulPluginRetroindexer) GetDefaultSettings() *plugin.PluginSettings {
	defaultSettings := plugin.NewDefaultPluginSettings().WithContentFilterDataTypes([]string{
		// Plugin that accepts common executable types, refer to azul-bedrocks for other valid file formats.
		// Windows exe
		"executable/windows/",
		// Non windows exe
		"executable/dll32",
		"executable/pe32",
		// Linux elf
		"executable/linux/elf64",
		"executable/linux/elf32",
		"executable/mach-o",
	})
	return defaultSettings
}

func (gi *AzulPluginRetroindexer) Execute(context context.Context, job *plugin.Job, inputUtils *plugin.PluginInputUtils) *plugin.PluginError {
	_, pluginErr := job.GetContentPath()
	if pluginErr != nil {
		return pluginErr
	}
	// Adding various features	
	pluginErr = job.AddFeature("string_feature", "hello")
	if pluginErr != nil{
		return pluginErr
	}
	pluginErr = job.AddFeature("datetime_feature", "2021-03-29T14:24:08.54928032+11:00")
	if pluginErr != nil{
		return pluginErr
	}
	pluginErr = job.AddFeature("int_feature", "10")
	if pluginErr != nil{
		return pluginErr
	}
	pluginErr = job.AddFeature("float_feature", "987.123")
	if pluginErr != nil{
		return pluginErr
	}

	// Add a child binary, can also be done with a file handle.
	childEvent := job.AddChildBytes([]byte("abcdef child binary!"), map[string]string{"child": "extracted"})
	pluginErr = childEvent.AddFeature("string_feature", "hello")
	if pluginErr != nil{
		return pluginErr
	}

	// Add a Augmented binary, can also be done with a file handle.
	job.AddAugmentedBytes([]byte("Augmented stream!"), events.DataLabelText)
	return nil
}

func main() {
	pr := plugin.NewPluginRunner(&AzulPluginRetroindexer{})
	pr.Run()
}
