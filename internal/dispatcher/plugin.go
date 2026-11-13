package dispatcher

import (
	"context"
	"fmt"
	"os"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/plugin"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-retroindexer/internal/indexing"
)

// IngestPlugin uses Azul's native Go plugin runner. This retains the normal
// Dispatcher task lifecycle, rather than independently polling events.
type IngestPlugin struct{ Pipeline *indexing.Pipeline }

func (p *IngestPlugin) GetName() string    { return "RetroindexerIngestor" }
func (p *IngestPlugin) GetVersion() string { return "0.1.0" }
func (p *IngestPlugin) GetDescription() string {
	return "Ingest binary content into Retrohunt BigGrep index batches"
}
func (p *IngestPlugin) GetFeatures() []events.PluginEntityFeature {
	return []events.PluginEntityFeature{}
}
func (p *IngestPlugin) GetDefaultSettings() *plugin.PluginSettings {
	return plugin.NewDefaultPluginSettings().
		WithFilterAllowEventTypes([]events.BinaryAction{events.ActionSourced, events.ActionExtracted}).
		WithRequireHistoric(p.Pipeline.Config.RequireHistoric).
		WithFilterDataTypes(map[string][]string{"content": {}})
}
func (p *IngestPlugin) Execute(ctx context.Context, job *plugin.Job, input *plugin.PluginInputUtils) *plugin.PluginError {
	if ctx.Err() != nil {
		return plugin.NewPluginError(plugin.ErrorTimeout, "Cancelled", ctx.Err().Error())
	}
	src := job.GetSourceEvent()
	if src.Source.Name == "" {
		return plugin.NewPluginOptOut("missing source")
	}
	// Restrict to content stream for parity with the standard Retrohunt content index.
	if !p.Pipeline.Config.StreamLabels["content"] {
		return plugin.NewPluginOptOut("content indexing disabled")
	}
	path, pluginErr := job.GetContentPath()
	if pluginErr != nil {
		return pluginErr
	}
	f, err := os.Open(path)
	if err != nil {
		return plugin.NewPluginError(plugin.ErrorException, "Cannot open input", err.Error())
	}
	defer f.Close()
	added, err := p.Pipeline.AddStream(f, indexing.Metadata{StreamLabel: "content", StreamSource: src.Source.Name})
	if err != nil {
		return plugin.NewPluginError(plugin.ErrorException, "Failed to stage index content", fmt.Sprintf("%v", err))
	}
	if added {
		input.Logger.Info().Str("source", src.Source.Name).Msg("content staged for BigGrep indexing")
	}
	if err := p.Pipeline.MaybePeriodic(); err != nil {
		input.Logger.Warn().Err(err).Msg("periodic index staging failed")
	}
	return nil
}
