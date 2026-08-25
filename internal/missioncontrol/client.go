package missioncontrol

import (
	"fmt"

	"github.com/flanksource/incident-commander/clientcmd/mccontext"
	"github.com/flanksource/incident-commander/sdk"
)

// NewUploader binds an uploader to a faro context.
//
// There is deliberately no server or token flag: faro already owns the login
// flow, the credential store and the refresh, and a second copy of that here
// would be a second place for a stale token to live. `faro auth login --server
// <url>` is the whole setup, and `--context` picks between servers.
func NewUploader(contextName string) (*Uploader, error) {
	client, context, err := newClient(contextName)
	if err != nil {
		return nil, err
	}
	return &Uploader{
		Client:   client,
		Resolver: NewResolver(client),
		Server:   context.Server,
		Context:  context.Name,
	}, nil
}

func newClient(contextName string) (*sdk.Client, *mccontext.MCContext, error) {
	config, err := mccontext.LoadConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("read the Mission Control client config: %w", err)
	}

	context := config.CurrentMCContext()
	if contextName != "" {
		context = config.GetContext(contextName)
		if context == nil {
			return nil, nil, fmt.Errorf("no Mission Control context named %q; `faro context list` shows the configured ones", contextName)
		}
	}
	if context == nil || context.Server == "" {
		return nil, nil, fmt.Errorf("no Mission Control server context configured; run `faro auth login --server <url>`")
	}
	if !context.HasAuth() {
		return nil, nil, fmt.Errorf("context %q holds no usable Mission Control credential; run `faro auth login --server %s`",
			context.Name, context.Server)
	}

	return sdk.New(
		context.Server,
		context.AccessToken(),
		sdk.WithTokenProvider(mccontext.ContextTokenProvider(context)),
		sdk.WithRetry(mccontext.RetryAttempts, mccontext.RetryDelay),
	), context, nil
}
