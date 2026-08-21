package entities

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/flanksource/clicky/rpc"
)

func requestBody(ctx context.Context, flattened map[string]any) (map[string]any, error) {
	request, ok := rpc.RequestFromContext(ctx)
	if !ok || request.Body == nil {
		return flattened, nil
	}

	data, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	if len(data) == 0 {
		return flattened, nil
	}

	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, fmt.Errorf("decode request body: %w", err)
	}
	if body == nil {
		return nil, fmt.Errorf("request body must be a JSON object")
	}
	return body, nil
}
