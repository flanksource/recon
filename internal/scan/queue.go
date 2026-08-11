package scan

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/flanksource/clicky/task"
	flanksourceContext "github.com/flanksource/commons/context"

	"github.com/flanksource/recon/internal/api"
)

type scanQueue struct {
	concurrency int

	mu      sync.Mutex
	group   task.TypedGroup[api.Scan]
	pending int
}

type queuedScanTask struct {
	*task.Task
	complete func()
}

func newScanQueue(concurrency int) (*scanQueue, error) {
	if concurrency < 1 {
		return nil, fmt.Errorf("scan concurrency must be at least 1, got %d", concurrency)
	}
	return &scanQueue{concurrency: concurrency}, nil
}

func (q *scanQueue) Add(
	name, engine, profile string,
	work func(context.Context, *task.Task) (api.Scan, error),
	stop func() error,
) *queuedScanTask {
	if work == nil || stop == nil {
		panic("scan queue work and stop functions are required")
	}

	controller := &scanTaskController{stop: stop}
	q.mu.Lock()
	if q.pending == 0 {
		q.group = task.StartGroup[api.Scan](
			"Scans",
			task.WithKind("scan"),
			task.WithLabels(map[string]string{"concurrency": strconv.Itoa(q.concurrency)}),
			task.WithHref("/scans"),
			task.WithConcurrency(q.concurrency),
		)
	}
	q.pending++
	group := q.group
	q.mu.Unlock()

	var completed sync.Once
	complete := func() { completed.Do(q.complete) }
	handle := group.Add(name, func(ctx flanksourceContext.Context, t *task.Task) (api.Scan, error) {
		defer complete()
		return work(ctx, t)
	}, task.WithTaskController(controller))
	handle.SetDescription(engine + " / " + profile)
	controller.task.Store(handle.Task)
	return &queuedScanTask{Task: handle.Task, complete: complete}
}

func (q *scanQueue) complete() {
	q.mu.Lock()
	q.pending--
	q.mu.Unlock()
}
