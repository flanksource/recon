package entities

import (
	"context"
	"fmt"
	"strconv"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/task"
	flanksourceContext "github.com/flanksource/commons/context"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/missioncontrol"
)

// syncKind is what the browser filters the task list by to follow a sync while
// its own request is still in flight; it must stay in step with the kind the UI
// asks for.
const syncKind = "insight-sync"

// syncRequest is one sync, resolved and then pushed.
type syncRequest struct {
	States           []api.InsightState
	Targets          map[string]api.TargetDocument
	MatchedResources int
	Options          missioncontrol.SyncOptions
}

// runSync syncs under the process task manager.
//
// A sync spends its time in the catalog — one lookup per distinct identity, each
// a round trip to Mission Control — and used to report nothing at all until the
// last state had been decided. Running it as a task is what puts a progress bar
// in front of that on both surfaces at once: the CLI renders the tree it already
// renders for a scan, and the browser reads the same run from /api/v1/tasks
// while the sync it started is still running.
func runSync(
	ctx context.Context,
	uploader *missioncontrol.Uploader,
	request syncRequest,
) (api.InsightSync, error) {
	group := clicky.StartGroup[api.InsightSync](syncName(uploader, request),
		task.WithKind(syncKind),
		task.WithLabels(map[string]string{
			"states":    strconv.Itoa(len(request.States)),
			"resources": strconv.Itoa(request.MatchedResources),
			"agent":     request.Options.Agent,
			"dry-run":   strconv.FormatBool(request.Options.DryRun),
		}),
		task.WithHref("/findings"))

	run := group.Add(fmt.Sprintf("resolve %d states against the catalog", len(request.States)),
		func(taskCtx flanksourceContext.Context, t *task.Task) (api.InsightSync, error) {
			syncCtx, release := follow(ctx, taskCtx)
			defer release()

			request.Options.Progress = func(progress missioncontrol.Progress) {
				t.SetProgress(progress.Done, progress.Total)
				t.SetDescription(describeProgress(progress))
			}
			result, err := uploader.Sync(syncCtx, request.States, request.Targets,
				request.MatchedResources, request.Options)
			if err != nil {
				return result, err
			}
			t.SetDescription(describeSync(result))
			t.SetDetailsProvider(func() any { return result })
			// Nothing failed — the estate is simply not all in the catalog — but a
			// run that left findings behind must not read as clean.
			if len(result.Unresolved) > 0 || len(result.Ambiguous) > 0 {
				t.Warning()
			}
			return result, nil
		})
	return run.GetResult()
}

func syncName(uploader *missioncontrol.Uploader, request syncRequest) string {
	name := "sync insights"
	if request.Options.DryRun {
		name = "preview insights"
	}
	if uploader.Server != "" {
		name += " → " + uploader.Server
	}
	return name
}

func describeProgress(progress missioncontrol.Progress) string {
	if progress.Phase == missioncontrol.PhasePush {
		return fmt.Sprintf("pushing %d insights", progress.Total)
	}
	if progress.Identity == "" {
		return fmt.Sprintf("resolved %d of %d states", progress.Done, progress.Total)
	}
	return progress.Identity
}

func describeSync(result api.InsightSync) string {
	described := fmt.Sprintf("%d of %d eligible states on %d config items",
		result.Direct+result.RolledUp, result.Eligible, len(result.Configs))
	if result.Pushed > 0 {
		described = fmt.Sprintf("pushed %d insights to %d config items", result.Pushed, len(result.Configs))
	}
	if len(result.Ambiguous) > 0 {
		described += fmt.Sprintf(", %d identities matched several", len(result.Ambiguous))
	}
	if len(result.Unresolved) > 0 {
		described += fmt.Sprintf(", %d unresolved", len(result.Unresolved))
	}
	return described
}

// follow gives the task the caller's cancellation without giving it the
// caller's context: clicky owns the task's own lifecycle, and both surfaces here
// wait for the result, so a caller that walks away must stop the work rather
// than leave it running against a request nobody is reading. The same idiom
// `reconctl ping` uses, and for the same reason.
func follow(caller context.Context, taskCtx flanksourceContext.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(taskCtx)
	stop := context.AfterFunc(caller, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}
