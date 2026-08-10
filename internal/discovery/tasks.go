package discovery

import (
	"context"
	"fmt"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/task"
	flanksourceContext "github.com/flanksource/commons/context"
)

type stageTaskController struct {
	task *task.Task
}

func (c stageTaskController) Actions() []task.ControlAction {
	if c.task.Status() == task.StatusPending || c.task.Status() == task.StatusRunning {
		return []task.ControlAction{task.ControlStop}
	}
	return nil
}

func (c stageTaskController) Control(_ context.Context, action task.ControlAction) error {
	if action != task.ControlStop {
		return fmt.Errorf("discovery task does not support %q", action)
	}
	c.task.Cancel()
	return nil
}

func newDiscoveryTaskGroup(id, mode, profile string) task.TypedGroup[Stage] {
	return clicky.StartGroup[Stage]("discover "+mode,
		task.WithGroupID(id),
		task.WithKind("discovery"),
		task.WithLabels(map[string]string{"mode": mode, "profile": profile}),
		task.WithConcurrency(1),
	)
}

func runDiscoveryTask(
	ctx context.Context,
	tasks task.TypedGroup[Stage],
	name string,
	run func(context.Context, *task.Task) (Stage, error),
) (Stage, error) {
	type outcome struct {
		stage Stage
		err   error
	}
	completed := make(chan outcome, 1)
	handle := tasks.Add(name, func(taskCtx flanksourceContext.Context, t *task.Task) (Stage, error) {
		t.SetController(stageTaskController{task: t})
		combined, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(taskCtx, cancel)
		defer stop()
		defer cancel()
		stage, err := run(combined, t)
		completed <- outcome{stage: stage, err: err}
		return stage, err
	})
	result := <-completed
	handle.WaitFor()
	return result.stage, result.err
}
