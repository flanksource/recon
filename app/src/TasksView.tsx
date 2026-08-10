import { TaskManager } from "@flanksource/clicky-ui";

type Props = {
  selectedId?: string;
  onSelectRun: (id: string | null) => void;
};

export function TasksView({ selectedId, onSelectRun }: Props) {
  return (
    <main className="h-full overflow-y-auto p-6">
      <header className="mb-4">
        <h1 className="text-lg font-semibold">Tasks</h1>
        <p className="text-sm text-muted-foreground">
          Live and recent background tasks from this recon server.
        </p>
      </header>
      <TaskManager
        basePath="/api/v1"
        selectedId={selectedId}
        onSelectRun={onSelectRun}
      />
    </main>
  );
}
