import { useEffect, useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TaskManagerButton } from "@flanksource/clicky-ui/data";
import { useBrowserRouter } from "@flanksource/clicky-ui/rpc";
import { InventoryView } from "./TargetsView";
import { ScanDetailView, ScansView } from "./ScansView";
import { ProfilesView } from "./ProfilesView";
import { TargetView } from "./TargetView";
import { TasksView } from "./TasksView";
import { TemplatesView } from "./TemplatesView";

const TABS = [
  { path: "/inventory", label: "Inventory" },
  { path: "/scans", label: "Scans" },
  { path: "/profiles", label: "Profiles" },
  { path: "/templates", label: "Templates" },
];

export function App() {
  const [queryClient] = useState(() => new QueryClient());
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}

function AppContent() {
  const router = useBrowserRouter();
  useEffect(() => {
    if (router.pathname === "/") router.navigate("/inventory", { replace: true });
  }, [router]);

  const targetMatch = router.pathname.match(/^\/inventory\/([^/]+)$/);
  const scanMatch = router.pathname.match(/^\/scans\/([^/]+)$/);
  const taskMatch = router.pathname.match(/^\/tasks(?:\/([^/]+))?$/);
  const templateMatch = router.pathname.match(/^\/templates(?:\/([^/]+))?$/);
  const templateEngine = templateMatch
    ? new URLSearchParams(window.location.search).get("engine") ?? undefined
    : undefined;
  const activePath = targetMatch
    ? "/inventory"
    : scanMatch
      ? "/scans"
      : templateMatch
        ? "/templates"
        : router.pathname;
  // The primary nav, built once so it can go either in the bar below or into
  // the top bar of a view that renders its own AppShell.
  const tabs = TABS.map((tab) =>
    router.renderLink({
      key: tab.path,
      to: tab.path,
      children: tab.label,
      className: `rounded-t-md border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
        activePath === tab.path
          ? "border-primary text-foreground"
          : "border-transparent text-muted-foreground hover:text-foreground"
      }`,
    }),
  );
  const taskButton = (
    <TaskManagerButton
      basePath="/api/v1"
      tasksHref="/tasks"
      onNavigate={(href) => router.navigate(href)}
    />
  );

  // Which routes own their chrome. Only the scan detail view does so far; the
  // rest still get the standalone nav bar below.
  const ownsShell = Boolean(scanMatch);

  const content = taskMatch ? (
    <TasksView
      selectedId={taskMatch[1] ? decodeURIComponent(taskMatch[1]) : undefined}
      onSelectRun={(id) => router.navigate(id ? `/tasks/${encodeURIComponent(id)}` : "/tasks")}
    />
  ) : targetMatch ? (
    <TargetView id={decodeURIComponent(targetMatch[1])} onBack={() => router.navigate("/inventory")} />
  ) : scanMatch ? (
    <ScanDetailView
      id={decodeURIComponent(scanMatch[1])}
      onBack={() => router.navigate("/scans")}
      tabs={tabs}
      taskButton={taskButton}
    />
  ) : router.pathname === "/inventory" ? (
    <InventoryView
      onOpenTarget={(id) => router.navigate(`/inventory/${encodeURIComponent(id)}`)}
      onOpenScan={(id) => router.navigate(`/scans/${encodeURIComponent(id)}`)}
    />
  ) : router.pathname === "/scans" ? (
    <ScansView onOpenScan={(id) => router.navigate(`/scans/${encodeURIComponent(id)}`)} />
  ) : router.pathname === "/profiles" ? (
    <ProfilesView
      onBrowseTemplates={(profile) =>
        router.navigate(`/templates/${encodeURIComponent(profile)}`)
      }
    />
  ) : templateMatch ? (
    // The profile is in the path rather than in component state, so "these are
    // the templates the k8s profile runs" is a link someone can send — the same
    // reason a target and a scan are addressable.
    <TemplatesView
      engine={templateEngine}
      profile={templateMatch[1] ? decodeURIComponent(templateMatch[1]) : undefined}
      onSelectEngine={(engine) =>
        router.navigate(engine ? `/templates?engine=${encodeURIComponent(engine)}` : "/templates")
      }
      onSelectProfile={(profile) =>
        router.navigate(profile ? `/templates/${encodeURIComponent(profile)}` : "/templates")
      }
    />
  ) : router.pathname === "/" ? null : (
    <div className="p-6">
      <h1 className="text-lg font-semibold">Page not found</h1>
      <button className="mt-3 text-sm text-primary underline" onClick={() => router.navigate("/inventory")}>
        Return to inventory
      </button>
    </div>
  );

  return (
    <div className="flex h-full flex-col bg-background text-foreground">
      {/* A view that renders its own AppShell takes the tabs into its top bar
          instead, so the page has one header band rather than this one stacked
          above the shell's. */}
      {!ownsShell && (
        <nav className="flex items-center gap-1 border-b border-border px-4 pt-2">
          {tabs}
          <div className="ml-auto pb-2">{taskButton}</div>
        </nav>
      )}
      <div className="min-h-0 flex-1">{content}</div>
    </div>
  );
}
