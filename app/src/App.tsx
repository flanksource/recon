import { useEffect, useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TaskManagerButton } from "@flanksource/clicky-ui/data";
import { useBrowserRouter } from "@flanksource/clicky-ui/rpc";
import { InventoryView } from "./TargetsView";
import { ScanDetailView, ScansView } from "./ScansView";
import { MutesView } from "./MutesView";
import { ProfilesView } from "./ProfilesView";
import { ReportPlayground } from "./ReportPlayground";
import { ResourcesView } from "./ResourcesView";
import { FindingsView } from "./FindingsView";
import { FindingEntityPage } from "./FindingEntityPage";
import { ResourceView } from "./ResourceView";
import { TargetView } from "./TargetView";
import { TasksView } from "./TasksView";
import { TemplatesView } from "./TemplatesView";

const TABS = [
  { path: "/inventory", label: "Inventory" },
  // Second, beside Inventory, because it is inventory — the machine-enumerated
  // half. A target is curated by a person and a resource is found by a scan,
  // but both outlive any single run, which is what separates them from Scans.
  { path: "/resources", label: "Resources" },
  { path: "/findings", label: "Findings" },
  { path: "/scans", label: "Scans" },
  { path: "/reports", label: "Reports" },
  { path: "/profiles", label: "Profiles" },
  { path: "/templates", label: "Templates" },
  { path: "/mutes", label: "Mutes" },
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
  // The run is optional: /reports opens on a sample so the report can be
  // designed before there is a run worth printing.
  const reportMatch = router.pathname.match(/^\/reports(?:\/([^/]+))?$/);
  const taskMatch = router.pathname.match(/^\/tasks(?:\/([^/]+))?$/);
  const templateMatch = router.pathname.match(/^\/templates(?:\/([^/]+))?$/);
  // A rule is addressable so it can be linked to, and `new` is a rule that does
  // not exist yet: muting a finding from the results is a link into a prefilled
  // draft rather than a second editor somewhere else.
  const muteMatch = router.pathname.match(/^\/mutes(?:\/([^/]+))?$/);
  // A resource is addressable so a finding can link to the thing it is about.
  const resourceMatch = router.pathname.match(/^\/resources(?:\/([^/]+))?$/);
  const findingMatch = router.pathname.match(/^\/findings\/([^/]+)$/);
  const templateEngine = templateMatch
    ? new URLSearchParams(window.location.search).get("engine") ?? undefined
    : undefined;
  const activePath = targetMatch
    ? "/inventory"
    : scanMatch
      ? "/scans"
      : reportMatch
        ? "/reports"
        : templateMatch
          ? "/templates"
          : muteMatch
            ? "/mutes"
            : resourceMatch
              ? "/resources"
              : findingMatch
                ? "/findings"
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

  // Which routes own their chrome. The scan detail view and the report
  // playground render their own AppShell; the rest still get the standalone nav
  // bar below.
  const ownsShell = Boolean(scanMatch || reportMatch);

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
      onOpenPlayground={(scanId) =>
        router.navigate(`/reports/${encodeURIComponent(scanId)}`)
      }
      onMuteFinding={(path) => router.navigate(path)}
      tabs={tabs}
      taskButton={taskButton}
    />
  ) : reportMatch ? (
    <ReportPlayground
      scanId={reportMatch[1] ? decodeURIComponent(reportMatch[1]) : undefined}
      onSelectScan={(scanId) =>
        router.navigate(scanId ? `/reports/${encodeURIComponent(scanId)}` : "/reports")
      }
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
  ) : findingMatch ? (
    <FindingEntityPage id={decodeURIComponent(findingMatch[1])} />
  ) : router.pathname === "/findings" ? (
    <FindingsView />
  ) : resourceMatch?.[1] ? (
    <ResourceView
      id={decodeURIComponent(resourceMatch[1])}
      onBack={() => router.navigate("/resources")}
      onMuteFinding={(path) => router.navigate(path)}
    />
  ) : resourceMatch ? (
    <ResourcesView
      onOpenResource={(id) => router.navigate(`/resources/${encodeURIComponent(id)}`)}
    />
  ) : muteMatch ? (
    <MutesView
      selected={muteMatch[1] ? decodeURIComponent(muteMatch[1]) : undefined}
      search={window.location.search}
      onSelect={(name) =>
        router.navigate(name ? `/mutes/${encodeURIComponent(name)}` : "/mutes")
      }
    />
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
