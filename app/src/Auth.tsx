// The serving Recon process supplies Clerk's public runtime configuration, so
// one frontend build can be reused by every tenant deployment.
import { ClerkProvider, SignIn, UserButton, useAuth, useClerk } from "@clerk/react";
import { useEffect, useState, type ReactNode } from "react";
import { App } from "./App";

type PublicAuthConfig =
  | { enabled: false }
  | { enabled: true; publishableKey: string; organizationId: string };

type ConfigState =
  | { phase: "loading" }
  | { phase: "failed"; message: string }
  | { phase: "ready"; config: PublicAuthConfig };

/** Loads the non-secret Clerk settings before Clerk or the application mounts. */
async function loadAuthConfig(): Promise<PublicAuthConfig> {
  const response = await fetch("/api/auth/config");
  if (!response.ok) {
    throw new Error(`GET /api/auth/config failed: ${response.status}`);
  }

  const config = (await response.json()) as Partial<PublicAuthConfig>;
  if (config.enabled === false) return { enabled: false };
  if (
    config.enabled !== true ||
    typeof config.publishableKey !== "string" ||
    typeof config.organizationId !== "string"
  ) {
    throw new Error("GET /api/auth/config returned an invalid configuration");
  }
  return {
    enabled: true,
    publishableKey: config.publishableKey,
    organizationId: config.organizationId,
  };
}

/** Selects authenticated or local-only application startup from server config. */
export function AuthenticatedApp() {
  const [state, setState] = useState<ConfigState>({ phase: "loading" });

  useEffect(() => {
    let active = true;
    void loadAuthConfig()
      .then((config) => {
        if (active) setState({ phase: "ready", config });
      })
      .catch((error: unknown) => {
        if (active) {
          setState({
            phase: "failed",
            message: error instanceof Error ? error.message : String(error),
          });
        }
      });
    return () => {
      active = false;
    };
  }, []);

  if (state.phase === "loading") return <FullPageMessage>Loading Recon…</FullPageMessage>;
  if (state.phase === "failed") {
    return (
      <FullPageMessage title="Unable to load authentication configuration">
        {state.message}
      </FullPageMessage>
    );
  }
  if (!state.config.enabled) return <App />;

  return (
    <ClerkProvider publishableKey={state.config.publishableKey} afterSignOutUrl="/">
      <TenantGate organizationId={state.config.organizationId} />
    </ClerkProvider>
  );
}

function TenantGate({ organizationId }: { organizationId: string }) {
  const { isLoaded, isSignedIn } = useAuth();

  if (!isLoaded) return <FullPageMessage>Loading session…</FullPageMessage>;
  if (!isSignedIn) {
    return (
      <main className="flex h-full items-center justify-center bg-muted/30 p-6">
        <div className="flex flex-col items-center gap-6">
          <div className="text-center">
            <h1 className="text-2xl font-semibold text-foreground">Recon</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Sign in to access this tenant’s security inventory.
            </p>
          </div>
          <SignIn routing="hash" />
        </div>
      </main>
    );
  }

  return <OrganizationGate organizationId={organizationId} />;
}

function OrganizationGate({ organizationId }: { organizationId: string }) {
  const { orgId } = useAuth();
  const clerk = useClerk();
  const [activation, setActivation] = useState<"pending" | "failed">("pending");

  useEffect(() => {
    if (orgId === organizationId || activation === "failed") return;
    let active = true;
    void clerk
      .setActive({ organization: organizationId })
      .catch(() => {
        if (active) setActivation("failed");
      });
    return () => {
      active = false;
    };
  }, [activation, clerk, orgId, organizationId]);

  if (orgId === organizationId) {
    return <App accountControl={<UserButton />} />;
  }
  if (activation === "failed") {
    return (
      <FullPageMessage
        title="You do not have access to this Recon tenant"
        action={<UserButton />}
      >
        Ask the tenant administrator to add your Clerk user to this organization.
      </FullPageMessage>
    );
  }
  return <FullPageMessage>Connecting to tenant…</FullPageMessage>;
}

function FullPageMessage({
  title,
  children,
  action,
}: {
  title?: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <main className="flex h-full items-center justify-center bg-background p-6 text-foreground">
      <div className="flex max-w-md flex-col items-center gap-3 text-center">
        {title && <h1 className="text-xl font-semibold">{title}</h1>}
        <div className="text-sm text-muted-foreground">{children}</div>
        {action}
      </div>
    </main>
  );
}
