import { useMemo } from "react";
import {
  OperationEntityPage,
  createOperationsApiClient,
  getClickySurfaces,
  makeSurfaceDefinition,
  useOperations,
} from "@flanksource/clicky-ui/rpc";

const apiClient = createOperationsApiClient();

export function FindingEntityPage({ id }: { id: string }) {
  const { spec, isLoading } = useOperations(apiClient);
  const surface = useMemo(
    () => getClickySurfaces(spec).find((candidate) => candidate.key === "finding"),
    [spec],
  );

  if (!surface) {
    return (
      <div className="p-6 text-sm text-muted-foreground">
        {isLoading ? "Loading finding…" : "Finding surface unavailable."}
      </div>
    );
  }

  return (
    <div className="h-full min-h-0 p-6">
      <OperationEntityPage
        definition={makeSurfaceDefinition(surface)}
        entities={[surface.entity]}
        client={apiClient}
        surfaceKey={surface.key}
        id={id}
        backHref="/findings"
        backLabel="Back to findings"
      />
    </div>
  );
}
