import { createRoot } from "react-dom/client";
import { ErrorWrapper } from "@flanksource/clicky-ui/components";
import { setFallbackIconProvider } from "@flanksource/clicky-ui/data";
import { clickyIconProvider } from "@flanksource/clicky-ui/icons";
import { AuthenticatedApp } from "./Auth";
import "@flanksource/clicky-ui/styles.css";
import "./index.css";

// Schema-driven icons carried as runtime name strings resolve through this set.
setFallbackIconProvider(clickyIconProvider());

const root = document.getElementById("root");
if (!root) throw new Error("#root not found");
createRoot(root).render(
  <ErrorWrapper>
    <AuthenticatedApp />
  </ErrorWrapper>,
);
