import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createInventoryStore } from "./inventory-store.ts";

const NUCLEI_DIR = resolve(import.meta.dirname, "..", "..");
const INVENTORY_DIR = resolve(NUCLEI_DIR, "inventory");
const ARGS = process.argv.slice(2).filter((argument, index) => argument !== "--" || index > 0);

function option(name: string): string | undefined {
  const index = ARGS.indexOf(name);
  return index === -1 ? undefined : ARGS[index + 1];
}

function requiredOption(name: string): string {
  const value = option(name);
  if (!value) throw new Error(`missing required option: ${name}`);
  return resolve(process.cwd(), value);
}

function jsonLines(path: string): unknown[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line, index) => {
      try {
        return JSON.parse(line) as unknown;
      } catch (error) {
        throw new Error(`${path}:${index + 1}: ${(error as Error).message}`);
      }
    });
}

function output(value: unknown): void {
  process.stdout.write(`${typeof value === "string" ? value : JSON.stringify(value, null, 2)}\n`);
}

function main(): void {
  const command = ARGS[0];
  const store = createInventoryStore({ inventoryDir: INVENTORY_DIR });
  if (command === "validate") {
    const inventory = store.list();
    output({ valid: true, targets: inventory.rows.length, zones: inventory.zones.length });
    return;
  }
  if (command === "render") {
    output(store.render({ outputDir: resolve(NUCLEI_DIR, ".gen") }));
    return;
  }
  if (command === "merge-discovery") {
    const path = option("--input")
      ? requiredOption("--input")
      : resolve(NUCLEI_DIR, ".gen", "discovered.json");
    output(store.mergeDiscovery(jsonLines(path)));
    return;
  }
  if (command === "record-scan") {
    const hosts = readFileSync(requiredOption("--list"), "utf8")
      .split("\n")
      .filter((host) => host.length > 0);
    store.recordScan({ hosts, resultPath: requiredOption("--result") });
    output({ updated: hosts.length });
    return;
  }
  if (command === "zones") {
    output(store.list().zones.join("\n"));
    return;
  }
  if (command === "known") {
    output(store.list().rows.map((target) => target.host).join("\n"));
    return;
  }
  throw new Error(
    "usage: pnpm inventory -- <validate|render|merge-discovery|record-scan|zones|known>",
  );
}

main();
