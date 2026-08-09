import { describe, expect, it } from "vitest";
import {
  buildDiscoveryObservations,
  discoveryCommands,
} from "./discovery-profile.ts";

describe("discovery profile", () => {
  it("runs bounded Naabu discovery before probing every open endpoint with httpx", () => {
    expect(discoveryCommands(".gen/targets.txt")).toEqual({
      naabu: {
        command: "naabu",
        args: [
          "-config",
          "config/discovery.naabu.yaml",
          "-silent",
          "-json",
          "-no-color",
          "-disable-update-check",
          "-no-stdin",
          "-l",
          ".gen/targets.txt",
        ],
      },
      httpx: {
        command: "httpx",
        args: [
          "-config",
          "config/discovery.httpx.yaml",
          "-silent",
          "-json",
          "-no-color",
          "-disable-update-check",
        ],
      },
    });
  });

  it("aggregates ports, known paths, latency, status, and login methods per host", () => {
    const observations = buildDiscoveryObservations({
      hosts: ["api.example.com"],
      naabu: [
        { host: "api.example.com", ip: "192.0.2.10", port: 443 },
        { host: "api.example.com", ip: "192.0.2.10", port: 8443 },
      ],
      httpx: [
        {
          input: "api.example.com:443",
          host: "api.example.com",
          url: "https://api.example.com",
          scheme: "https",
          port: "443",
          path: "/",
          status_code: 404,
          time: "410ms",
        },
        {
          input: "api.example.com:8443",
          host: "api.example.com",
          url: "https://api.example.com:8443",
          scheme: "https",
          port: "8443",
          path: "/",
          status_code: 200,
          time: "125ms",
          header: { "www-authenticate": "Basic realm=\"admin\"" },
        },
      ],
      paths: [
        {
          host: "api.example.com",
          url: "https://api.example.com:8443/login",
          path: "/login",
          status_code: 200,
          time: "150ms",
          location: "/oauth2/authorize",
        },
        {
          host: "api.example.com",
          url: "https://api.example.com:8443/.well-known/openid-configuration",
          path: "/.well-known/openid-configuration",
          status_code: 200,
          time: "140ms",
        },
        {
          host: "api.example.com",
          url: "https://api.example.com:8443/signin",
          path: "/signin",
          status_code: 404,
          time: "145ms",
        },
      ],
    });

    expect(observations).toEqual([
      expect.objectContaining({
        input: "api.example.com",
        url: "https://api.example.com:8443",
        status_code: 200,
        time: "125ms",
        open_ports: [443, 8443],
        known_paths: ["/", "/.well-known/openid-configuration", "/login"],
        login_methods: ["Basic", "OAuth 2.0", "OpenID Connect", "Web login"],
      }),
    ]);
    expect(observations[0]).not.toHaveProperty("header");
  });

  it("retains non-HTTP open ports and reports completely unresponsive hosts", () => {
    expect(
      buildDiscoveryObservations({
        hosts: ["db.example.com", "down.example.com"],
        naabu: [{ host: "db.example.com", port: 5432 }],
        httpx: [],
        paths: [],
      }),
    ).toEqual([
      { input: "db.example.com", open_ports: [5432] },
      {
        input: "down.example.com",
        failed: true,
        error: "no open ports or HTTP endpoints responded",
      },
    ]);
  });
});
