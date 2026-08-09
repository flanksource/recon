import { describe, expect, it } from "vitest";
import { discoverDnsRecords, type DnsResolver } from "./dns-discovery.ts";

describe("DNS discovery", () => {
  it("normalises and deduplicates NS and MX targets across configured zones", async () => {
    const resolver: DnsResolver = {
      resolveNs: async (zone) =>
        zone === "example.com"
          ? ["NS1.EXAMPLE.COM.", "ns2.example.net."]
          : ["ns1.example.com"],
      resolveMx: async () => [
        { exchange: "MAIL.EXAMPLE.COM.", priority: 10 },
        { exchange: "backup.example.net", priority: 20 },
      ],
    };

    await expect(
      discoverDnsRecords([" Example.com. ", "apps.example.com"], resolver),
    ).resolves.toEqual({
      hosts: [
        "backup.example.net",
        "mail.example.com",
        "ns1.example.com",
        "ns2.example.net",
      ],
      nameservers: ["ns1.example.com", "ns2.example.net"],
      mailExchanges: ["backup.example.net", "mail.example.com"],
      failures: [],
    });
  });

  it("keeps successful record types and reports DNS query failures", async () => {
    const resolver: DnsResolver = {
      resolveNs: async () => {
        throw new Error("query timed out");
      },
      resolveMx: async () => [{ exchange: "mail.example.com.", priority: 10 }],
    };

    await expect(discoverDnsRecords(["example.com"], resolver)).resolves.toEqual({
      hosts: ["mail.example.com"],
      nameservers: [],
      mailExchanges: ["mail.example.com"],
      failures: [
        { zone: "example.com", recordType: "NS", error: "query timed out" },
      ],
    });
  });

  it("does not turn a null MX root exchange into a discovery host", async () => {
    const resolver: DnsResolver = {
      resolveNs: async () => ["ns.example.net"],
      resolveMx: async () => [{ exchange: ".", priority: 0 }],
    };

    await expect(discoverDnsRecords(["example.com"], resolver)).resolves.toEqual({
      hosts: ["ns.example.net"],
      nameservers: ["ns.example.net"],
      mailExchanges: [],
      failures: [],
    });
  });
});
