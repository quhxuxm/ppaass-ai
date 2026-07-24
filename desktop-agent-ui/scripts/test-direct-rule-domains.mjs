import assert from "node:assert/strict";
import {
  directRuleCoversDomain,
  domainsAndAddressesToDirectRules,
  domainsToDirectRules,
  domainToDirectRule,
  isIpAddress
} from "../src/directRuleDomains.ts";

assert.equal(domainToDirectRule("api.example.com"), "*.example.com");
assert.equal(domainToDirectRule("a.service.example.com."), "*.service.example.com");
assert.equal(domainToDirectRule("example.com"), "example.com");
assert.equal(domainToDirectRule("foo.co.uk"), "foo.co.uk");
assert.equal(domainToDirectRule("tenant.github.io"), "tenant.github.io");
assert.deepEqual(
  domainsToDirectRules(["api.example.com", "www.example.com", "example.net"]),
  ["*.example.com", "example.net"]
);
assert.equal(directRuleCoversDomain("*.example.com", "api.example.com"), true);
assert.equal(directRuleCoversDomain("*.example.com", "example.com"), false);
assert.equal(directRuleCoversDomain("example.com", "EXAMPLE.COM."), true);
assert.equal(isIpAddress("203.0.113.8"), true);
assert.equal(isIpAddress("2001:db8::8"), true);
assert.equal(isIpAddress("203.0.113.999"), false);
assert.equal(isIpAddress("edge.example.com"), false);
assert.deepEqual(
  domainsAndAddressesToDirectRules(
    ["api.example.com"],
    ["203.0.113.8", "2001:db8::8", "alias.example.com", "203.0.113.8"]
  ),
  ["*.example.com", "203.0.113.8", "2001:db8::8"]
);

console.log("directRuleDomains tests passed");
