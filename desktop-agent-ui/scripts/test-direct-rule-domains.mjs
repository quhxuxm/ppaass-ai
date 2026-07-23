import assert from "node:assert/strict";
import {
  directRuleCoversDomain,
  domainsToDirectRules,
  domainToDirectRule
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

console.log("directRuleDomains tests passed");
