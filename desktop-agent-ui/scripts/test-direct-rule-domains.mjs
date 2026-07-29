import assert from "node:assert/strict";
import {
  directRuleCoversDomain,
  directRulesMatchingDomainsAndAddresses,
  domainsAndAddressesToDirectRules,
  domainsToDirectRules,
  domainToDirectRule,
  isIpAddress,
  selectedDomainsToNewDirectRules
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
assert.deepEqual(
  directRulesMatchingDomainsAndAddresses(
    [
      "*.example.com",
      "api.example.com",
      "203.0.113.8",
      "2001:DB8::8",
      "203.0.113.0/24",
      "*.other.example"
    ],
    ["api.example.com"],
    ["203.0.113.8", "2001:db8::8", "alias.example.com"]
  ),
  ["*.example.com", "api.example.com", "203.0.113.8", "2001:DB8::8"]
);
assert.deepEqual(
  directRulesMatchingDomainsAndAddresses(
    ["example.com", "*.example.com", "198.51.100.4"],
    ["example.com"],
    []
  ),
  ["example.com"]
);
assert.deepEqual(
  selectedDomainsToNewDirectRules(["new.example.com"], [], []),
  ["*.example.com"],
  "selected domains stay addable after their visible DNS record is refreshed away"
);
assert.deepEqual(
  selectedDomainsToNewDirectRules(
    ["direct.example.com", "new.example.net"],
    ["203.0.113.8"],
    ["*.example.com", "203.0.113.8"]
  ),
  ["*.example.net"],
  "covered domains and existing address rules are excluded"
);

console.log("directRuleDomains tests passed");
