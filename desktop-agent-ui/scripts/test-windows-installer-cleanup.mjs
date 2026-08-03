import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const hooks = await readFile(
  new URL("../src-tauri/windows/installer-hooks.nsh", import.meta.url),
  "utf8"
);
const wix = await readFile(
  new URL("../src-tauri/windows/fragments/agent-service.wxs", import.meta.url),
  "utf8"
);

for (const root of ["$APPDATA", "$LOCALAPPDATA"]) {
  assert.ok(
    hooks.includes(`!insertmacro PPAASS_REMOVE_AGENT_CONFIG_ROOT ${root}`),
    `${root} must be cleaned by the NSIS installer`
  );
}
assert.ok(hooks.includes("com.ppaass.agent\\agent.toml"));
function macroBody(name) {
  const match = new RegExp(`!macro ${name}([\\s\\S]*?)!macroend`).exec(hooks);
  assert.ok(match, `${name} must exist`);
  return match[1];
}
assert.match(macroBody("NSIS_HOOK_PREINSTALL"), /PPAASS_REMOVE_AGENT_CONFIG/);
assert.match(macroBody("NSIS_HOOK_POSTINSTALL"), /PPAASS_INSTALL_AGENT_SERVICE/);
assert.match(macroBody("NSIS_HOOK_PREUNINSTALL"), /PPAASS_REMOVE_AGENT_CONFIG/);
assert.doesNotMatch(hooks, /RMDir\s+\/r/i);
const installService = macroBody("PPAASS_INSTALL_AGENT_SERVICE");
assert.match(installService, /desktop-agent-ui\.exe/);
assert.match(installService, /--ppaass-install-service/);
assert.match(installService, /--ppaass-service-config-root/);
assert.match(installService, /Test-Path -LiteralPath \$\$configRoot -PathType Container/);

for (const directory of ["AppDataFolder", "LocalAppDataFolder"]) {
  assert.match(wix, new RegExp(`<Directory Id="${directory}">`));
}
assert.equal(
  wix.match(/<RemoveFile[\s\S]*?Name="agent\.toml"[\s\S]*?On="both"[\s\S]*?\/>/g)
    ?.length,
  2
);
assert.doesNotMatch(wix, /<RemoveFile[\s\S]*?Name="\*"/);
assert.match(wix, /Directory="PpaassRoamingDataDir"/);
assert.match(wix, /Directory="PpaassLocalDataDir"/);

console.log("Windows installer configuration cleanup tests passed");
