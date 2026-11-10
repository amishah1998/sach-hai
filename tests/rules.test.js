// Offline check of the scam rules in index.html. No network, no API key, no dependencies.
// Run from the repo root:  node tests/rules.test.js
// "fake": the rules alone must flag it. "notFake": real messages the rules must never flag.
const fs = require("fs"), path = require("path"), vm = require("vm");

const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
const script = html.slice(html.lastIndexOf("<script>") + 8, html.lastIndexOf("</script>"));
const cases = JSON.parse(fs.readFileSync(path.join(__dirname, "rules-cases.json"), "utf8"));

// The page script touches the DOM at load; give it inert stand-ins.
const el = () => ({ value: "", textContent: "", innerHTML: "", style: {}, dataset: {},
  classList: { add() {}, remove() {}, toggle() {} }, setAttribute() {}, focus() {}, addEventListener() {} });
const els = {};
const ctx = {
  console, setTimeout, clearTimeout, URLSearchParams,
  atob: s => Buffer.from(s, "base64").toString("latin1"),
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  location: { href: "http://localhost/", search: "" },
  document: { getElementById: id => els[id] || (els[id] = el()), querySelectorAll: () => [], documentElement: {}, head: { appendChild() {} } },
};
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(script, ctx);
const { ruleCheck } = ctx.SachHai;

let failed = 0;
for (const c of cases) {
  const r = ruleCheck(c.text);
  const flagged = r.score >= 3;
  const ok = c.expect === "fake" ? flagged : !flagged;
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"}  ${c.id.padEnd(20)} score=${r.score} rules=${r.ids.join(",") || "-"}`);
}
console.log(`\n${cases.length - failed}/${cases.length} passed`);
process.exit(failed ? 1 : 0);
