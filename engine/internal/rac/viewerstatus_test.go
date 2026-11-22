package rac_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"signari.dev/engine/internal/rac"
)

// What a person reads when guacd refuses is what guacd said, not "Disconnected."
//
// The library ends a refused session by calling onerror and then disconnect(), and
// the viewer answered the DISCONNECTED that follows by writing over the reason. So a
// wrong password, an untrusted certificate and an unreachable host all read
// "Disconnected.", which is the black-rectangle failure this viewer exists to avoid.
// Found against a real guacd (November 2026), where the reason was on screen for no
// time at all.
//
// The viewer's own script is run, under node, against a library stubbed to do what
// the vendored one does in that order (static/guacamole-common.js, Client's
// "error" handler and disconnect()). Skipped loudly without node.
func TestTheViewerKeepsTheReasonASessionEnded(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; the viewer's script is not run here")
	}
	const imported = `import Guacamole from "/static/guacamole-common.js";`
	module := strings.Replace(rac.ClientJS, imported, "const Guacamole = globalThis.Guacamole;", 1)
	if module == rac.ClientJS {
		t.Fatal("the viewer no longer imports the library the way this test replaces")
	}
	dir := t.TempDir()
	client := filepath.Join(dir, "client.mjs")
	runner := filepath.Join(dir, "run.mjs")
	if err := os.WriteFile(client, []byte(module), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runner, []byte(viewerRunner), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct{ scenario, want string }{
		{"guacd-refused", "The remote session ended: Aborted. See logs."},
		// guacd sent no reason, which against a real one was about half the refused RDP sessions.
		{"refused-silently", "The session ended before it started, and no reason was given."},
		{"closed", "Disconnected."},
		{"button", "Disconnected."},
	} {
		out, err := exec.Command("node", runner, client, c.scenario).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", c.scenario, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != c.want {
			t.Errorf("%s: the viewer says %q, want %q", c.scenario, got, c.want)
		}
	}
}

// The page and the library, as little of each as the viewer touches.
const viewerRunner = `import { pathToFileURL } from "node:url";
function el(extra) {
  return Object.assign({ style: {}, dataset: {}, hidden: false, textContent: "", className: "",
    listeners: {}, appendChild(c) { return c; }, remove() {}, focus() {},
    addEventListener(type, fn) { this.listeners[type] = fn; } }, extra);
}
const elements = { screen: el({ dataset: { slug: "desk" }, clientWidth: 800, clientHeight: 600 }),
  status: el(), disconnect: el() };
globalThis.document = { getElementById: (id) => elements[id] || el(), createElement: () => el(),
  addEventListener() {} };
globalThis.window = { addEventListener() {}, devicePixelRatio: 1 };
globalThis.location = { protocol: "http:", host: "localhost" };

class Client {
  constructor() { this.state = 0; globalThis.__client = this; }
  setState(s) { this.state = s; if (this.onstatechange) this.onstatechange(s); }
  getDisplay() {
    return { getElement: () => el(), getWidth: () => 0, getHeight: () => 0, scale() {}, showCursor() {} };
  }
  connect() { this.setState(1); this.setState(2); }
  // As the vendored library's: DISCONNECTING, then DISCONNECTED, unless already there.
  disconnect() { if (this.state !== 4 && this.state !== 5) { this.setState(4); this.setState(5); } }
  sendMouseState() {}
  sendKeyEvent() {}
  createArgumentValueStream() { return {}; }
}
Client.State = { IDLE: 0, CONNECTING: 1, WAITING: 2, CONNECTED: 3, DISCONNECTING: 4, DISCONNECTED: 5 };
class Status { constructor(code, message) { this.code = code; this.message = message; } }
globalThis.Guacamole = { Client, Status, WebSocketTunnel: class {}, Mouse: class { onEach() {} },
  Keyboard: class { reset() {} }, StringWriter: class { sendText() {} sendEnd() {} } };

await import(pathToFileURL(process.argv[2]).href);
const client = globalThis.__client;
switch (process.argv[3]) {
case "guacd-refused":
  // The library's "error" instruction: onerror, then disconnect().
  client.onerror(new Status(0x0201, "Aborted. See logs."));
  client.disconnect();
  break;
case "refused-silently":
  client.disconnect();
  break;
case "closed":
  client.setState(3);
  client.disconnect();
  break;
case "button":
  elements.disconnect.listeners.click();
  break;
}
console.log(elements.status.textContent);
`
