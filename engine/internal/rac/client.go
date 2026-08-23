package rac

import (
	_ "embed"
	"io"
	"strings"
)

// The browser half of remote access.
//
// It lives here, beside the protocol and the proxy, because it is the other end
// of the same conversation: the framing rule in ReadFrame exists because of how
// the code in ClientJS parses what it receives, and separating them would put a
// contract and its only consumer in different packages.
//
// Keeping it here also means a harness can serve the identical page and script
// that production serves, without an HTTP server, a database or a signed-in
// user -- see internal/rac/harness.
//
// # Why this one page carries a dependency
//
// Everywhere else in this engine the browser code is hand-written, and the
// sign-in page carries none at all, because a dependency there runs where the
// session cookie lives. This is the deliberate exception; static/PROVENANCE.md
// gives the reasoning. In short: the library is the counterpart of guacd, from
// the same project, versioned against the daemon that already holds the
// credentials for every host in the estate.

//go:embed static/guacamole-common.js
var libraryJS string

// LibraryJS is the vendored Guacamole client, served as published.
func LibraryJS() io.ReadSeeker { return strings.NewReader(libraryJS) }

// ClientJS is the glue between that library and this engine.
//
// A module, because the library is an ES module. No build step: nothing is
// bundled, minified or transpiled.
const ClientJS = `"use strict";
import Guacamole from "/static/guacamole-common.js";

// The slug rides on #screen rather than on <body>, because the viewer's markup
// lives in the shared page set now and the layout there owns the <body> tag.
// An element the content block owns is the only place a page can put it.
const screen = document.getElementById("screen");
const status = document.getElementById("status");
const slug = screen.dataset.slug;

// A visible reason for everything.
//
// The worst failure mode for a remote desktop is a black rectangle: the user
// cannot tell a policy refusal from a dead host from a bug, and neither can the
// person they report it to. Every state change says something.
function say(text, kind) {
  status.textContent = text;
  status.className = kind || "";
  status.hidden = false;
}
function clearStatus() { status.hidden = true; }

const scheme = location.protocol === "https:" ? "wss:" : "ws:";
const tunnel = new Guacamole.WebSocketTunnel(
  scheme + "//" + location.host + "/rac/connect/" + encodeURIComponent(slug));
const client = new Guacamole.Client(tunnel);
const display = client.getDisplay();

screen.appendChild(display.getElement());

// The display arrives at whatever size the remote host chose. Scale it to fit
// rather than clipping it, so a 1920-wide desktop is usable in a smaller window.
function fit() {
  const w = display.getWidth(), h = display.getHeight();
  if (!w || !h) return;
  display.scale(Math.min(screen.clientWidth / w, screen.clientHeight / h, 1));
}
display.onresize = fit;
window.addEventListener("resize", fit);

tunnel.onerror = function (status) {
  say("The connection failed: " + status.message + " (" + status.code + ")", "err");
};

client.onerror = function (status) {
  say("The remote session ended: " + status.message, "err");
};

client.onstatechange = function (state) {
  const States = Guacamole.Client.State;
  if (state === States.CONNECTING) say("Connecting…");
  else if (state === States.WAITING) say("Waiting for the remote host…");
  else if (state === States.CONNECTED) { clearStatus(); fit(); }
  else if (state === States.DISCONNECTED) say("Disconnected.", "err");
};

// Input.
//
// The mouse is bound to the display element and the keyboard to the document,
// which is what makes keystrokes reach the remote host without the user having
// to click into a particular box first.
const mouse = new Guacamole.Mouse(display.getElement());
mouse.onEach(["mousedown", "mouseup", "mousemove"], function (e) {
  client.sendMouseState(e.state, true);
});

const keyboard = new Guacamole.Keyboard(document);
keyboard.onkeydown = function (sym) { client.sendKeyEvent(1, sym); };
keyboard.onkeyup = function (sym) { client.sendKeyEvent(0, sym); };

// guacd draws the remote cursor itself, so a local one would be a second
// pointer trailing the first.
display.showCursor(false);
display.getElement().style.cursor = "none";

// Release every held key when the tab loses focus. Without this, alt-tabbing
// away leaves Alt down on the remote host, and the next keystroke there is a
// menu accelerator rather than a letter.
window.addEventListener("blur", function () { keyboard.reset(); });
window.addEventListener("pagehide", function () { client.disconnect(); });

document.getElementById("disconnect").addEventListener("click", function () {
  client.disconnect();
  say("Disconnected.", "");
});

say("Connecting…");
client.connect(
  "width=" + Math.floor(screen.clientWidth) +
  "&height=" + Math.floor(screen.clientHeight) +
  "&dpi=" + Math.round(96 * (window.devicePixelRatio || 1)));
`

// The viewer's markup is internal/pages/files/racview.html, not a literal here.
//
// The element ids in it -- screen, status, disconnect -- and its data-slug are
// the contract ClientJS above depends on: a rename on either side is a blank
// screen from the other. Keeping the markup with the other pages is what makes
// the viewer themeable and what lets `signari theme check` see it at all; the
// cost is that the contract now spans two files, so ViewContract names the ids
// and a test holds the page to them.

// ViewContract is what racview.html must contain for ClientJS to work.
//
// It exists because the markup and the script are no longer in the same file.
var ViewContract = []string{`id="screen"`, `id="status"`, `id="disconnect"`, "data-slug"}

// ViewCSP is the policy the viewer needs, and no more.
//
// script-src 'self' because the library and the glue are both served from here
// and neither is inline; connect-src for the WebSocket; img-src data: and blob:
// because the display decodes image streams into both.
const ViewCSP = `default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; ` +
	`connect-src 'self'; img-src 'self' data: blob:; frame-ancestors 'none'`
