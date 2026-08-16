// Command harness verifies the browser half of remote access without guacd.
//
//	go run ./internal/rac/harness
//	open http://127.0.0.1:4830
//
// # What it is for
//
// The server side of remote access can be tested in Go. The browser side
// cannot: whether the display renders, whether the keyboard reaches the far
// end, whether an image stream decodes -- those are answered by looking at a
// page. Doing that normally needs a real guacd and a real machine to connect
// to, which is a lot of apparatus to keep working, and which nobody sets up
// when they are changing one line of JavaScript.
//
// So this stands in for both: a fake guacd that draws a recognisable scene, and
// a server that runs the REAL rac.Proxy and serves the REAL page and script. It
// is deliberately not a copy of them -- a harness that reimplements what it
// tests will agree with itself while production is broken.
//
// # What it does not prove
//
// The fake speaks the handshake faithfully and does not speak RDP, VNC or SSH.
// Nothing here says those work. It also has no authentication, no policy and no
// database, because those are exactly the parts that Go tests cover well.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"signari.dev/engine/internal/rac"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4830", "where to serve the harness")
	flag.Parse()

	guacd, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			conn, err := guacd.Accept()
			if err != nil {
				return
			}
			go fakeGuacd(conn)
		}
	}()
	log.Printf("fake guacd on %s", guacd.Addr())

	var seen input
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", rac.ViewCSP)
		_ = rac.ViewPage.Execute(w, map[string]any{
			"Slug": "harness", "Name": "Harness", "Protocol": "fake",
		})
	})
	mux.HandleFunc("GET /rac.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = io.WriteString(w, rac.ClientJS)
	})
	mux.HandleFunc("GET /static/guacamole-common.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = io.Copy(w, rac.LibraryJS())
	})

	// What the browser sent back, so a test can assert on input without
	// scraping a log.
	mux.HandleFunc("GET /harness/input", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, seen.json())
	})

	mux.HandleFunc("GET /rac/connect/{slug}", func(w http.ResponseWriter, r *http.Request) {
		guac, err := rac.Dial(guacd.Addr().String(), rac.Connection{
			Protocol: "rdp",
			Parameters: map[string]string{
				"hostname": "harness.invalid", "port": "3389",
				"username": "harness", "password": "unused",
			},
			Width:  atoiOr(r.URL.Query().Get("width"), 1024),
			Height: atoiOr(r.URL.Query().Get("height"), 768),
			DPI:    atoiOr(r.URL.Query().Get("dpi"), 96),
		}, 5*time.Second)
		if err != nil {
			log.Printf("dial: %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = guac.Close() }()

		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"guacamole"},
		})
		if err != nil {
			log.Printf("upgrade: %v", err)
			return
		}
		log.Printf("connected, guacd id %s", guac.ID)
		reason := rac.Proxy(r.Context(), &recordingPeer{ws: ws, seen: &seen}, guac)
		log.Printf("session ended: %s", reason)
		_ = ws.Close(websocket.StatusNormalClosure, "")
	})

	log.Printf("harness on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// recordingPeer is the production adapter plus a note of what came back.
type recordingPeer struct {
	ws   *websocket.Conn
	seen *input
}

func (p *recordingPeer) ReadMessage(ctx context.Context) ([]byte, error) {
	typ, data, err := p.ws.Read(ctx)
	if err != nil {
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
			return nil, rac.NormalClose
		}
		return nil, err
	}
	if typ != websocket.MessageText {
		return nil, fmt.Errorf("client sent a binary frame")
	}
	p.seen.record(data)
	return data, nil
}

func (p *recordingPeer) WriteMessage(ctx context.Context, data []byte) error {
	err := p.ws.Write(ctx, websocket.MessageText, data)
	if err != nil && websocket.CloseStatus(err) == websocket.StatusNormalClosure {
		return rac.NormalClose
	}
	return err
}

// input counts the opcodes the browser sent.
type input struct {
	mu     sync.Mutex
	counts map[string]int
	last   []string
}

func (i *input) record(data []byte) {
	r := rac.NewReader(bytes.NewReader(data))
	for {
		in, err := r.ReadInstruction()
		if err != nil {
			return
		}
		i.mu.Lock()
		if i.counts == nil {
			i.counts = map[string]int{}
		}
		i.counts[in.Opcode]++
		i.last = append(i.last, in.Opcode+" "+strings.Join(in.Args, ","))
		if len(i.last) > 20 {
			i.last = i.last[len(i.last)-20:]
		}
		i.mu.Unlock()
	}
}

func (i *input) json() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	var b strings.Builder
	b.WriteString(`{"counts":{`)
	first := true
	for k, v := range i.counts {
		if !first {
			b.WriteByte(',')
		}
		first = false
		fmt.Fprintf(&b, "%q:%d", k, v)
	}
	b.WriteString(`},"last":[`)
	for n, s := range i.last {
		if n > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q", s)
	}
	b.WriteString(`]}`)
	return b.String()
}

// fakeGuacd speaks the handshake and then draws.
func fakeGuacd(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r, w := rac.NewReader(conn), rac.NewWriter(conn)

	sel, err := r.ReadInstruction()
	if err != nil || sel.Opcode != "select" {
		return
	}
	// The parameter list a real guacd sends for RDP, in its order.
	params := []string{"hostname", "port", "domain", "username", "password",
		"width", "height", "dpi", "recording-path", "create-recording-path"}
	_ = w.Write(rac.Instruction{Opcode: "args", Args: params})

	for {
		in, err := r.ReadInstruction()
		if err != nil {
			return
		}
		if in.Opcode != "connect" {
			continue
		}
		_ = w.Write(rac.Instruction{Opcode: "ready", Args: []string{"$harness-0001"}})
		draw(conn)

		for {
			in, err := r.ReadInstruction()
			if err != nil {
				return
			}
			if in.Opcode == "disconnect" {
				log.Print("  browser disconnected")
				return
			}
		}
	}
}

const (
	over  = "14" // Guacamole.Layer.OVER
	layer = "0"  // the default layer
)

// draw sends a scene in ONE write.
//
// One write on purpose: a real guacd emits a burst of instructions per frame
// with no regard for packet boundaries, and a single large burst is what catches
// a proxy that forwards arbitrary chunks instead of whole instructions.
func draw(conn net.Conn) {
	const w, h = 800, 600
	var b strings.Builder
	add := func(op string, args ...string) {
		b.WriteString(rac.Instruction{Opcode: op, Args: args}.String())
	}

	add("size", layer, itoa(w), itoa(h))
	add("name", "Harness Desktop")

	add("rect", layer, "0", "0", itoa(w), itoa(h))
	add("cfill", over, layer, "39", "39", "42", "255")

	// Three bars, left to right: red, green, blue.
	for i, c := range [][3]string{
		{"239", "68", "68"}, {"34", "197", "94"}, {"59", "130", "246"},
	} {
		add("rect", layer, itoa(40+i*130), "60", "110", "160")
		add("cfill", over, layer, c[0], c[1], c[2], "255")
	}

	// A PNG through an image stream: img -> blob -> end. This is how a real
	// desktop's pixels arrive, so it is the part most worth exercising.
	add("img", "1", over, layer, "image/png", "40", "280")
	add("blob", "1", base64.StdEncoding.EncodeToString(checkerPNG(320, 200, 20)))
	add("end", "1")

	add("sync", "1000")

	if _, err := io.WriteString(conn, b.String()); err != nil {
		log.Printf("  draw failed: %v", err)
		return
	}
	log.Printf("  drew a scene (%d bytes in one write)", b.Len())
}

// checkerPNG is deliberately a checkerboard: something that is obviously right
// or obviously wrong in a screenshot, rather than a gradient that looks
// plausible either way.
func checkerPNG(w, h, cell int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if (x/cell+y/cell)%2 == 0 {
				img.Set(x, y, color.RGBA{250, 204, 21, 255}) // amber
			} else {
				img.Set(x, y, color.RGBA{24, 24, 27, 255}) // near-black
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func itoa(n int) string { return strconv.Itoa(n) }

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}
