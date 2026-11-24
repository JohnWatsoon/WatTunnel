package panel

// A small QR encoder (ISO/IEC 18004): byte mode, error correction level M, versions 1-15 (up to 412 bytes),
// automatic mask. It draws the 2FA enrolment code (otpauth:// URI) and the panel URL, in the browser as SVG and in
// the manager as terminal half blocks. Written here instead of adding a module so the release keeps its
// dependency set; follows the structure of Project Nayuki's reference encoder.

import (
	"errors"
	"fmt"
	"strings"
)

// level M per version: EC codewords per block, then (blocks, data codewords) for group 1 and group 2.
var qrBlocksM = [16][5]int{
	{},
	{10, 1, 16, 0, 0}, {16, 1, 28, 0, 0}, {26, 1, 44, 0, 0}, {18, 2, 32, 0, 0}, {24, 2, 43, 0, 0},
	{16, 4, 27, 0, 0}, {18, 4, 31, 0, 0}, {22, 2, 38, 2, 39}, {22, 3, 36, 2, 37}, {26, 4, 43, 1, 44},
	{30, 1, 50, 4, 51}, {22, 6, 36, 2, 37}, {22, 8, 37, 1, 38}, {24, 4, 40, 5, 41}, {24, 5, 41, 5, 42},
}

var qrAlign = [16][]int{
	{}, {}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50},
	{6, 30, 54}, {6, 32, 58}, {6, 34, 62}, {6, 26, 46, 66}, {6, 26, 48, 70},
}

// QR is a square module matrix; true is dark. Index [y][x].
type QR [][]bool

// EncodeQR encodes text (byte mode, level M) in the smallest version that fits.
func EncodeQR(text string) (QR, error) {
	data := []byte(text)
	ver := 0
	for v := 1; v <= 15; v++ {
		b := qrBlocksM[v]
		capacity := b[1]*b[2] + b[3]*b[4]
		countBits := 8
		if v >= 10 {
			countBits = 16
		}
		if 4+countBits+8*len(data) <= capacity*8 {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, errors.New("qr: text too long")
	}
	b := qrBlocksM[ver]
	capacity := b[1]*b[2] + b[3]*b[4]
	countBits := 8
	if ver >= 10 {
		countBits = 16
	}
	// bit stream
	var bits []bool
	put := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, v>>i&1 == 1)
		}
	}
	put(4, 4)
	put(len(data), countBits)
	for _, c := range data {
		put(int(c), 8)
	}
	for i := 0; i < 4 && len(bits) < capacity*8; i++ {
		bits = append(bits, false)
	}
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	cw := make([]byte, 0, capacity)
	for i := 0; i < len(bits); i += 8 {
		var v byte
		for j := 0; j < 8; j++ {
			if bits[i+j] {
				v |= 1 << (7 - j)
			}
		}
		cw = append(cw, v)
	}
	for pad := byte(0xEC); len(cw) < capacity; pad ^= 0xEC ^ 0x11 {
		cw = append(cw, pad)
	}
	// blocks + error correction, then interleave
	gen := rsGenerator(b[0])
	var blocks, ecs [][]byte
	off := 0
	for g := 0; g < 2; g++ {
		for i := 0; i < b[1+2*g]; i++ {
			d := cw[off : off+b[2+2*g]]
			off += len(d)
			blocks = append(blocks, d)
			ecs = append(ecs, rsRemainder(d, gen))
		}
	}
	var final []byte
	for i := 0; i < b[4] || i < b[2]; i++ {
		for _, d := range blocks {
			if i < len(d) {
				final = append(final, d[i])
			}
		}
	}
	for i := 0; i < b[0]; i++ {
		for _, e := range ecs {
			final = append(final, e[i])
		}
	}
	return qrPlace(ver, final), nil
}

type qrGrid struct {
	n    int
	mod  [][]bool
	fn   [][]bool
	ver  int
	data []byte
}

func (g *qrGrid) set(x, y int, dark bool) { g.mod[y][x], g.fn[y][x] = dark, true }

func qrPlace(ver int, data []byte) QR {
	n := 17 + 4*ver
	g := &qrGrid{n: n, ver: ver, data: data}
	g.mod, g.fn = make([][]bool, n), make([][]bool, n)
	for i := range g.mod {
		g.mod[i], g.fn[i] = make([]bool, n), make([]bool, n)
	}
	for i := 0; i < n; i++ { // timing
		g.set(6, i, i%2 == 0)
		g.set(i, 6, i%2 == 0)
	}
	for _, c := range [][2]int{{3, 3}, {n - 4, 3}, {3, n - 4}} { // finders + separators
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := c[0]+dx, c[1]+dy
				if x < 0 || y < 0 || x >= n || y >= n {
					continue
				}
				d := max(abs(dx), abs(dy))
				g.set(x, y, d != 2 && d != 4)
			}
		}
	}
	al := qrAlign[ver]
	for i, ax := range al {
		for j, ay := range al {
			if (i == 0 && j == 0) || (i == 0 && j == len(al)-1) || (i == len(al)-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					g.set(ax+dx, ay+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	g.drawFormat(0) // reserve the format areas
	if ver >= 7 {
		rem := ver
		for i := 0; i < 12; i++ {
			rem = rem<<1 ^ (rem>>11)*0x1F25
		}
		v := ver<<12 | rem
		for i := 0; i < 18; i++ {
			bit := v>>i&1 == 1
			a, b := n-11+i%3, i/3
			g.set(a, b, bit)
			g.set(b, a, bit)
		}
	}
	// zigzag data placement
	i := 0
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < n; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = n - 1 - vert
				}
				if !g.fn[y][x] && i < len(data)*8 {
					g.mod[y][x] = data[i>>3]>>(7-i&7)&1 == 1
					i++
				}
			}
		}
	}
	best, bestScore := -1, 0
	for m := 0; m < 8; m++ {
		g.mask(m)
		g.drawFormat(m)
		if s := g.penalty(); best < 0 || s < bestScore {
			best, bestScore = m, s
		}
		g.mask(m)
	}
	g.mask(best)
	g.drawFormat(best)
	return QR(g.mod)
}

func (g *qrGrid) drawFormat(mask int) {
	data := 0<<3 | mask // level M = 0b00
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return bits>>i&1 == 1 }
	n := g.n
	for i := 0; i <= 5; i++ {
		g.set(8, i, bit(i))
	}
	g.set(8, 7, bit(6))
	g.set(8, 8, bit(7))
	g.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		g.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		g.set(n-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		g.set(8, n-15+i, bit(i))
	}
	g.set(8, n-8, true)
}

func (g *qrGrid) mask(m int) {
	for y := 0; y < g.n; y++ {
		for x := 0; x < g.n; x++ {
			if g.fn[y][x] {
				continue
			}
			var inv bool
			switch m {
			case 0:
				inv = (x+y)%2 == 0
			case 1:
				inv = y%2 == 0
			case 2:
				inv = x%3 == 0
			case 3:
				inv = (x+y)%3 == 0
			case 4:
				inv = (x/3+y/2)%2 == 0
			case 5:
				inv = x*y%2+x*y%3 == 0
			case 6:
				inv = (x*y%2+x*y%3)%2 == 0
			case 7:
				inv = ((x+y)%2+x*y%3)%2 == 0
			}
			if inv {
				g.mod[y][x] = !g.mod[y][x]
			}
		}
	}
}

// penalty is the spec's four rules (runs, 2x2 blocks, finder-like patterns, dark balance).
func (g *qrGrid) penalty() int {
	n, p := g.n, 0
	at := func(x, y int, col bool) bool {
		if col {
			return g.mod[x][y]
		}
		return g.mod[y][x]
	}
	for _, col := range []bool{false, true} {
		for y := 0; y < n; y++ {
			run := 1
			for x := 1; x < n; x++ {
				if at(x, y, col) == at(x-1, y, col) {
					run++
					if run == 5 {
						p += 3
					} else if run > 5 {
						p++
					}
				} else {
					run = 1
				}
			}
			for x := 0; x+10 < n; x++ {
				var s strings.Builder
				for k := 0; k < 11; k++ {
					if at(x+k, y, col) {
						s.WriteByte('1')
					} else {
						s.WriteByte('0')
					}
				}
				if v := s.String(); v == "10111010000" || v == "00001011101" {
					p += 40
				}
			}
		}
	}
	dark := 0
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if g.mod[y][x] {
				dark++
			}
			if x+1 < n && y+1 < n {
				c := g.mod[y][x]
				if g.mod[y][x+1] == c && g.mod[y+1][x] == c && g.mod[y+1][x+1] == c {
					p += 3
				}
			}
		}
	}
	k := abs(dark*20-n*n*10) / (n * n)
	return p + k*10
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// ---- Reed-Solomon over GF(256), polynomial 0x11D ----

func gfMul(a, b byte) byte {
	var z byte
	for i := 7; i >= 0; i-- {
		z = z<<1 ^ (z>>7)*0x1D
		if b>>i&1 == 1 {
			z ^= a
		}
	}
	return z
}

func rsGenerator(deg int) []byte {
	res := make([]byte, deg)
	res[deg-1] = 1
	root := byte(1)
	for i := 0; i < deg; i++ {
		for j := range res {
			res[j] = gfMul(res[j], root)
			if j+1 < len(res) {
				res[j] ^= res[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return res
}

func rsRemainder(data, gen []byte) []byte {
	res := make([]byte, len(gen))
	for _, b := range data {
		f := b ^ res[0]
		copy(res, res[1:])
		res[len(res)-1] = 0
		for i := range res {
			res[i] ^= gfMul(gen[i], f)
		}
	}
	return res
}

// SVG draws the code with a 4-module quiet zone; colours come from CSS (fill: currentColor) so it themes.
func (q QR) SVG() string {
	n := len(q)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="-4 -4 %d %d" shape-rendering="crispEdges"><rect x="-4" y="-4" width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n+8, n+8, n+8, n+8)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if q[y][x] {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}

// Terminal draws the code with Unicode half blocks, two module rows per text line, light-on-dark safe (the quiet
// zone and light modules are printed as full blocks so it scans on a black terminal).
func (q QR) Terminal() string {
	n := len(q)
	dark := func(x, y int) bool { return x >= 0 && y >= 0 && x < n && y < n && q[y][x] }
	var b strings.Builder
	for y := -2; y < n+2; y += 2 {
		b.WriteString("  ")
		for x := -2; x < n+2; x++ {
			top, bot := !dark(x, y), !dark(x, y+1) // "light" is drawn
			switch {
			case top && bot:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bot:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
