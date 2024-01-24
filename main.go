package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"golang.org/x/term"
)

// ///// //
// Model //
// ///// //
type filter struct {
	contains string
	matches  *regexp.Regexp
}

func (f filter) matchesString(data string) bool {
	if f.contains != "" && strings.Index(data, f.contains) == -1 {
		return false
	}
	if f.matches != nil && !f.matches.MatchString(data) {
		return false
	}
	return true
}

func applyFilterToSlice(f filter, data []string) []string {
	res := []string{}
	for _, s := range data {
		if f.matchesString(s) {
			res = append(res, s)
		}
	}
	return res
}

func applyFilterToMapKeys[V any](f filter, data map[string]V) map[string]V {
	res := map[string]V{}
	for k, v := range data {
		if f.matchesString(k) {
			res[k] = v
		}
	}
	return res
}

func applyFilterToMapValues[K comparable](f filter, data map[K]string) map[K]string {
	res := map[K]string{}
	for k, v := range data {
		if f.matchesString(v) {
			res[k] = v
		}
	}
	return res
}

type debugInfo[Data any] struct {
	raw      Data
	filtered Data
	filter   filter
	vp       viewport.Model
	visible  bool
}

type model struct {
	vars       *debugInfo[map[string]string]
	bts        *debugInfo[map[string]string]
	logs       *debugInfo[[]string]
	termWidth  int
	termHeight int
}

/*
func (m model) recalcLayout() {
   logHeight := 0
   varWidth := 0

	if m.vars.visible && m.bts.visible {
		varWidth = m.termWidth / 2
	} else if m.vars.visible {

		varWidth = m.termWidth
	}

	if m.logs.visible && (m.vars.visible || m.bts.visible) {
		logHeight = m.termHeight / 2
	} else if m.logs.visible {

		logHeight = m.termHeight
	}

   varHeight := m.termHeight - logHeight
   btWidth := m.termWidth - varWidth

	if logHeight > 0 {
		m.logs.vp.Height = logHeight
		m.logs.vp.Width = m.termWidth
	}

	if varHeight > 0 && varWidth > 0 {
		m.vars.vp.Height = varHeight
		m.vars.vp.Width = varWidth
	}

	if varHeight > 0 && btWidth > 0 {
		m.bts.vp.Height = varHeight
		m.bts.vp.Width = btWidth
	}
}
*/

func initialModel(width, height int) model {
	model := model{
		vars: &debugInfo[map[string]string]{
			raw:      map[string]string{},
			filtered: map[string]string{},
			vp:       viewport.New(width, height),
		},
		bts: &debugInfo[map[string]string]{
			raw:      map[string]string{},
			filtered: map[string]string{},
			vp:       viewport.New(width, height),
		},
		logs: &debugInfo[[]string]{
			raw:      []string{},
			filtered: []string{},
			vp:       viewport.New(width, height),
			visible:  true,
		},
	}
	model.vars.vp.MouseWheelEnabled = true
	model.vars.vp.YPosition = 0
	model.bts.vp.MouseWheelEnabled = true
	model.bts.vp.YPosition = 0
	model.logs.vp.MouseWheelEnabled = true
	model.logs.vp.YPosition = 0
	return model
}

// /////// //
// Updates //
// /////// //
type setVar struct {
	name  string
	value string
}

type setBt struct {
	name  string
	value string
}

type addLog string

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmds := []tea.Cmd{}
	switch msg := msg.(type) {
	case setVar:
		m.vars.raw[msg.name] = msg.value
		if m.vars.filter.matchesString(msg.name) {
			m.vars.filtered[msg.name] = msg.value
			if m.vars.visible {
				m.renderVars()
			}
		}
	case setBt:
		m.bts.raw[msg.value] = msg.name
		if m.bts.filter.matchesString(msg.name) {
			m.bts.filtered[msg.value] = msg.name
			if m.bts.visible {
				m.renderBts()
			}
		}
	case addLog:
		m.logs.raw = append(m.logs.raw, string(msg))
		if m.logs.filter.matchesString(string(msg)) {
			m.logs.filtered = append(m.logs.filtered, string(msg))
			if m.logs.visible {
				m.logs.vp.SetContent(strings.Join(m.logs.filtered, "\n"))
			}
		}
	case tea.WindowSizeMsg:
		m.termWidth = msg.Width
		m.termHeight = msg.Height
		m.logs.vp.Height = m.termHeight
		m.logs.vp.Width = m.termWidth
		m.vars.vp.Height = m.termHeight
		m.vars.vp.Width = m.termWidth
		m.bts.vp.Height = m.termHeight
		m.bts.vp.Width = m.termWidth
		if m.vars.visible {
			m.renderVars()
		}
		if m.bts.visible {
			m.renderBts()
		}
		if m.logs.visible {
			m.logs.vp.SetContent(strings.Join(m.logs.filtered, "\n"))
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, tea.Quit
		case "s":
			m.vars.visible = true
			m.bts.visible = false
			m.logs.visible = false
			m.renderVars()
		case "d":
			m.vars.visible = false
			m.bts.visible = true
			m.logs.visible = false
			m.renderBts()
		case "f":
			m.vars.visible = false
			m.bts.visible = false
			m.logs.visible = true
			m.logs.vp.SetContent(strings.Join(m.logs.filtered, "\n"))
		default:
			var cmd tea.Cmd
			if m.vars.visible {
				m.vars.vp, cmd = m.vars.vp.Update(msg)
			} else if m.bts.visible {
				m.bts.vp, cmd = m.bts.vp.Update(msg)
			} else if m.logs.visible {
				m.logs.vp, cmd = m.logs.vp.Update(msg)
			}
			cmds = append(cmds, cmd)
		}
	case tea.MouseMsg:
		var cmd tea.Cmd
		if m.vars.visible {
			m.vars.vp, cmd = m.vars.vp.Update(msg)
		} else if m.bts.visible {
			m.bts.vp, cmd = m.bts.vp.Update(msg)
		} else if m.logs.visible {
			m.logs.vp, cmd = m.logs.vp.Update(msg)
		}
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

var varStyle = lipgloss.NewStyle().
	Padding(0, 1).Margin(1).MarginBottom(0).
	Border(lipgloss.NormalBorder())

var btStyle = lipgloss.NewStyle().Padding(0, 1).Border(lipgloss.NormalBorder())

func (m model) renderVars() {
	names := []string{}
	for name := range m.vars.filtered {
		names = append(names, name)
	}

	sort.StringSlice(names).Sort()

	renderedVars := []string{}
	for _, name := range names {
		value := m.vars.filtered[name]
		text := fmt.Sprintf("%s\n%s", name, value)
		block := varStyle.Render(lipgloss.Place(40, 2, lipgloss.Center, lipgloss.Top, text))
		renderedVars = append(renderedVars, block)
	}

	out := strings.Builder{}
	lineWidth := 0
	row := []string{}
	renderLine := func() {
		line := lipgloss.JoinHorizontal(lipgloss.Center, row...)
		out.WriteString(lipgloss.PlaceHorizontal(m.termWidth, lipgloss.Center, line))
		row = row[:0]
		lineWidth = 0
	}
	for _, block := range renderedVars {
		varWidth := lipgloss.Width(block)
		if lineWidth+varWidth > m.vars.vp.Width {
			renderLine()
		}
		lineWidth += varWidth
		row = append(row, block)
	}
	renderLine()
	m.vars.vp.SetContent(out.String())
}

func (m model) renderBts() {
	traces := []string{}
	for value, name := range m.bts.filtered {
		traces = append(traces, fmt.Sprintf("%s\n\n%s", name, value))

	}
	sort.StringSlice(traces).Sort()
	out := strings.Builder{}
	for _, text := range traces {
		out.WriteString(btStyle.Render(
			lipgloss.PlaceHorizontal(m.bts.vp.Width-2, lipgloss.Left, text),
		))
	}
	m.bts.vp.SetContent(out.String())
}

func (m model) View() string {
	if m.vars.visible {
		return m.vars.vp.View()
	}
	if m.bts.visible {
		return m.bts.vp.View()
	}
	if m.logs.visible {
		return m.logs.vp.View()
	}
	return "No visible view"
}

func readByte(r io.Reader) (byte, error) {
	var data [1]byte
	_, err := io.ReadAtLeast(r, data[:], 1)
	return data[0], err
}

func expectByte(r io.Reader, expected byte) error {
	got, err := readByte(r)
	if err != nil {
		return err
	}
	if got != expected {
		byteName := ""
		switch expected {
		case SOH:
			byteName = "SOH"
		case STX:
			byteName = "STX"
		case ETX:
			byteName = "ETX"
		case RS:
			byteName = "RS"
		case US:
			byteName = "US"
		}
		if byteName != "" {
			return fmt.Errorf("expected %s", byteName)
		} else {
			return fmt.Errorf("expected 0x%02x", expected)
		}
	}
	return nil
}

func readTerminated(r io.Reader, delimiter ...byte) ([]byte, byte, error) {
	res := []byte{}
	var b byte
	var err error
readLoop:
	for {
		b, err = readByte(r)
		if err != nil {
			break readLoop
		}
		for _, d := range delimiter {
			if b == d {
				break readLoop
			}
		}
		res = append(res, b)
	}
	return res, b, err
}

const (
	SOH = 1
	STX = 2
	ETX = 3
	RS  = 30
	US  = 31
)

func main() {
	addr := flag.String("address", "localhost:21212", "")
	btProcessor := flag.String("bt", "", "")
	flag.Parse()
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read terminal size: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial failed: %v\n", err)
		os.Exit(1)
	}
	handshake := []byte("\x01version\x1f1\x03")
	_, err = conn.Write(handshake)
	if err != nil {
		fmt.Fprintf(os.Stderr, "handshake write failed: %v\n", err)
		os.Exit(1)
	}
	check := make([]byte, len(handshake))
	_, err = io.ReadAtLeast(conn, check, len(check))
	if err != nil {
		fmt.Fprintf(os.Stderr, "handshake read failed: %v\n", err)
		os.Exit(1)
	}
	if string(check) != string(handshake) {
		fmt.Fprintln(os.Stderr, "Bad handshake")
		os.Exit(1)
	}

	p := tea.NewProgram(initialModel(width, height), tea.WithAltScreen(), tea.WithMouseCellMotion())

	go func() {
		for {
			if err := expectByte(conn, SOH); err != nil {
				p.Send(addLog(fmt.Sprintf("<<Network error>>: %s", err.Error())))
				return
			}
			msgType := ""
			msgName := ""
			for {
				name, _, err := readTerminated(conn, US)
				if err != nil {
					p.Send(addLog(fmt.Sprintf("<<Network error>>: %s", err.Error())))
					return
				}
				value, delim, err := readTerminated(conn, RS, STX)
				if err != nil {
					p.Send(addLog(fmt.Sprintf("<<Network error>>: %s", err.Error())))
					return
				}
				switch string(name) {
				case "type":
					msgType = string(value)
				case "name":
					msgName = string(value)
				default:
					p.Send(addLog(fmt.Sprintf(`<<Network error>>: unknown header "%s"`, name)))
					return
				}
				if delim == STX {
					break
				}
			}
			msg, _, err := readTerminated(conn, ETX)
			if err != nil {
				p.Send(addLog(fmt.Sprintf("<<Network error>>: %s", err.Error())))
				return
			}
			switch msgType {
			case "var":
				if msgName == "" {
					p.Send(addLog(fmt.Sprintf(
						`<<Network error>>: message name required for type %s`, msgType,
					)))
					return
				}
				p.Send(setVar{name: msgName, value: string(msg)})
			case "bt":
				if msgName == "" {
					p.Send(addLog(fmt.Sprintf(
						`<<Network error>>: message name required for type %s`, msgType,
					)))
					return
				}
				if btProcessor != nil && *btProcessor != "" {
					go func() {
						cmd := exec.Command(*btProcessor)
						cmdIn, err := cmd.StdinPipe()
						if err != nil {
							p.Send(setBt{name: msgName, value: string(msg)})
							return
						}
						cmdOut, err := cmd.StdoutPipe()
						if err != nil {
							p.Send(setBt{name: msgName, value: string(msg)})
							return
						}
						err = cmd.Start()
						if err != nil {
							p.Send(setBt{name: msgName, value: string(msg)})
							return
						}
						var newMsg []byte
						var writeErr, readErr, waitErr error
						go func() {
							_, writeErr = cmdIn.Write(msg)
							cmdIn.Close()
						}()
						go func() {
							newMsg, readErr = io.ReadAll(cmdOut)
						}()
						waitErr = cmd.Wait()
						if writeErr != nil || readErr != nil || waitErr != nil {
							p.Send(setBt{name: msgName, value: string(msg)})
							return
						}
						p.Send(setBt{name: msgName, value: string(newMsg)})
					}()
				} else {
					p.Send(setBt{name: msgName, value: string(msg)})
				}
			case "log":
				p.Send(addLog(string(msg)))
			default:
				p.Send(addLog(fmt.Sprintf(`<<Network error>: unknown message type "%s"`, msgType)))
				return
			}
		}
	}()

	_, err = p.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
