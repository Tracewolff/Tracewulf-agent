package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type StepStatus int

const (
	StepPending StepStatus = iota
	StepActive
	StepDone
	StepFailed
)

type stepUpdateMsg struct {
	Index  int
	Status StepStatus
	Detail string
}

type readyMsg struct {
	DashboardURL string
}

type quitMsg struct{}

// Reporter lets setup code (in main.go) push progress into the TUI without
// the TUI package needing to know anything about Kubernetes or eBPF.
type Reporter struct {
	updates chan tea.Msg
}

func NewReporter() *Reporter {
	return &Reporter{updates: make(chan tea.Msg, 16)}
}

func (r *Reporter) Start(i int) { r.updates <- stepUpdateMsg{Index: i, Status: StepActive} }
func (r *Reporter) Done(i int, detail string) {
	r.updates <- stepUpdateMsg{Index: i, Status: StepDone, Detail: detail}
}
func (r *Reporter) Fail(i int, err error) {
	r.updates <- stepUpdateMsg{Index: i, Status: StepFailed, Detail: err.Error()}
}
func (r *Reporter) Ready(dashboardURL string) { r.updates <- readyMsg{DashboardURL: dashboardURL} }
func (r *Reporter) Quit()                     { r.updates <- quitMsg{} }

var Steps = []string{
	"Connecting to Kubernetes API and syncing informers",
	"Loading eBPF programs and attaching kernel probes",
	"Restoring history and starting dashboard",
}

var (
	banner = lipgloss.NewStyle().Foreground(lipgloss.Color("51")).Bold(true)
	dim    = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	ok     = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	errS   = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true)
	box    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("51")).Padding(0, 2)
)

const logo = `
      _/\_                          ████████╗ ██╗    ██╗
   __/    \__          _/\_          ╚══██╔═  ██║    ██║
  /          \_     __/    \__          ██║   ██║ █╗ ██║
 /              \__/          \__       ██║   ██║███╗██║
/                                 \___  ██║    ███ ███╔╝
                                      \_ ╚╝     ╚══╝╚═╝
`

type Model struct {
	reporter     *Reporter
	stepStatus   []StepStatus
	stepDetail   []string
	spin         spinner.Model
	ready        bool
	dashboardURL string
	failed       bool
	quitting     bool
}

func NewModel(r *Reporter) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	return Model{
		reporter:   r,
		stepStatus: make([]StepStatus, len(Steps)),
		stepDetail: make([]string, len(Steps)),
		spin:       s,
	}
}

func waitForUpdate(r *Reporter) tea.Cmd {
	return func() tea.Msg { return <-r.updates }
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spin.Tick, waitForUpdate(m.reporter))
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	case stepUpdateMsg:
		m.stepStatus[msg.Index] = msg.Status
		if msg.Detail != "" {
			m.stepDetail[msg.Index] = msg.Detail
		}
		if msg.Status == StepFailed {
			m.failed = true
		}
		return m, waitForUpdate(m.reporter)
	case readyMsg:
		m.ready = true
		m.dashboardURL = msg.DashboardURL
		return m, waitForUpdate(m.reporter)
	case quitMsg:
		m.quitting = true
		return m, tea.Quit
	case tea.KeyMsg:
		if m.ready && (msg.String() == "q" || msg.String() == "ctrl+c" || msg.String() == "enter") {
			m.quitting = true
			return m, tea.Quit
		}
		if m.failed && msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}

	out := banner.Render(logo) + "\n"
	out += dim.Render("  eBPF-based Kubernetes network cost observability") + "\n\n"

	for i, label := range Steps {
		var mark string
		switch m.stepStatus[i] {
		case StepDone:
			mark = ok.Render("✓")
		case StepFailed:
			mark = errS.Render("✗")
		case StepActive:
			mark = m.spin.View()
		default:
			mark = dim.Render("○")
		}
		line := fmt.Sprintf("  %s  %s", mark, label)
		if m.stepStatus[i] == StepFailed && m.stepDetail[i] != "" {
			line += "\n      " + errS.Render(m.stepDetail[i])
		}
		if m.stepStatus[i] == StepDone && m.stepDetail[i] != "" {
			line += dim.Render("  (" + m.stepDetail[i] + ")")
		}
		out += line + "\n"
	}

	if m.ready {
		content := ok.Render("TraceWulf is running") + "\n\n" +
			"  Dashboard:  " + banner.Render(m.dashboardURL) + "\n\n" +
			dim.Render("  press enter to continue (daemon keeps running in background)")
		out += "\n" + box.Render(content) + "\n"
	}

	if m.failed {
		out += "\n" + errS.Render("Startup failed — see error above. Press ctrl+c to exit.") + "\n"
	}

	return out
}
