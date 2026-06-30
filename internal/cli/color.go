package cli

import (
	"io"
	"os"
)

// colors renders ANSI styling, but only when writing to a terminal and when
// NO_COLOR is unset (https://no-color.org).
type colors struct{ on bool }

func newColors(w io.Writer) colors {
	if os.Getenv("NO_COLOR") != "" {
		return colors{on: false}
	}
	f, ok := w.(*os.File)
	if !ok {
		return colors{on: false}
	}
	info, err := f.Stat()
	if err != nil {
		return colors{on: false}
	}
	return colors{on: info.Mode()&os.ModeCharDevice != 0}
}

func (c colors) wrap(code, s string) string {
	if !c.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (c colors) red(s string) string    { return c.wrap("41;97;1", s) } // white on red
func (c colors) yellow(s string) string { return c.wrap("43;30;1", s) } // black on yellow
func (c colors) green(s string) string  { return c.wrap("42;30;1", s) } // black on green
func (c colors) dim(s string) string    { return c.wrap("2", s) }
