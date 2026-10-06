// Package logging provides the minimal module.Logger implementation used
// by cmd/recontool. Kept separate from main so it can be reused by tests.
package logging

import (
	"log"
	"os"
)

type StdLogger struct {
	l *log.Logger
}

func New() *StdLogger {
	return &StdLogger{l: log.New(os.Stderr, "", log.LstdFlags)}
}

func (s *StdLogger) Infof(format string, args ...any)  { s.l.Printf("[INFO] "+format, args...) }
func (s *StdLogger) Warnf(format string, args ...any)  { s.l.Printf("[WARN] "+format, args...) }
func (s *StdLogger) Errorf(format string, args ...any) { s.l.Printf("[ERROR] "+format, args...) }
