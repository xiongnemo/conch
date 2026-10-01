package privilege

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseFileCaps(t *testing.T) {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b, vfsCapRevision2|vfsCapEffective)
	binary.LittleEndian.PutUint32(b[4:], uint32(tunCaps))
	if caps, ok := parseFileCaps(b); !ok || caps != tunCaps {
		t.Errorf("v2 +ep: %b, %v", caps, ok)
	}
	// Revision 3 adds the namespace's root uid after the same fields.
	v3 := append(append([]byte(nil), b...), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(v3, vfsCapRevision3|vfsCapEffective)
	if caps, ok := parseFileCaps(v3); !ok || caps != tunCaps {
		t.Errorf("v3: %b, %v", caps, ok)
	}
	// Permitted but not effective (setcap +p) does not help an unaware binary.
	binary.LittleEndian.PutUint32(b, vfsCapRevision2)
	if _, ok := parseFileCaps(b); ok {
		t.Error("+p without +e counted")
	}
	if _, ok := parseFileCaps(b[:8]); ok {
		t.Error("a short value parsed")
	}
}

func TestTUNErrorWithoutCapabilities(t *testing.T) {
	if os.Geteuid() == 0 || processHas("CapAmb", capNetAdmin) {
		t.Skip("running with privileges")
	}
	bin := filepath.Join(t.TempDir(), "kernel")
	os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755)
	if err := TUNError(bin); !errors.Is(err, ErrTUN) {
		t.Errorf("TUNError = %v", err)
	}
	if err := SetTUNCaps(bin); err == nil {
		t.Error("setting capabilities without root succeeded")
	}
}
