package winplace

import "testing"

var work = Rect{0, 0, 1920, 1040} // 1080p with a bottom taskbar

func TestGrowAroundCentreAndReturn(t *testing.T) {
	var s State
	main := Rect{700, 200, 1080, 860} // 380 wide
	wide := s.Next(main, 900, true, work)
	if wide.CX() != main.CX() || wide.Top != main.Top || wide.W() != 900 {
		t.Fatalf("not centred: %+v", wide)
	}
	back := s.Next(wide, 380, false, work)
	if back != main {
		t.Fatalf("did not return exactly: %+v want %+v", back, main)
	}
}

func TestRepeatedSwitchesDoNotDrift(t *testing.T) {
	var s State
	r := Rect{701, 200, 1081, 860}
	start := r
	for i := 0; i < 20; i++ {
		r = s.Next(r, 900, true, work)
		r = s.Next(r, 380, false, work)
	}
	if r != start {
		t.Fatalf("drifted: %+v -> %+v", start, r)
	}
}

func TestClampAtScreenEdge(t *testing.T) {
	var s State
	main := Rect{1520, 100, 1900, 760} // near the right edge
	wide := s.Next(main, 900, true, work)
	if wide.Right != work.Right || wide.Left != work.Right-900 {
		t.Fatalf("not kept on screen: %+v", wide)
	}
	back := s.Next(wide, 380, false, work)
	if back != main {
		t.Fatalf("should return to the original spot: %+v", back)
	}
}

func TestMovedWhileWide(t *testing.T) {
	var s State
	main := Rect{700, 200, 1080, 860}
	wide := s.Next(main, 900, true, work)
	moved := Rect{wide.Left - 300, wide.Top + 50, wide.Right - 300, wide.Bottom + 50}
	back := s.Next(moved, 380, false, work)
	if back.CX() != moved.CX() || back.Top != moved.Top || back.W() != 380 {
		t.Fatalf("should centre on the moved window: %+v", back)
	}
}

func TestHighDPI(t *testing.T) {
	var s State
	// 150 % scaling: 380 DIP = 570 px, 900 DIP = 1350 px
	main := Rect{1000, 300, 1570, 1290}
	wide := s.Next(main, 1350, true, Rect{0, 0, 3840, 2100})
	if wide.CX() != main.CX() {
		t.Fatalf("centre moved at 150%%: %+v", wide)
	}
	if back := s.Next(wide, 570, false, Rect{0, 0, 3840, 2100}); back != main {
		t.Fatalf("150%% return: %+v", back)
	}
}

func TestSecondMonitorNegativeCoords(t *testing.T) {
	var s State
	left := Rect{-1920, 0, 0, 1040} // monitor left of the primary
	main := Rect{-400, 100, -20, 760}
	wide := s.Next(main, 900, true, left)
	if wide.Right != 0 || wide.Left != -900 {
		t.Fatalf("not kept on the left monitor: %+v", wide)
	}
	if back := s.Next(wide, 380, false, left); back != main {
		t.Fatalf("return on left monitor: %+v", back)
	}
}
