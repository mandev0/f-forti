// Package winplace computes where a window goes when the app switches
// between its narrow main view and its wide settings view, so the window
// grows around its centre and comes back to where it was. Pure geometry in
// physical pixels; the Win32 calls live in the GUI.
package winplace

// Rect is a window or work-area rectangle in physical pixels.
type Rect struct{ Left, Top, Right, Bottom int32 }

// W returns the width.
func (r Rect) W() int32 { return r.Right - r.Left }

// H returns the height.
func (r Rect) H() int32 { return r.Bottom - r.Top }

// CX returns the horizontal centre.
func (r Rect) CX() int32 { return r.Left + r.W()/2 }

// State remembers the main-view rect before expanding and the wide rect we
// placed, to detect whether the user moved the wide window.
type State struct {
	savedMain, placedWide *Rect
}

// Next returns the new window rect for width newW. work is the monitor work
// area (zero Rect = unknown, no clamping).
func (s *State) Next(cur Rect, newW int32, expanding bool, work Rect) Rect {
	x, y := cur.CX()-newW/2, cur.Top
	if expanding {
		saved := cur
		s.savedMain = &saved
	} else if s.savedMain != nil && s.placedWide != nil && cur.Left == s.placedWide.Left && cur.Top == s.placedWide.Top {
		x, y = s.savedMain.Left, s.savedMain.Top
	}
	if work != (Rect{}) {
		x = clamp(x, work.Left, work.Right-newW)
		y = clamp(y, work.Top, work.Bottom-cur.H())
	}
	r := Rect{Left: x, Top: y, Right: x + newW, Bottom: y + cur.H()}
	if expanding {
		placed := r
		s.placedWide = &placed
	} else {
		s.savedMain, s.placedWide = nil, nil
	}
	return r
}

func clamp(v, lo, hi int32) int32 {
	if hi < lo {
		return lo
	}
	return max(lo, min(v, hi))
}
