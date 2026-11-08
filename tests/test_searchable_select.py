"""Guards for the searchable select dropdown escaping its modal.

`.modal` is a scroll box (`max-height: 90vh; overflow-y: auto`) with a
transform on it, inside a backdrop that carries a `backdrop-filter`. That
combination clips an absolutely positioned child at the modal's edge - and
because the transform also makes the modal the containing block for fixed
children, `position: fixed` alone does not get out either. The only way out is
to move the open panel out of the modal, so these tests pin the three halves of
that: the panel leaves for `<body>`, it comes back on close, and everything
that used to rely on it living next to its trigger was updated.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STYLE = (ROOT / 'static' / 'css' / 'style.css').read_text(encoding='utf-8')
JS = (ROOT / 'static' / 'js' / 'searchable-select.js').read_text(encoding='utf-8')


def css_block(selector):
    match = re.search(re.escape(selector) + r'\s*\{([^}]*)\}', STYLE)
    assert match, f'no rule for {selector}'
    return match.group(1)


def z_index_of(selector):
    match = re.search(r'z-index:\s*(\d+)', css_block(selector))
    assert match, f'{selector} has no z-index'
    return int(match.group(1))


def method(name):
    match = re.search(
        r'SearchableSelect\.prototype\.' + name + r' = function \([^)]*\) \{(.*?)\n    \};',
        JS,
        re.S,
    )
    assert match, f'no {name}() in searchable-select.js'
    return match.group(1)


class PanelCssTests(unittest.TestCase):
    def test_closed_panel_stays_anchored_to_its_trigger(self):
        """Only the open panel floats; closed, it is a plain absolute child."""
        block = css_block('.searchable-select-panel')
        self.assertIn('position: absolute', block)
        self.assertIn('top: calc(100% + 4px)', block)

    def test_open_panel_is_fixed_and_placed_by_script(self):
        block = css_block('.searchable-select-panel.is-floating')
        self.assertIn('position: fixed', block)
        # The base rule pins inset-inline/top; the script sets left/top/width.
        self.assertIn('inset: auto', block)

    def test_open_panel_stacks_above_modals_and_below_toasts(self):
        panel = z_index_of('.searchable-select-panel.is-floating')
        self.assertGreater(panel, z_index_of('.modal-backdrop'))
        self.assertLess(panel, z_index_of('.toast-container'))


class PanelPortalTests(unittest.TestCase):
    def test_open_panel_moves_to_body(self):
        body = method('show')
        self.assertIn('document.body.appendChild(this.panel)', body)
        self.assertIn("this.panel.classList.add('is-floating')", body)

    def test_closed_panel_moves_back_under_its_trigger(self):
        body = method('hide')
        self.assertIn('this.wrapper.appendChild(this.panel)', body)
        self.assertIn("this.panel.classList.remove('is-floating')", body)
        # Stale coordinates would place the reopened panel wrong for a frame.
        self.assertIn("this.panel.removeAttribute('style')", body)
        self.assertIn("this.list.style.maxHeight = ''", body)

    def test_outside_click_does_not_count_the_panel(self):
        """The panel is no longer inside the wrapper, so the old check alone
        closed the dropdown the moment the search box was clicked."""
        match = re.search(
            r"document\.addEventListener\('click', function \(e\) \{(.*?)\n        \}\);",
            JS,
            re.S,
        )
        self.assertIsNotNone(match)
        self.assertIn('!panel.contains(e.target)', match.group(1))


class PanelPositioningTests(unittest.TestCase):
    def test_panel_follows_scroll_and_resize_while_open(self):
        show = method('show')
        self.assertIn("window.addEventListener('resize', this.onViewportChange)", show)
        # Capture phase, or a scroll inside the modal never reaches us.
        self.assertIn(
            "document.addEventListener('scroll', this.onViewportChange, true)",
            show,
        )
        hide = method('hide')
        self.assertIn("window.removeEventListener('resize', this.onViewportChange)", hide)
        self.assertIn(
            "document.removeEventListener('scroll', this.onViewportChange, true)",
            hide,
        )

    def test_position_flips_above_when_there_is_no_room_below(self):
        body = method('position')
        self.assertIn('window.innerHeight - rect.bottom', body)
        self.assertIn('rect.top - PANEL_GAP - VIEWPORT_MARGIN', body)
        self.assertRegex(body, r'openDown\s*\?\s*rect\.bottom \+ PANEL_GAP')

    def test_position_clamps_the_panel_into_the_viewport(self):
        body = method('position')
        self.assertRegex(body, r'panel\.style\.top =\s*\n?\s*clamp\(')
        self.assertRegex(body, r'panel\.style\.left =\s*\n?\s*clamp\(')
        self.assertIn('window.innerWidth - rect.width - VIEWPORT_MARGIN', body)

    def test_reposition_keeps_the_option_list_where_it_was_scrolled(self):
        """Measuring the natural height hands the list its CSS cap back, which
        shortens its scroll range and would otherwise jump the list."""
        body = method('position')
        self.assertIn('var scrolled = this.list.scrollTop', body)
        self.assertIn('this.list.scrollTop = scrolled', body)

    def test_list_scroll_events_do_not_trigger_a_reposition(self):
        self.assertIn('if (e && e.target && self.panel.contains(e.target)) return;', JS)


class PanelDismissTests(unittest.TestCase):
    def test_panel_closes_when_its_modal_closes(self):
        """A closed modal keeps its layout box, so the panel has to be told."""
        self.assertIn('new MutationObserver(', method('show'))
        self.assertRegex(method('show'), r"attributeFilter: \['class', 'style', 'hidden'\]")
        self.assertIn('if (self.open && !isVisible(self.trigger)) self.hide();', JS)
        self.assertIn('this.ancestorObserver.disconnect()', method('hide'))

    def test_visibility_check_covers_a_hidden_ancestor(self):
        match = re.search(r'function isVisible\(el\) \{(.*?)\n    \}', JS, re.S)
        self.assertIsNotNone(match)
        body = match.group(1)
        self.assertIn('visibilityProperty: true', body)
        self.assertIn('opacityProperty: true', body)
        # Browsers without checkVisibility still get the rect fallback.
        self.assertIn('getBoundingClientRect()', body)

    def test_panel_closes_when_the_trigger_scrolls_out_of_its_modal(self):
        self.assertIn('new IntersectionObserver(', method('show'))
        self.assertIn('this.observer.observe(this.trigger)', method('show'))
        self.assertIn('this.observer.disconnect()', method('hide'))


if __name__ == '__main__':
    unittest.main()
