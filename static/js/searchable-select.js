/**
 * Searchable select — progressive enhancement for long <select> lists.
 *
 * Any `<select data-searchable>` is wrapped in a filterable dropdown: a
 * trigger button styled like .form-select, a search box and a filtered
 * option list with keyboard navigation.
 *
 * The original <select> stays in the DOM (visually hidden) and remains the
 * single source of truth, so existing code that reads `.value`, sets it, or
 * listens for `change` keeps working untouched.
 *
 * While open, the panel is parked in <body> and positioned in viewport
 * coordinates: a modal is a scroll box with a transform on it, and such a box
 * clips even position: fixed children, so a panel left inside one gets cut off
 * at the modal's edge. See position().
 *
 * Labels come from data attributes so translations stay in the templates:
 *   data-search-placeholder="..."   search box placeholder
 *   data-search-empty="..."         shown when nothing matches
 */
(function () {
    'use strict';

    var ID_SEQ = 0;

    /* Gap between the trigger and the panel, and the margin the panel keeps
       from the viewport edges. */
    var PANEL_GAP = 4;
    var VIEWPORT_MARGIN = 8;
    /* Roughly two rows: the list is never squeezed below this, so on a very
       short viewport the panel overlaps the trigger instead of collapsing. */
    var MIN_LIST_HEIGHT = 64;

    function clamp(value, min, max) {
        return Math.min(Math.max(value, min), Math.max(min, max));
    }

    function textOf(option) {
        return (option.textContent || '').trim();
    }

    /* Is the element still rendered? A modal that was closed keeps its box and
       its rect, so the fallback below (browsers without checkVisibility) only
       catches a detached or display: none trigger. */
    function isVisible(el) {
        if (el.checkVisibility) {
            return el.checkVisibility({ visibilityProperty: true, opacityProperty: true });
        }
        var rect = el.getBoundingClientRect();
        return !!(rect.width || rect.height);
    }

    function SearchableSelect(select) {
        var self = this;
        this.select = select;
        this.id = 'ss-' + (++ID_SEQ);
        this.open = false;
        this.activeIndex = -1;
        this.items = [];
        // Kept on the instance so show() and hide() add and remove the very
        // same listener.
        this.onViewportChange = function (e) {
            // Scrolling the option list is not the panel moving.
            if (e && e.target && self.panel.contains(e.target)) return;
            self.position();
        };
        this.build();
    }

    SearchableSelect.prototype.build = function () {
        var self = this;
        var select = this.select;

        var wrapper = document.createElement('div');
        wrapper.className = 'searchable-select';

        var trigger = document.createElement('button');
        trigger.type = 'button';
        trigger.className = 'form-select searchable-select-trigger';
        trigger.setAttribute('aria-haspopup', 'listbox');
        // Option text is user data (names, emails) and may run counter to the
        // page direction; let the browser pick per string instead of forcing
        // the UI direction onto it.
        trigger.setAttribute('dir', 'auto');
        trigger.setAttribute('aria-expanded', 'false');
        if (select.id) {
            trigger.setAttribute('aria-labelledby', select.id + '-label');
        }

        var panel = document.createElement('div');
        panel.className = 'searchable-select-panel';
        panel.hidden = true;

        var searchWrap = document.createElement('div');
        searchWrap.className = 'searchable-select-search';

        var search = document.createElement('input');
        search.type = 'text';
        search.className = 'form-input';
        search.autocomplete = 'off';
        search.spellcheck = false;
        search.setAttribute('dir', 'auto');
        search.placeholder = select.dataset.searchPlaceholder || 'Search...';
        search.setAttribute('aria-controls', this.id + '-list');
        searchWrap.appendChild(search);

        var list = document.createElement('div');
        list.className = 'searchable-select-list';
        list.id = this.id + '-list';
        list.setAttribute('role', 'listbox');

        var empty = document.createElement('div');
        empty.className = 'searchable-select-empty';
        empty.textContent = select.dataset.searchEmpty || 'No matches';
        empty.hidden = true;

        panel.appendChild(searchWrap);
        panel.appendChild(list);
        panel.appendChild(empty);

        select.parentNode.insertBefore(wrapper, select);
        wrapper.appendChild(select);
        wrapper.appendChild(trigger);
        wrapper.appendChild(panel);
        select.classList.add('searchable-select-native');
        select.setAttribute('tabindex', '-1');
        select.setAttribute('aria-hidden', 'true');

        this.wrapper = wrapper;
        this.trigger = trigger;
        this.panel = panel;
        this.search = search;
        this.list = list;
        this.empty = empty;

        this.renderOptions();
        this.syncTrigger();

        trigger.addEventListener('click', function () {
            self.toggle();
        });
        trigger.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                self.show();
            }
        });
        search.addEventListener('input', function () {
            self.filter(search.value);
        });
        search.addEventListener('keydown', function (e) {
            self.onSearchKey(e);
        });
        select.addEventListener('change', function () {
            self.syncTrigger();
        });
        document.addEventListener('click', function (e) {
            // The open panel sits in <body>, so it is outside the wrapper.
            if (self.open && !wrapper.contains(e.target) && !panel.contains(e.target)) {
                self.hide();
            }
        });
    };

    /** Rebuild the option list from the native <select>. */
    SearchableSelect.prototype.renderOptions = function () {
        var self = this;
        this.list.textContent = '';
        this.items = [];

        Array.prototype.forEach.call(this.select.options, function (option, index) {
            var item = document.createElement('div');
            item.className = 'searchable-select-option';
            item.setAttribute('role', 'option');
            item.setAttribute('dir', 'auto');
            item.id = self.id + '-opt-' + index;
            item.textContent = textOf(option);   // textContent: never trust option text as HTML
            item.dataset.index = String(index);
            if (option.disabled) {
                item.classList.add('is-disabled');
            }
            item.addEventListener('click', function () {
                if (option.disabled) return;
                self.choose(index);
            });
            self.list.appendChild(item);
            self.items.push({ el: item, text: textOf(option).toLowerCase(), index: index });
        });
    };

    SearchableSelect.prototype.syncTrigger = function () {
        var option = this.select.options[this.select.selectedIndex];
        this.trigger.textContent = option ? textOf(option) : '';
        var self = this;
        this.items.forEach(function (item) {
            item.el.setAttribute('aria-selected', item.index === self.select.selectedIndex ? 'true' : 'false');
        });
    };

    SearchableSelect.prototype.filter = function (query) {
        var needle = (query || '').trim().toLowerCase();
        var visible = 0;
        this.items.forEach(function (item) {
            var match = !needle || item.text.indexOf(needle) !== -1;
            item.el.hidden = !match;
            if (match) visible++;
        });
        this.empty.hidden = visible !== 0;
        this.setActive(this.firstVisibleIndex());
        if (this.open) this.position();   // filtering just changed the height
    };

    SearchableSelect.prototype.visibleItems = function () {
        return this.items.filter(function (item) {
            return !item.el.hidden && !item.el.classList.contains('is-disabled');
        });
    };

    SearchableSelect.prototype.firstVisibleIndex = function () {
        var visible = this.visibleItems();
        return visible.length ? visible[0].index : -1;
    };

    SearchableSelect.prototype.setActive = function (index) {
        var self = this;
        this.activeIndex = index;
        this.items.forEach(function (item) {
            var active = item.index === index;
            item.el.classList.toggle('is-active', active);
            if (active) {
                self.list.setAttribute('aria-activedescendant', item.el.id);
                var top = item.el.offsetTop;
                var bottom = top + item.el.offsetHeight;
                if (top < self.list.scrollTop) {
                    self.list.scrollTop = top;
                } else if (bottom > self.list.scrollTop + self.list.clientHeight) {
                    self.list.scrollTop = bottom - self.list.clientHeight;
                }
            }
        });
        if (index === -1) {
            this.list.removeAttribute('aria-activedescendant');
        }
    };

    SearchableSelect.prototype.moveActive = function (step) {
        var visible = this.visibleItems();
        if (!visible.length) return;
        var current = -1;
        for (var i = 0; i < visible.length; i++) {
            if (visible[i].index === this.activeIndex) { current = i; break; }
        }
        var next = current + step;
        if (next < 0) next = visible.length - 1;
        if (next >= visible.length) next = 0;
        this.setActive(visible[next].index);
    };

    SearchableSelect.prototype.onSearchKey = function (e) {
        switch (e.key) {
            case 'ArrowDown':
                e.preventDefault();
                this.moveActive(1);
                break;
            case 'ArrowUp':
                e.preventDefault();
                this.moveActive(-1);
                break;
            case 'Enter':
                e.preventDefault();
                if (this.activeIndex !== -1) this.choose(this.activeIndex);
                break;
            case 'Escape':
                e.preventDefault();
                this.hide();
                this.trigger.focus();
                break;
            case 'Tab':
                // Focus is inside the panel, which lives in <body>; hand it
                // back so the next tab stop is the one after this field.
                this.trigger.focus();
                this.hide();
                break;
        }
    };

    SearchableSelect.prototype.choose = function (index) {
        this.select.selectedIndex = index;
        this.select.dispatchEvent(new Event('input', { bubbles: true }));
        this.select.dispatchEvent(new Event('change', { bubbles: true }));
        this.syncTrigger();
        this.hide();
        this.trigger.focus();
    };

    SearchableSelect.prototype.show = function () {
        if (this.open) return;
        var self = this;
        this.open = true;
        this.panel.hidden = false;
        // Out of the modal and into <body>: nothing between the panel and the
        // page can clip it there.
        document.body.appendChild(this.panel);
        this.panel.classList.add('is-floating');
        this.wrapper.classList.add('is-open');
        this.trigger.setAttribute('aria-expanded', 'true');
        this.syncTrigger();               // pick up programmatic value changes
        this.search.value = '';
        this.filter('');
        this.setActive(this.select.selectedIndex);
        this.position();
        this.search.focus();

        window.addEventListener('resize', this.onViewportChange);
        // Capture phase: a scroll inside the modal never bubbles to window.
        document.addEventListener('scroll', this.onViewportChange, true);
        // The panel no longer rides along with the trigger, so close once the
        // trigger is scrolled out of its own modal rather than leave the panel
        // floating over the page.
        if (window.IntersectionObserver) {
            if (!this.observer) {
                this.observer = new IntersectionObserver(function (entries) {
                    if (self.open && !entries[entries.length - 1].isIntersecting) {
                        self.hide();
                    }
                });
            }
            this.observer.observe(this.trigger);
        }
        // Closing a modal flips a class on it; the panel is no longer inside
        // it, so it would be left hanging over the page. Any ancestor that
        // changes class, style or hidden is reason enough to re-check.
        if (window.MutationObserver) {
            if (!this.ancestorObserver) {
                this.ancestorObserver = new MutationObserver(function () {
                    if (self.open && !isVisible(self.trigger)) self.hide();
                });
            }
            for (var node = this.wrapper.parentNode; node && node.nodeType === 1; node = node.parentNode) {
                this.ancestorObserver.observe(node, {
                    attributes: true,
                    attributeFilter: ['class', 'style', 'hidden'],
                });
            }
        }
    };

    /**
     * Place the open panel under the trigger in viewport coordinates, flipping
     * above it and shrinking the option list when there is not enough room
     * below. Runs on open and on every scroll or resize while open.
     */
    SearchableSelect.prototype.position = function () {
        if (!isVisible(this.trigger)) {   // the field is gone (modal closed)
            this.hide();
            return;
        }

        var rect = this.trigger.getBoundingClientRect();
        var panel = this.panel;
        panel.style.width = rect.width + 'px';

        // Natural size first: the list keeps the cap it has in CSS. That
        // shrinks its scroll range for a moment, so remember where the user
        // had scrolled to and put it back below.
        var scrolled = this.list.scrollTop;
        this.list.style.maxHeight = '';
        var listHeight = this.list.offsetHeight;
        var chrome = panel.offsetHeight - listHeight;   // search box + padding
        var below = window.innerHeight - rect.bottom - PANEL_GAP - VIEWPORT_MARGIN;
        var above = rect.top - PANEL_GAP - VIEWPORT_MARGIN;
        var openDown = panel.offsetHeight <= below || below >= above;
        var room = openDown ? below : above;

        this.list.style.maxHeight =
            Math.round(Math.max(MIN_LIST_HEIGHT, Math.min(listHeight, room - chrome))) + 'px';
        this.list.scrollTop = scrolled;

        var height = panel.offsetHeight;
        var top = openDown ? rect.bottom + PANEL_GAP : rect.top - PANEL_GAP - height;
        panel.style.top =
            clamp(top, VIEWPORT_MARGIN, window.innerHeight - height - VIEWPORT_MARGIN) + 'px';
        panel.style.left =
            clamp(rect.left, VIEWPORT_MARGIN, window.innerWidth - rect.width - VIEWPORT_MARGIN) + 'px';
    };

    SearchableSelect.prototype.hide = function () {
        if (!this.open) return;
        this.open = false;
        window.removeEventListener('resize', this.onViewportChange);
        document.removeEventListener('scroll', this.onViewportChange, true);
        if (this.observer) this.observer.disconnect();
        if (this.ancestorObserver) this.ancestorObserver.disconnect();
        this.panel.hidden = true;
        this.panel.classList.remove('is-floating');
        this.panel.removeAttribute('style');    // drop the viewport coordinates
        this.list.style.maxHeight = '';
        this.wrapper.appendChild(this.panel);   // back under its own trigger
        this.wrapper.classList.remove('is-open');
        this.trigger.setAttribute('aria-expanded', 'false');
    };

    SearchableSelect.prototype.toggle = function () {
        this.open ? this.hide() : this.show();
    };

    /** Re-read options from the native select (call after changing them). */
    SearchableSelect.prototype.refresh = function () {
        this.renderOptions();
        this.syncTrigger();
        if (this.open) this.filter(this.search.value);
    };

    function enhance(select) {
        if (!select || select.searchableSelect) return null;
        select.searchableSelect = new SearchableSelect(select);
        return select.searchableSelect;
    }

    function enhanceAll(root) {
        var scope = root || document;
        Array.prototype.forEach.call(
            scope.querySelectorAll('select[data-searchable]'),
            enhance
        );
    }

    window.SearchableSelect = { enhance: enhance, enhanceAll: enhanceAll };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { enhanceAll(); });
    } else {
        enhanceAll();
    }
})();
