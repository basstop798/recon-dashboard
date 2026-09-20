'use client';

/**
 * Pill-shaped tab navigation with a sliding active indicator.
 *
 * Fourteen tabs rarely fit one row, so the bar scrolls horizontally. Edge fades
 * appear only when there is more to scroll to, and the active tab is scrolled
 * into view when it changes from elsewhere (a finding's jump link, a module
 * card).
 */

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent,
} from 'react';

import { cx } from './ui';

export type TabItem<T extends string> = { id: T; label: string; count?: number };

const compact = new Intl.NumberFormat('en', { notation: 'compact' });

export function TabBar<T extends string>({
  tabs,
  active,
  onChange,
}: {
  tabs: ReadonlyArray<TabItem<T>>;
  active: T;
  onChange: (id: T) => void;
}) {
  const scrollerRef = useRef<HTMLDivElement>(null);
  const indicatorRef = useRef<HTMLSpanElement>(null);
  const tabRefs = useRef(new Map<T, HTMLButtonElement>());
  const [edges, setEdges] = useState({ left: false, right: false });

  // The indicator is positioned with direct style writes: it moves on every
  // resize and count update, and none of that needs a React render.
  const placeIndicator = useCallback(() => {
    const indicator = indicatorRef.current;
    const button = tabRefs.current.get(active);
    if (!indicator || !button) return;

    indicator.style.width = `${button.offsetWidth}px`;
    indicator.style.transform = `translateX(${button.offsetLeft}px)`;

    if (!('ready' in indicator.dataset)) {
      // Snap into place on first paint, then enable the slide for later moves.
      void indicator.offsetWidth;
      indicator.dataset.ready = '';
    }
  }, [active]);

  const updateEdges = useCallback(() => {
    const scroller = scrollerRef.current;
    if (!scroller) return;
    const left = scroller.scrollLeft > 1;
    const right = scroller.scrollLeft + scroller.clientWidth < scroller.scrollWidth - 1;
    setEdges((current) =>
      current.left === left && current.right === right ? current : { left, right },
    );
  }, []);

  useLayoutEffect(placeIndicator, [placeIndicator]);

  // Tab widths change as counts stream in and when the web font swaps in; the
  // bar's own width decides whether the fades are needed at all.
  useEffect(() => {
    const scroller = scrollerRef.current;
    if (!scroller) return;

    const observer = new ResizeObserver(() => {
      placeIndicator();
      updateEdges();
    });
    observer.observe(scroller);
    for (const button of tabRefs.current.values()) observer.observe(button);

    return () => observer.disconnect();
  }, [placeIndicator, updateEdges]);

  // Horizontal-only, so a tab change never drags the page vertically.
  useEffect(() => {
    const scroller = scrollerRef.current;
    const button = tabRefs.current.get(active);
    if (!scroller || !button) return;

    const start = button.offsetLeft;
    const end = start + button.offsetWidth;
    const gutter = 48;

    if (start < scroller.scrollLeft + gutter) {
      scroller.scrollTo({ left: start - gutter, behavior: 'smooth' });
    } else if (end > scroller.scrollLeft + scroller.clientWidth - gutter) {
      scroller.scrollTo({ left: end - scroller.clientWidth + gutter, behavior: 'smooth' });
    }
  }, [active]);

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = tabs.findIndex((tab) => tab.id === active);
    let next: number;

    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = tabs.length - 1;
    else return;

    event.preventDefault();
    const id = tabs[next].id;
    onChange(id);
    tabRefs.current.get(id)?.focus({ preventScroll: true });
  };

  return (
    <div className="relative">
      <div
        ref={scrollerRef}
        role="tablist"
        aria-label="Report sections"
        onKeyDown={onKeyDown}
        onScroll={updateEdges}
        className="no-scrollbar relative flex gap-1 overflow-x-auto rounded-full border border-white/10 bg-zinc-900 p-1 shadow-lg shadow-black/30"
      >
        <span
          ref={indicatorRef}
          aria-hidden
          className="pointer-events-none absolute top-1 bottom-1 left-0 w-0 rounded-full bg-zinc-100 shadow-sm duration-300 ease-out data-ready:transition-[transform,width]"
        />

        {tabs.map((tab) => {
          const selected = tab.id === active;
          return (
            <button
              key={tab.id}
              ref={(node) => {
                if (node) tabRefs.current.set(tab.id, node);
                else tabRefs.current.delete(tab.id);
              }}
              type="button"
              role="tab"
              aria-selected={selected}
              tabIndex={selected ? 0 : -1}
              onClick={() => onChange(tab.id)}
              className={cx(
                'relative z-10 inline-flex shrink-0 items-center gap-2 rounded-full px-3.5 py-1.5 text-sm font-medium whitespace-nowrap transition-colors duration-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-400',
                selected ? 'text-zinc-900' : 'text-zinc-400 hover:bg-white/5 hover:text-zinc-100',
              )}
            >
              {tab.label}
              {tab.count ? (
                <span
                  className={cx(
                    'rounded-full px-1.5 py-px text-[11px] font-semibold tabular-nums transition-colors duration-200',
                    selected ? 'bg-zinc-900/10 text-zinc-600' : 'bg-white/5 text-zinc-500',
                  )}
                >
                  {compact.format(tab.count)}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>

      <div
        aria-hidden
        className={cx(
          'pointer-events-none absolute inset-y-px left-px w-12 rounded-l-full bg-linear-to-r from-zinc-900 to-transparent transition-opacity',
          edges.left ? 'opacity-100' : 'opacity-0',
        )}
      />
      <div
        aria-hidden
        className={cx(
          'pointer-events-none absolute inset-y-px right-px w-12 rounded-r-full bg-linear-to-l from-zinc-900 to-transparent transition-opacity',
          edges.right ? 'opacity-100' : 'opacity-0',
        )}
      />
    </div>
  );
}
