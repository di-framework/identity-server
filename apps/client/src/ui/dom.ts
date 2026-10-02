import { GlobalWindow } from 'happy-dom';

const dom = new GlobalWindow({ url: 'http://localhost/' });
const names = [
  'window',
  'document',
  'navigator',
  'HTMLElement',
  'Element',
  'Node',
  'DocumentFragment',
  'SVGElement',
  'MutationObserver',
  'Event',
  'KeyboardEvent',
  'MouseEvent',
  'NodeFilter',
  'getComputedStyle',
] as const;

for (const name of names) {
  Object.defineProperty(globalThis, name, {
    configurable: true,
    writable: true,
    value: name === 'getComputedStyle' ? dom.getComputedStyle.bind(dom) : dom[name],
  });
}

globalThis.requestAnimationFrame = dom.requestAnimationFrame.bind(
  dom,
) as unknown as typeof globalThis.requestAnimationFrame;
globalThis.cancelAnimationFrame = dom.cancelAnimationFrame.bind(
  dom,
) as unknown as typeof globalThis.cancelAnimationFrame;
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
