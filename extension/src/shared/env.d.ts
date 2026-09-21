declare const __MS_VERSION__: string;
declare const __MS_TARGET__: 'firefox' | 'chrome';
declare const __MS_DEV__: boolean;
/** True only in the local preview harness (scripts/preview.mjs), never in shipped builds. */
declare const __MS_PREVIEW__: boolean;

declare module '*.css' {
  const css: string;
  export default css;
}
