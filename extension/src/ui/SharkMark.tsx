// The MailShark mark, animated. States: idle (gentle bob), scan (swimming), safe / caution / danger.
import { SHARK_EYE, SHARK_GILLS, SHARK_PATH } from '../../brand/mark.mjs';

export type SharkState = 'idle' | 'scan' | 'safe' | 'caution' | 'danger';

let uid = 0;

export function SharkMark({ size = 28, state = 'idle', badge = true, still = false }: { size?: number; state?: SharkState; badge?: boolean; still?: boolean }) {
  const id = `msg${++uid}`;
  const tone = state === 'danger' ? '#ff5c77' : state === 'caution' ? '#fbbf24' : state === 'safe' ? '#34d399' : '#38e1d6';
  return (
    <svg class="ms-shark" data-state={state} data-still={still ? '' : undefined} width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <defs>
        <linearGradient id={`${id}bg`} x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
          <stop offset="0" stop-color="#0b1b33" />
          <stop offset="1" stop-color="#0e5e75" />
        </linearGradient>
        <linearGradient id={`${id}fish`} x1="0" y1="0" x2="64" y2="40" gradientUnits="userSpaceOnUse">
          <stop offset="0" stop-color="#f2fdff" />
          <stop offset="1" stop-color="#a5f3f0" />
        </linearGradient>
        <clipPath id={`${id}clip`}>
          <rect x="0" y="0" width="64" height="64" rx="16" />
        </clipPath>
      </defs>
      {badge && <rect x="0" y="0" width="64" height="64" rx="16" fill={`url(#${id}bg)`} />}
      <g clip-path={badge ? `url(#${id}clip)` : undefined}>
        <g class="ms-shark-wave">
          <path
            d="M0 50 q8 -5 16 0 t16 0 t16 0 t16 0 t16 0 t16 0 t16 0 t16 0"
            fill="none"
            stroke={tone}
            stroke-opacity={badge ? 0.75 : 0.9}
            stroke-width="3"
            stroke-linecap="round"
          />
        </g>
        <g class="ms-shark-body">
          <g transform="translate(5 12) scale(0.84)">
            <path d={SHARK_PATH} fill={badge ? `url(#${id}fish)` : 'currentColor'} />
            <circle cx={SHARK_EYE.cx} cy={SHARK_EYE.cy} r={SHARK_EYE.r + 0.3} fill={badge ? '#0b1b33' : 'var(--ms-bg, #000)'} />
            {badge &&
              SHARK_GILLS.map((d) => <path d={d} fill="none" stroke="#0b1b33" stroke-opacity="0.5" stroke-width="1" stroke-linecap="round" />)}
          </g>
        </g>
      </g>
    </svg>
  );
}

/** A dorsal fin gliding along a wave: MailShark's "working" indicator. */
export function Scanner({ width = 220 }: { width?: number }) {
  return (
    <div class="ms-scanner" style={{ width: `${width}px` }} role="progressbar" aria-label="Dissecting">
      <svg class="ms-scanner-wave" viewBox="0 0 400 8" preserveAspectRatio="none" aria-hidden="true">
        <path
          d="M0 4 q10 -4 20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0 t20 0"
          fill="none"
          stroke="currentColor"
          stroke-opacity="0.55"
          stroke-width="1.6"
        />
      </svg>
      <div class="ms-scanner-fin">
        <svg viewBox="0 0 22 13" aria-hidden="true">
          <path d="M1 12.5C6.5 12 10.5 7.5 12.6 1.2C13 0.2 14.2 0.4 14.3 1.4C14.8 5.8 16.8 10 21 12.5Z" fill="currentColor" />
        </svg>
      </div>
    </div>
  );
}
