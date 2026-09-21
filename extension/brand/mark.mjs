// MailShark brand geometry: the single source for the logo in PNG icons, UI components and docs.
// Shark silhouette (facing right) designed on a 64×40 grid.

export const SHARK_PATH =
  'M62.5 21.2C60.8 17.6 55.6 14.6 47.4 13.3C44.2 12.8 40.9 12.6 37.9 12.7L31.2 2.6C30.8 2 29.9 2.2 29.8 2.9L28.4 12.9' +
  'C21.6 13.8 15.6 15.6 11 17.8L3.7 8.3C3.2 7.6 2.1 8.1 2.3 8.9L5.4 20.6L2.2 32.4C2 33.2 3 33.7 3.5 33.1L11.2 24.1' +
  'C16.2 26.2 22.3 27.6 28.9 28.3L25 36.6C24.7 37.3 25.5 37.9 26.1 37.5L35.1 29C41.7 29.2 48.4 28.6 53.8 27.2' +
  'C58.4 26 61.7 24.2 62.6 22.4C62.8 22 62.7 21.6 62.5 21.2Z';

export const SHARK_EYE = { cx: 51.6, cy: 19.4, r: 1.35 };
export const SHARK_GILLS = ['M43.6 17.2C42.9 19.3 42.9 21.6 43.6 23.7', 'M46.2 16.9C45.5 19 45.5 21.3 46.2 23.4', 'M48.8 16.8C48.2 18.8 48.2 21 48.8 23'];
export const SHARK_MOUTH = 'M53.6 24.4C56.2 24.4 58.7 23.8 60.4 22.9';

/** App icon: shark on an abyss-to-lagoon squircle with a sonar arc. */
export function appIconSvg(size = 128) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 128 128">
  <defs>
    <linearGradient id="bg" x1="10" y1="0" x2="118" y2="128" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#0B1B33"/>
      <stop offset="0.55" stop-color="#0A2B4A"/>
      <stop offset="1" stop-color="#0E5E75"/>
    </linearGradient>
    <linearGradient id="fish" x1="20" y1="30" x2="110" y2="100" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#E9FBFF"/>
      <stop offset="1" stop-color="#8EEFF0"/>
    </linearGradient>
    <radialGradient id="glow" cx="64" cy="118" r="70" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#38E1D6" stop-opacity="0.55"/>
      <stop offset="1" stop-color="#38E1D6" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect x="4" y="4" width="120" height="120" rx="30" fill="url(#bg)"/>
  <rect x="4" y="4" width="120" height="120" rx="30" fill="url(#glow)"/>
  <rect x="4.5" y="4.5" width="119" height="119" rx="29.5" fill="none" stroke="#FFFFFF" stroke-opacity="0.12"/>
  <path d="M22 96C34 88 46 88 58 96C70 104 82 104 94 96C100 92 105 90 110 90" fill="none" stroke="#38E1D6" stroke-opacity="0.55" stroke-width="4" stroke-linecap="round"/>
  <g transform="translate(14 30) scale(1.56)">
    <path d="${SHARK_PATH}" fill="url(#fish)"/>
    <circle cx="${SHARK_EYE.cx}" cy="${SHARK_EYE.cy}" r="${SHARK_EYE.r}" fill="#0B1B33"/>
    ${SHARK_GILLS.map((d) => `<path d="${d}" fill="none" stroke="#0B1B33" stroke-opacity="0.55" stroke-width="0.9" stroke-linecap="round"/>`).join('')}
  </g>
</svg>`;
}

/** Small-size icon (16–32 px): simplified, no gills, stronger contrast. */
export function smallIconSvg(size = 32) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 128 128">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="128" y2="128" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#0B1B33"/>
      <stop offset="1" stop-color="#0E6A80"/>
    </linearGradient>
  </defs>
  <rect x="0" y="0" width="128" height="128" rx="32" fill="url(#bg)"/>
  <g transform="translate(8 26) scale(1.75)">
    <path d="${SHARK_PATH}" fill="#E9FBFF"/>
    <circle cx="${SHARK_EYE.cx}" cy="${SHARK_EYE.cy}" r="1.8" fill="#0B1B33"/>
  </g>
</svg>`;
}
