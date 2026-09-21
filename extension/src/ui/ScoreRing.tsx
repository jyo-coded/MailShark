import { useEffect, useState } from 'preact/hooks';
import type { Verdict } from '../../../engine/src/types';

const TONE: Record<Verdict, string> = { danger: 'var(--ms-danger)', caution: 'var(--ms-caution)', safe: 'var(--ms-safe)' };

/** Animated risk ring (0–100). The arc sweeps in on mount. */
export function ScoreRing({ score, verdict, size = 84, stroke = 7, label = 'risk' }: { score: number; verdict: Verdict; size?: number; stroke?: number; label?: string }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const [shown, setShown] = useState(0);
  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(score));
    return () => cancelAnimationFrame(id);
  }, [score]);
  const offset = c * (1 - Math.max(0, Math.min(100, shown)) / 100);
  return (
    <div class="ms-ring" style={{ width: `${size}px`, height: `${size}px` }} role="img" aria-label={`Risk ${score} out of 100`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle class="ms-ring-track" cx={size / 2} cy={size / 2} r={r} fill="none" stroke-width={stroke} />
        <circle class="ms-ring-value" cx={size / 2} cy={size / 2} r={r} fill="none" stroke={TONE[verdict]} stroke-width={stroke} stroke-dasharray={c} stroke-dashoffset={offset} />
      </svg>
      <div class="ms-ring-label" style={{ fontSize: `${Math.round(size * 0.3)}px`, color: TONE[verdict] }}>
        <div>
          {score}
          {size >= 64 && <small>{label}</small>}
        </div>
      </div>
    </div>
  );
}
