import React from 'react';

export type SealPhase = 'idle' | 'pressing' | 'sealed' | 'failed';

/**
 * The signature element of the Defense Hall: a wax seal that presses down
 * when a jury notarizes a defense. Once "sealed", the document hash is
 * engraved into the wax. This is the one moment of ceremony in an
 * otherwise plain, functional interface — everything else stays quiet so
 * this can carry the weight.
 */
export const Seal = ({ phase, hash }: { phase: SealPhase; hash?: string }) => {
  const teeth = Array.from({ length: 28 });
  const engraved = hash ? `${hash.slice(0, 4)}···${hash.slice(-4)}` : undefined;

  return (
    <div
      className={[
        'relative w-28 h-28 mx-auto transition-transform duration-300 motion-reduce:transition-none',
        phase === 'pressing' ? 'scale-90 motion-safe:animate-[press_0.35s_ease-out]' : '',
        phase === 'sealed' ? 'scale-100' : '',
        phase === 'idle' ? 'scale-100 opacity-70' : 'opacity-100',
      ].join(' ')}
      role="img"
      aria-label={
        phase === 'sealed'
          ? `Notarized, hash beginning ${hash?.slice(0, 8)}`
          : phase === 'pressing'
          ? 'Sealing in progress'
          : phase === 'failed'
          ? 'Seal rejected'
          : 'Awaiting notarization'
      }
    >
      <svg viewBox="0 0 120 120" className="w-full h-full">
        <defs>
          <radialGradient id="waxGradient" cx="35%" cy="30%" r="75%">
            <stop offset="0%" stopColor={phase === 'failed' ? '#4a4a4a' : '#a6404c'} />
            <stop offset="55%" stopColor={phase === 'failed' ? '#333338' : 'var(--seal)'} />
            <stop offset="100%" stopColor={phase === 'failed' ? '#1c1d22' : 'var(--seal-dark)'} />
          </radialGradient>
        </defs>

        {/* serrated seal edge */}
        <g>
          {teeth.map((_, i) => {
            const angle = (i / teeth.length) * 2 * Math.PI;
            const x1 = 60 + Math.cos(angle) * 52;
            const y1 = 60 + Math.sin(angle) * 52;
            const x2 = 60 + Math.cos(angle) * 58;
            const y2 = 60 + Math.sin(angle) * 58;
            return (
              <line
                key={i}
                x1={x1}
                y1={y1}
                x2={x2}
                y2={y2}
                stroke="var(--gold)"
                strokeWidth={2}
                opacity={0.8}
              />
            );
          })}
        </g>

        <circle cx="60" cy="60" r="50" fill="url(#waxGradient)" stroke="var(--gold)" strokeWidth="1.5" />
        <circle cx="60" cy="60" r="41" fill="none" stroke="var(--gold)" strokeWidth="1" opacity="0.5" />

        {engraved && phase === 'sealed' ? (
          <text
            x="60"
            y="64"
            textAnchor="middle"
            fontFamily="IBM Plex Mono, monospace"
            fontSize="9"
            fill="var(--gold-soft)"
            letterSpacing="0.5"
          >
            {engraved}
          </text>
        ) : (
          <text
            x="60"
            y="65"
            textAnchor="middle"
            fontFamily="Fraunces, serif"
            fontSize="11"
            fill="var(--gold-soft)"
          >
            {phase === 'failed' ? '✕' : 'N'}
          </text>
        )}
      </svg>
      <style>{`
        @keyframes press {
          0% { transform: scale(1); }
          50% { transform: scale(0.82); }
          100% { transform: scale(0.9); }
        }
      `}</style>
    </div>
  );
};
