// frontend/src/features/pow/ui/DayCycleIllustration.tsx

import "./pow.css";

export function DayCycleIllustration() {
  return (
    <div className="illustFrame" aria-hidden="true">
      <div className="dayCycle illustSky">
        <div className="illustSun" />
        <div className="illustMoon" />
        <div className="illustGround" />
      </div>
    </div>
  );
}
