"use client";

import { useEffect, useState } from "react";
import { animate } from "framer-motion";

export function CountUp({
  to,
  duration = 1.5,
  decimals = 0,
  className,
}: {
  to: number;
  duration?: number;
  decimals?: number;
  className?: string;
}) {
  const [val, setVal] = useState(0);

  useEffect(() => {
    const controls = animate(0, to, {
      duration,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (v) => setVal(v),
    });
    return () => controls.stop();
  }, [to, duration]);

  return <span className={className}>{val.toFixed(decimals)}</span>;
}
