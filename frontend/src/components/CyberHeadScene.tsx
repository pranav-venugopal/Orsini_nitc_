import { useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Float, Line } from "@react-three/drei";
import { clsx, type ClassValue } from "clsx";
import { motion, useReducedMotion } from "motion/react";
import { twMerge } from "tailwind-merge";
import * as THREE from "three";

type Point3 = [number, number, number];

function OrbitRing({ position, radius, speed }: { position: Point3; radius: number; speed: number }) {
  const ring = useRef<THREE.Mesh>(null);
  useFrame((_, delta) => {
    if (ring.current) ring.current.rotation.z += delta * speed;
  });

  return (
    <mesh ref={ring} position={position} rotation={[0.18, 0.34, 0]}>
      <torusGeometry args={[radius, 0.008, 8, 96]} />
      <meshBasicMaterial color="#50ddff" transparent opacity={0.84} />
    </mesh>
  );
}

function SceneGeometry({ reducedMotion }: { reducedMotion: boolean }) {
  const subject = useRef<THREE.Group>(null);

  useFrame(({ clock, pointer }, delta) => {
    if (!subject.current || reducedMotion) return;
    subject.current.rotation.x = THREE.MathUtils.damp(subject.current.rotation.x, -pointer.y * 0.045, 2.2, delta);
    subject.current.rotation.y = THREE.MathUtils.damp(
      subject.current.rotation.y,
      pointer.x * 0.065 + Math.sin(clock.elapsedTime * 0.16) * 0.018,
      2.2,
      delta,
    );
  });

  const corners: Point3[][] = [
    [[-2.08, 1.24, 0.2], [-1.82, 1.24, 0.2], [-1.82, 1.02, 0.2]],
    [[2.08, 1.24, 0.2], [1.82, 1.24, 0.2], [1.82, 1.02, 0.2]],
    [[-2.08, -1.24, 0.2], [-1.82, -1.24, 0.2], [-1.82, -1.02, 0.2]],
    [[2.08, -1.24, 0.2], [1.82, -1.24, 0.2], [1.82, -1.02, 0.2]],
  ];

  return (
    <>
      <ambientLight intensity={0.8} />
      <pointLight position={[2.5, 1.8, 2]} color="#8eeeff" intensity={2.2} />
      <group ref={subject}>
        <Float speed={reducedMotion ? 0 : 0.7} rotationIntensity={reducedMotion ? 0 : 0.018} floatIntensity={reducedMotion ? 0 : 0.035}>
          <mesh position={[2.02, 0.52, 0.16]} rotation={[0.3, 0.5, 0.15]}>
            <octahedronGeometry args={[0.075, 0]} />
            <meshStandardMaterial color="#d9faff" emissive="#00bce8" emissiveIntensity={0.9} metalness={0.75} roughness={0.2} />
          </mesh>
          <mesh position={[-2.0, -0.5, 0.16]} rotation={[0.25, 0.2, 0.4]}>
            <icosahedronGeometry args={[0.045, 0]} />
            <meshStandardMaterial color="#9cecff" emissive="#00bce8" emissiveIntensity={0.7} metalness={0.8} roughness={0.18} />
          </mesh>
        </Float>
        <OrbitRing position={[1.68, 0.05, 0.11]} radius={0.58} speed={reducedMotion ? 0 : 0.12} />
        <OrbitRing position={[-1.7, 0.02, 0.12]} radius={0.48} speed={reducedMotion ? 0 : -0.1} />
        {corners.map((points, index) => <Line key={index} points={points} color="#8cecff" lineWidth={1.1} transparent opacity={0.85} />)}
      </group>
    </>
  );
}

export default function CyberHeadScene({ className }: { className?: string }) {
  const reducedMotion = useReducedMotion() ?? false;
  const classes = twMerge(clsx("cyber-scene relative isolate h-[190px] w-full overflow-hidden sm:h-[220px] md:h-[258px]", className));

  return (
    <motion.figure
      role="img"
      aria-label="Chrome android artwork framed by animated cyan security geometry"
      className={classes}
      initial={reducedMotion ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, ease: "easeOut" }}
    >
      <img src="/HEAD.jpg" alt="" className="absolute inset-0 size-full object-cover object-[55%_42%]" />
      <Canvas
        aria-hidden="true"
        className="!absolute inset-0 z-10"
        dpr={reducedMotion ? 1 : [1, 1.25]}
        camera={{ position: [0, 0, 5.3], fov: 39 }}
        gl={{ alpha: true, antialias: false, powerPreference: "low-power" }}
        frameloop={reducedMotion ? "demand" : "always"}
        fallback={<span className="sr-only">3D effects unavailable; the reference artwork remains visible.</span>}
      >
        <SceneGeometry reducedMotion={reducedMotion} />
      </Canvas>
      <figcaption className="pointer-events-none absolute inset-0 z-20">
        <span className="scene-glass absolute left-3 top-3 flex items-center gap-2 px-2.5 py-1.5 text-[9px] uppercase tracking-[0.08em]">
          <span className="size-1.5 animate-pulse bg-cyan-400 shadow-[0_0_9px_#00c8ff]" /> Visual guard / active
        </span>
        <span className="scene-glass absolute bottom-3 right-3 px-2.5 py-1.5 font-mono text-[9px] uppercase tracking-[0.06em]">
          Threat surface / monitored
        </span>
      </figcaption>
    </motion.figure>
  );
}