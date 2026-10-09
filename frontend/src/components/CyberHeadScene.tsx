import { useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Float, Line, Sparkles } from "@react-three/drei";
import { clsx, type ClassValue } from "clsx";
import { motion, useReducedMotion } from "motion/react";
import { twMerge } from "tailwind-merge";
import * as THREE from "three";

type Point3 = [number, number, number];

function OrbitRing({ position, radius, speed, rotation }: { position: Point3; radius: number; speed: number; rotation: Point3 }) {
  const ring = useRef<THREE.Mesh>(null);
  useFrame((_, delta) => {
    if (!ring.current) return;
    ring.current.rotation.x += delta * speed * 0.36;
    ring.current.rotation.y += delta * speed * 0.52;
    ring.current.rotation.z += delta * speed;
  });

  return (
    <mesh ref={ring} position={position} rotation={rotation}>
      <torusGeometry args={[radius, 0.014, 10, 128]} />
      <meshBasicMaterial color="#58e4ff" transparent opacity={0.94} toneMapped={false} />
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
      <ambientLight intensity={0.9} />
      <pointLight position={[0.8, 1.8, 2.5]} color="#8eeeff" intensity={3.2} />
      <group ref={subject}>
        <OrbitRing position={[0, 0, 0.78]} radius={1.34} speed={reducedMotion ? 0 : 0.25} rotation={[0.55, 0.18, 0.08]} />
        <OrbitRing position={[0, 0, 0.72]} radius={1.08} speed={reducedMotion ? 0 : -0.34} rotation={[1.14, 0.3, 0.72]} />
        <OrbitRing position={[0, 0, 0.84]} radius={0.82} speed={reducedMotion ? 0 : 0.42} rotation={[0.3, 1.12, 0.25]} />
        <Float speed={reducedMotion ? 0 : 0.7} rotationIntensity={reducedMotion ? 0 : 0.018} floatIntensity={reducedMotion ? 0 : 0.035}>
          <mesh position={[1.55, 0.82, 1.0]} rotation={[0.3, 0.5, 0.15]}>
            <octahedronGeometry args={[0.11, 0]} />
            <meshStandardMaterial color="#d9faff" emissive="#00bce8" emissiveIntensity={1.4} metalness={0.75} roughness={0.2} />
          </mesh>
          <mesh position={[-1.55, -0.72, 1.0]} rotation={[0.25, 0.2, 0.4]}>
            <icosahedronGeometry args={[0.075, 0]} />
            <meshStandardMaterial color="#9cecff" emissive="#00bce8" emissiveIntensity={1.2} metalness={0.8} roughness={0.18} />
          </mesh>
        </Float>
        <Sparkles position={[0, 0, 0.45]} count={38} scale={[4.1, 2.6, 0.45]} size={2.3} speed={reducedMotion ? 0 : 0.3} opacity={0.8} color="#a8efff" />
        {corners.map((points, index) => <Line key={index} points={points} color="#8cecff" lineWidth={1.1} transparent opacity={0.85} />)}
      </group>
    </>
  );
}

export default function CyberHeadScene({ className }: { className?: string }) {
  const reducedMotion = useReducedMotion() ?? false;
  const classes = twMerge(clsx("cyber-scene relative isolate h-[220px] w-full overflow-hidden rounded-[28px] shadow-[0_22px_65px_rgba(9,52,79,0.2)] sm:h-[250px] md:h-[300px]", className));

  return (
    <motion.figure
      role="img"
      aria-label="Chrome android artwork framed by animated cyan security geometry"
      className={classes}
      initial={reducedMotion ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, ease: "easeOut" }}
    >
      <motion.img
        src="/HEAD.jpg"
        alt=""
        className="absolute inset-y-0 right-0 z-[1] h-full w-[88%] object-cover object-[55%_42%] md:w-[78%]"
        style={{ maskImage: "linear-gradient(90deg, transparent 0%, #000 10%, #000 100%)" }}
        animate={reducedMotion ? { scale: 1.04 } : { scale: [1.04, 1.085, 1.04], x: [0, 5, 0], y: [0, -3, 0] }}
        transition={{ duration: 9, repeat: Infinity, ease: "easeInOut" }}
      />
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
        <span className="scene-wordmark absolute bottom-5 left-4 font-display text-5xl uppercase leading-none sm:text-6xl">Defense</span>
        <motion.span
          className="scene-glass absolute left-3 top-3 flex items-center gap-2 px-3 py-2 text-[9px] uppercase tracking-[0.08em]"
          initial={reducedMotion ? false : { opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.55, delay: 0.16 }}
        >
          <span className="size-1.5 animate-pulse bg-cyan-400 shadow-[0_0_9px_#00c8ff]" /> Visual guard / active
        </motion.span>
        <motion.span
          className="scene-glass absolute right-3 top-12 flex items-center gap-2 px-3 py-2 text-[9px] uppercase tracking-[0.08em]"
          animate={reducedMotion ? { y: 0 } : { y: [0, -5, 0] }}
          transition={{ duration: 5.4, delay: 0.45, repeat: Infinity, ease: "easeInOut" }}
        >
          <span className="flex h-3 items-end gap-0.5" aria-hidden>
            <i className="h-1 w-0.5 bg-cyan-200/60" /><i className="h-2 w-0.5 bg-cyan-200" /><i className="h-1.5 w-0.5 bg-cyan-200/75" />
          </span>
          Policy / enforced
        </motion.span>
        <motion.span
          className="scene-glass absolute bottom-3 right-3 px-3 py-2 font-mono text-[9px] uppercase tracking-[0.06em]"
          animate={reducedMotion ? { y: 0 } : { y: [0, 3, 0] }}
          transition={{ duration: 6.2, delay: 0.25, repeat: Infinity, ease: "easeInOut" }}
        >
          Threat surface / monitored
        </motion.span>
      </figcaption>
    </motion.figure>
  );
}