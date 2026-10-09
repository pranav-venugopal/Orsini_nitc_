import { useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Float, Line, Sparkles } from "@react-three/drei";
import { motion, useReducedMotion } from "motion/react";
import * as THREE from "three";

type SceneMode = "monitor" | "redteam";
type Point3 = [number, number, number];

const shieldShape = new THREE.Shape();
shieldShape.moveTo(0, 1.12);
shieldShape.quadraticCurveTo(0.52, 0.88, 0.82, 0.73);
shieldShape.lineTo(0.71, 0.04);
shieldShape.quadraticCurveTo(0.58, -0.66, 0, -1.08);
shieldShape.quadraticCurveTo(-0.58, -0.66, -0.71, 0.04);
shieldShape.lineTo(-0.82, 0.73);
shieldShape.quadraticCurveTo(-0.52, 0.88, 0, 1.12);

function GyroRing({ radius, speed, color, rotation }: { radius: number; speed: number; color: string; rotation: Point3 }) {
  const ring = useRef<THREE.Mesh>(null);
  useFrame((_, delta) => {
    if (!ring.current) return;
    ring.current.rotation.x += delta * speed * 0.42;
    ring.current.rotation.y += delta * speed * 0.68;
    ring.current.rotation.z += delta * speed;
  });

  return (
    <mesh ref={ring} rotation={rotation}>
      <torusGeometry args={[radius, 0.012, 8, 112]} />
      <meshBasicMaterial color={color} transparent opacity={0.78} toneMapped={false} />
    </mesh>
  );
}

function MonitoringGeometry({ reducedMotion }: { reducedMotion: boolean }) {
  const shield = useRef<THREE.Mesh>(null);
  useFrame(({ clock, pointer }, delta) => {
    if (!shield.current || reducedMotion) return;
    shield.current.rotation.y = THREE.MathUtils.damp(shield.current.rotation.y, pointer.x * 0.12 + Math.sin(clock.elapsedTime * 0.22) * 0.06, 2, delta);
    shield.current.rotation.x = THREE.MathUtils.damp(shield.current.rotation.x, -pointer.y * 0.07, 2, delta);
  });

  return (
    <>
      <ambientLight intensity={1.05} />
      <pointLight position={[-1, 1.6, 2.4]} color="#9beaff" intensity={3.4} />
      <pointLight position={[1.8, -0.8, 1]} color="#31b8ff" intensity={1.4} />
      <GyroRing radius={1.52} speed={reducedMotion ? 0 : 0.14} color="#a8edff" rotation={[0.92, 0.22, 0.18]} />
      <GyroRing radius={1.28} speed={reducedMotion ? 0 : -0.22} color="#32c9ff" rotation={[0.3, 1.08, 0.64]} />
      <GyroRing radius={1.05} speed={reducedMotion ? 0 : 0.3} color="#d8f8ff" rotation={[1.24, 0.15, 0.28]} />
      <Float speed={reducedMotion ? 0 : 0.8} floatIntensity={reducedMotion ? 0 : 0.1} rotationIntensity={reducedMotion ? 0 : 0.035}>
        <mesh ref={shield} position={[0, 0, 0.1]}>
          <extrudeGeometry args={[shieldShape, { depth: 0.12, bevelEnabled: true, bevelSegments: 3, steps: 1, bevelSize: 0.04, bevelThickness: 0.035 }]} />
          <meshPhysicalMaterial color="#8ce8ff" emissive="#058abd" emissiveIntensity={0.34} transparent opacity={0.4} metalness={0.72} roughness={0.12} transmission={0.34} thickness={0.6} />
        </mesh>
        <mesh position={[0, 0.02, 0.29]}>
          <octahedronGeometry args={[0.24, 0]} />
          <meshPhysicalMaterial color="#e2faff" emissive="#00aada" emissiveIntensity={1.1} metalness={0.68} roughness={0.12} />
        </mesh>
      </Float>
      <Sparkles position={[0, 0, 0.35]} count={44} scale={[3.7, 2.7, 0.5]} size={2.1} speed={reducedMotion ? 0 : 0.28} opacity={0.72} color="#9cecff" />
    </>
  );
}

function AdversarialGeometry({ reducedMotion }: { reducedMotion: boolean }) {
  const target = useRef<THREE.Group>(null);
  useFrame(({ clock, pointer }, delta) => {
    if (!target.current || reducedMotion) return;
    target.current.rotation.y = THREE.MathUtils.damp(target.current.rotation.y, pointer.x * 0.1 + clock.elapsedTime * 0.08, 2, delta);
    target.current.rotation.x = THREE.MathUtils.damp(target.current.rotation.x, -pointer.y * 0.075 + Math.sin(clock.elapsedTime * 0.2) * 0.035, 2, delta);
  });

  const vectors: Point3[][] = [
    [[-1.72, 0.95, 0.24], [-0.62, 0.34, 0.3], [0, 0, 0.34]],
    [[1.72, 0.95, 0.24], [0.62, 0.34, 0.3], [0, 0, 0.34]],
    [[-1.72, -0.95, 0.24], [-0.62, -0.34, 0.3], [0, 0, 0.34]],
    [[1.72, -0.95, 0.24], [0.62, -0.34, 0.3], [0, 0, 0.34]],
  ];

  return (
    <>
      <ambientLight intensity={0.9} />
      <pointLight position={[1.5, 1.4, 2]} color="#ff829a" intensity={2.2} />
      <pointLight position={[-1.2, -1, 1.6]} color="#48dfff" intensity={2.8} />
      <group ref={target}>
        <GyroRing radius={1.46} speed={reducedMotion ? 0 : -0.24} color="#6fe5ff" rotation={[0.42, 0.38, 0.12]} />
        <GyroRing radius={1.18} speed={reducedMotion ? 0 : 0.32} color="#ff8095" rotation={[1.16, 0.24, 0.62]} />
        <GyroRing radius={0.88} speed={reducedMotion ? 0 : -0.42} color="#cbeeff" rotation={[0.3, 1.15, 0.28]} />
        <Float speed={reducedMotion ? 0 : 0.9} floatIntensity={reducedMotion ? 0 : 0.08} rotationIntensity={reducedMotion ? 0 : 0.04}>
          <mesh>
            <icosahedronGeometry args={[0.68, 1]} />
            <meshPhysicalMaterial color="#71dff7" emissive="#083b59" emissiveIntensity={0.5} wireframe transparent opacity={0.64} metalness={0.76} roughness={0.18} />
          </mesh>
          <mesh position={[0, 0, 0.02]}>
            <octahedronGeometry args={[0.22, 0]} />
            <meshPhysicalMaterial color="#ff91a1" emissive="#bf2848" emissiveIntensity={1.1} metalness={0.55} roughness={0.16} />
          </mesh>
        </Float>
        {vectors.map((points, index) => <Line key={index} points={points} color={index % 2 ? "#ff8da1" : "#79e8ff"} lineWidth={1.5} transparent opacity={0.86} />)}
        <Sparkles position={[0, 0, 0.4]} count={54} scale={[4, 2.8, 0.5]} size={2.3} speed={reducedMotion ? 0 : 0.4} opacity={0.85} color="#ff9bac" />
      </group>
    </>
  );
}

export default function SectionScene({ mode }: { mode: SceneMode }) {
  const reducedMotion = useReducedMotion() ?? false;
  const monitoring = mode === "monitor";
  const labels = monitoring
    ? ["Telemetry / live", "Policy stream / active", "Signal / verified"]
    : ["Attack vector / scanning", "Control / challenged", "Payload / isolated"];

  return (
    <motion.figure
      role="img"
      aria-label={monitoring ? "Animated 3D security shield and monitoring telemetry" : "Animated 3D adversarial target and attack vectors"}
      className={`section-scene section-scene-${mode} relative isolate h-[190px] w-full overflow-hidden rounded-[28px] border sm:h-[220px] md:h-[270px]`}
      initial={reducedMotion ? false : { opacity: 0, y: 14 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.2 }}
      transition={{ duration: 0.7, ease: [0.22, 0.68, 0.25, 1] }}
    >
      <Canvas
        aria-hidden="true"
        className="!absolute inset-0 z-10"
        dpr={reducedMotion ? 1 : [1, 1.2]}
        camera={{ position: [0, 0, 5.2], fov: 38 }}
        gl={{ alpha: true, antialias: false, powerPreference: "low-power" }}
        frameloop={reducedMotion ? "demand" : "always"}
      >
        {monitoring ? <MonitoringGeometry reducedMotion={reducedMotion} /> : <AdversarialGeometry reducedMotion={reducedMotion} />}
      </Canvas>
      <figcaption className="pointer-events-none absolute inset-0 z-20">
        <motion.span
          className="scene-glass absolute left-3 top-3 px-3 py-2 text-[9px] uppercase tracking-[0.08em]"
          animate={reducedMotion ? { y: 0 } : { y: [0, -4, 0] }}
          transition={{ duration: 5.6, repeat: Infinity, ease: "easeInOut" }}
        >{labels[0]}</motion.span>
        <motion.span
          className="scene-glass absolute right-3 top-11 px-3 py-2 text-[9px] uppercase tracking-[0.08em]"
          animate={reducedMotion ? { y: 0 } : { y: [0, 4, 0] }}
          transition={{ duration: 6.2, delay: 0.35, repeat: Infinity, ease: "easeInOut" }}
        >{labels[1]}</motion.span>
        <span className="scene-glass absolute bottom-3 right-3 px-3 py-2 font-mono text-[9px] uppercase tracking-[0.06em]">{labels[2]}</span>
      </figcaption>
    </motion.figure>
  );
}