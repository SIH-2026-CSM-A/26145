import React, { useLayoutEffect, useMemo, useRef } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { Line, Grid } from '@react-three/drei';
import * as THREE from 'three';
import { MAX } from './sim';

const CYAN = '#5ee6ff', HOST = '#9cc4ff';

function dotTexture() {
  const c = document.createElement('canvas'); c.width = c.height = 64;
  const g = c.getContext('2d'), r = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  r.addColorStop(0, 'rgba(255,255,255,1)'); r.addColorStop(0.25, 'rgba(255,255,255,0.8)'); r.addColorStop(1, 'rgba(255,255,255,0)');
  g.fillStyle = r; g.fillRect(0, 0, 64, 64);
  return new THREE.CanvasTexture(c);
}

// keep the whole stage (x from -6 to +6) in frame at any panel aspect
function Fit() {
  const { camera, size } = useThree();
  const want = 12.6, tan = Math.tan(THREE.MathUtils.degToRad(camera.fov / 2));
  useLayoutEffect(() => {
    const d = Math.max(want / (2 * tan * (size.width / size.height)), 5.6 / (2 * tan));
    camera.position.set(0, d * 0.16, d);
    camera.lookAt(0, 0.05, 0);
  }, [camera, size, tan]);
  return null;
}

function Particles({ sim, rate, still, enclaveAt, labels, place }) {
  const tex = useMemo(dotTexture, []);
  const [dots, sparks] = useMemo(() => [0, 1].map(() => {
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(new Float32Array(MAX * 3), 3));
    g.setAttribute('color', new THREE.BufferAttribute(new Float32Array(MAX * 3), 3));
    return g;
  }), []);
  const tmp = useMemo(() => [0, 0, 0], []), col = useMemo(() => new THREE.Color(), []), v = useMemo(() => new THREE.Vector3(), []);
  const base = useMemo(() => new THREE.Color(CYAN), []);
  useFrame(({ camera, size }, dt) => {
    sim.step(still ? 0 : Math.min(dt, 0.05), rate.current);
    const screen = (p) => { v.set(...p).project(camera); return [((v.x + 1) / 2) * size.width, ((1 - v.y) / 2) * size.height]; };
    const [ex, ey] = screen([4.2, 0.1, 0]);
    enclaveAt.current = { x: ex, y: ey };
    for (const l of labels) place(l.key, ...screen(l.at));
    let n = 0, m = 0;
    for (const q of sim.particles) {
      if (!q.live) continue;
      sim.pos(q, tmp);
      const [g, i] = q.big ? [sparks, m++] : [dots, n++];
      g.attributes.position.array.set(tmp, i * 3);
      if (q.big) col.set(q.color); else col.copy(base).multiplyScalar(0.6 + 0.6 * Math.sin(Math.PI * q.t));
      g.attributes.color.array.set([col.r, col.g, col.b], i * 3);
    }
    for (const [g, k] of [[dots, n], [sparks, m]]) {
      g.setDrawRange(0, k); g.attributes.position.needsUpdate = true; g.attributes.color.needsUpdate = true;
    }
  });
  const mat = (size) => <pointsMaterial size={size} map={tex} vertexColors transparent depthWrite={false} blending={THREE.AdditiveBlending} toneMapped={false} />;
  return <><points geometry={dots}>{mat(0.24)}</points><points geometry={sparks}>{mat(0.7)}</points></>;
}

function Enclave() {
  const g = useRef();
  const edges = useMemo(() => new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(0.9, 0)), []);
  useFrame((_, dt) => { if (g.current) { g.current.rotation.y += dt * 0.25; g.current.rotation.x += dt * 0.08; } });
  return (
    <group position={[4.2, 0.1, 0]}>
      <group ref={g}><lineSegments geometry={edges}><lineBasicMaterial color={CYAN} transparent opacity={0.9} toneMapped={false} /></lineSegments></group>
      <mesh><sphereGeometry args={[0.38, 24, 24]} /><meshBasicMaterial color={CYAN} transparent opacity={0.35} toneMapped={false} /></mesh>
      <mesh><boxGeometry args={[2.4, 3, 1.8]} /><meshBasicMaterial color={CYAN} transparent opacity={0.035} depthWrite={false} /></mesh>
      <lineSegments><edgesGeometry args={[new THREE.BoxGeometry(2.4, 3, 1.8)]} /><lineBasicMaterial color={CYAN} transparent opacity={0.28} /></lineSegments>
    </group>
  );
}

function Gate() {
  const chev = (x) => [[x - 0.16, 0.36, 0], [x + 0.16, 0, 0], [x - 0.16, -0.36, 0]];
  return (
    <group>
      {[-0.28, 0.28].map((z) => (
        <mesh key={z} position={[0, 0.1, z]}><boxGeometry args={[0.06, 3.3, 0.06]} /><meshBasicMaterial color={CYAN} toneMapped={false} /></mesh>
      ))}
      <mesh position={[0, 0.1, 0]} rotation={[0, Math.PI / 2, 0]}><planeGeometry args={[0.56, 3.3]} />
        <meshBasicMaterial color={CYAN} transparent opacity={0.1} side={THREE.DoubleSide} depthWrite={false} blending={THREE.AdditiveBlending} /></mesh>
      {[-0.3, 0.05, 0.4].map((x) => <Line key={x} points={chev(x)} position={[0, 0.1, 0.35]} color={CYAN} lineWidth={2.5} transparent opacity={0.9} />)}
    </group>
  );
}

function Network({ hosts }) {
  const links = useMemo(() => hosts.flatMap((h, i) => (i % 3 === 0 ? [[h, hosts[(i + 5) % hosts.length]]] : [])), [hosts]);
  return (
    <group>
      {hosts.map((h, i) => (
        <mesh key={i} position={h}><sphereGeometry args={[0.07, 12, 12]} /><meshBasicMaterial color={HOST} toneMapped={false} /></mesh>
      ))}
      {links.map(([a, b], i) => <Line key={i} points={[a, b]} color={HOST} lineWidth={1} transparent opacity={0.25} />)}
    </group>
  );
}

export default function Scene3D({ sim, hosts, rate, still, enclaveAt, labels, place }) {
  return (
    <Canvas dpr={[1, 2]} camera={{ fov: 30, near: 0.1, far: 100 }} gl={{ antialias: true, alpha: true }} data-testid="hero-webgl">
      <Fit />
      <Grid position={[0, -2.4, 0]} args={[40, 40]} cellSize={0.5} sectionSize={2.5} cellColor="#1c2b52" sectionColor="#2a4a8a"
            fadeDistance={26} fadeStrength={1.6} infiniteGrid />
      <Network hosts={hosts} />
      <Gate />
      <Enclave />
      <Line points={[[3.2, -1.95, 0.3], [-3.3, -1.95, 0.3]]} color="#7a869e" lineWidth={1.5} dashed dashSize={0.18} gapSize={0.14} transparent opacity={0.7} />
      <Particles sim={sim} rate={rate} still={still} enclaveAt={enclaveAt} labels={labels} place={place} />
    </Canvas>
  );
}
