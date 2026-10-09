type PageArtworkProps = { label: string };

export default function PageArtwork({ label }: PageArtworkProps) {
  return (
    <figure className="relative hidden h-24 w-40 shrink-0 overflow-hidden border border-cyan-300/25 bg-[#030b16] md:block">
      <img src="/HEAD.jpg" alt="" className="absolute inset-0 size-full object-cover object-[55%_42%]" />
      <figcaption className="absolute bottom-2 left-2 border border-white/20 bg-[#030b16]/75 px-2 py-1 text-[9px] uppercase text-cyan-100 backdrop-blur">
        {label}
      </figcaption>
    </figure>
  );
}