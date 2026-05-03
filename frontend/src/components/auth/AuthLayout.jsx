export default function AuthLayout({ title, subtitle, children, footer }) {
  return (
    <div className="min-h-screen relative flex items-center justify-center bg-[#020617] px-4 overflow-hidden">
      {/* Background Glow */}
      <div className="absolute w-[500px] h-[500px] bg-emerald-500/10 blur-[120px] rounded-full top-[-100px] left-1/2 -translate-x-1/2" />

      <div className="absolute w-[400px] h-[400px] bg-blue-500/10 blur-[120px] rounded-full bottom-[-100px] right-[-100px]" />

      {/* Card */}
      <div className="w-full max-w-md bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl p-8 shadow-2xl relative z-10">
        {/* Title */}
        <h1 className="text-2xl font-semibold text-white text-center">
          {title}
        </h1>

        {/* Subtitle */}
        <p className="text-sm text-gray-400 text-center mt-2">{subtitle}</p>

        {/* Content */}
        <div className="mt-8">{children}</div>

        {/* Footer */}
        {footer && (
          <div className="mt-6 text-center text-sm text-gray-400">{footer}</div>
        )}
      </div>
    </div>
  );
}
