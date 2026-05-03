import { useState, useRef, useEffect } from "react";
import {
  Lock,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Eye,
  EyeOff,
  Globe,
  User,
  Tag,
  ShieldCheck,
  CheckCircle2,
  Sparkles,
} from "lucide-react";

const AUTH_TYPES = [
  { value: "credential", label: "Credential (Username / Password)" },
];

// ── Smart-guess the login URL from the main scanned URL ──────────────────────
function guessLoginUrl(mainUrl) {
  if (!mainUrl) return "";
  try {
    const u = new URL(
      mainUrl.startsWith("http") ? mainUrl : `https://${mainUrl}`,
    );
    return `${u.origin}/login`;
  } catch {
    return "";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
export default function AuthForm({ onChange, mainUrl = "" }) {
  const [enabled, setEnabled] = useState(false);
  const [open, setOpen] = useState(false);
  const [authType, setAuthType] = useState("credential");
  const [loginUrl, setLoginUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [userField, setUserField] = useState("username");
  const [passField, setPassField] = useState("password");
  const [showPw, setShowPw] = useState(false);
  // track whether user manually edited loginUrl
  const [urlTouched, setUrlTouched] = useState(false);

  const wrapperRef = useRef(null);

  // Auto-fill loginUrl from mainUrl whenever mainUrl changes
  // — but only if the user hasn't manually typed something different
  useEffect(() => {
    if (!urlTouched) {
      setLoginUrl(guessLoginUrl(mainUrl));
    }
  }, [mainUrl, urlTouched]);

  // Close panel on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target))
        setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  // Emit full state upward
  const emit = (patch = {}) => {
    onChange({
      enabled,
      auth_type: authType,
      login_url: loginUrl,
      username,
      password,
      login_user_field: userField,
      login_pass_field: passField,
      ...patch,
    });
  };

  // Main button: toggle enabled + open/close panel
  const handleButtonClick = () => {
    const next = !enabled;
    setEnabled(next);
    setOpen(next);
    // When enabling, pre-fill loginUrl if empty / untouched
    if (next && !urlTouched) {
      const guess = guessLoginUrl(mainUrl);
      setLoginUrl(guess);
      emit({ enabled: next, login_url: guess });
    } else {
      emit({ enabled: next });
    }
  };

  const inputCls =
    "w-full py-2.5 rounded-lg text-sm bg-slate-800/70 border border-slate-700/80 " +
    "text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500/50 transition";

  const isFilled = enabled && username.trim() && password.trim();

  return (
    <div ref={wrapperRef} className="relative shrink-0">
      {/* ── Toggle button ─────────────────────────────────────────────────── */}
      <button
        type="button"
        onClick={handleButtonClick}
        className={`
          flex items-center gap-2 px-4 py-3 rounded-xl text-sm font-medium
          transition cursor-pointer border whitespace-nowrap
          ${
            enabled
              ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-400"
              : "bg-transparent border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500"
          }
        `}
      >
        {isFilled ? (
          <CheckCircle2 size={14} className="text-emerald-400" />
        ) : (
          <Lock
            size={14}
            className={enabled ? "text-emerald-400" : "text-slate-500"}
          />
        )}
        <span>Auth Scan</span>
        {/* Chevron — only toggles open/close, doesn't disable */}
        <span
          onClick={(e) => {
            e.stopPropagation();
            if (enabled) setOpen((o) => !o);
          }}
        >
          {open ? (
            <ChevronUp size={13} className="text-emerald-500/70" />
          ) : (
            <ChevronDown
              size={13}
              className={enabled ? "text-emerald-500/70" : "text-slate-600"}
            />
          )}
        </span>
      </button>

      {/* Filled hint */}
      {isFilled && !open && (
        <p className="text-[10px] text-emerald-500/70 text-center mt-2 leading-none">
          ✓ credentials set
        </p>
      )}

      {/* ── Dropdown panel ────────────────────────────────────────────────── */}
      {open && (
        <div
          className="absolute top-full left-0 mt-2 z-50 w-80 sm:w-[26rem] rounded-xl
          bg-gray-950 border border-emerald-500/25 shadow-2xl shadow-black/60 overflow-hidden"
        >
          {/* Header */}
          <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800 bg-slate-900/50">
            <Lock size={13} className="text-emerald-400" />
            <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">
              Login Configuration
            </span>
            <span className="ml-auto text-[10px] text-slate-600">
              auto-used during scan
            </span>
          </div>

          <div className="p-4 space-y-4">
            {/* Auth type */}
            <div>
              <label className="block text-xs text-slate-500 mb-1.5 font-medium">
                Auth Type
              </label>
              <div className="relative">
                <ShieldCheck
                  size={13}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none"
                />
                <select
                  value={authType}
                  onChange={(e) => {
                    setAuthType(e.target.value);
                    emit({ auth_type: e.target.value });
                  }}
                  className={`${inputCls} pl-8 pr-8 appearance-none cursor-pointer`}
                >
                  {AUTH_TYPES.map((t) => (
                    <option
                      key={t.value}
                      value={t.value}
                      className="bg-gray-950 text-white"
                    >
                      {t.label}
                    </option>
                  ))}
                </select>
                <ChevronDown
                  size={13}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none"
                />
              </div>
            </div>

            {/* Login URL — pre-filled with smart guess */}
            <div>
              <label className="block text-xs text-slate-500 mb-1.5 font-medium">
                Login Page URL
                {/* Show "auto-detected" badge only when pre-filled & untouched */}
                {!urlTouched && loginUrl && (
                  <span
                    className="ml-2 inline-flex items-center gap-1 text-[10px] text-emerald-500/80
                    bg-emerald-500/10 border border-emerald-500/20 rounded-full px-2 py-0.5"
                  >
                    <Sparkles size={9} />
                    auto-detected
                  </span>
                )}
              </label>
              <div className="relative">
                <Globe
                  size={13}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none"
                />
                <input
                  type="text"
                  placeholder="https://example.com/login"
                  value={loginUrl}
                  onChange={(e) => {
                    setUrlTouched(true);
                    setLoginUrl(e.target.value);
                    emit({ login_url: e.target.value });
                  }}
                  className={`${inputCls} pl-8 pr-4`}
                />
              </div>
              {/* Re-detect hint if user has changed it */}
              {urlTouched && mainUrl && (
                <button
                  type="button"
                  onClick={() => {
                    const guess = guessLoginUrl(mainUrl);
                    setLoginUrl(guess);
                    setUrlTouched(false);
                    emit({ login_url: guess });
                  }}
                  className="mt-1 text-[10px] text-slate-600 hover:text-emerald-400 transition cursor-pointer"
                >
                  ↺ Reset to auto-detected ({guessLoginUrl(mainUrl)})
                </button>
              )}
            </div>

            {/* Credentials */}
            <div>
              <label className="block text-xs text-slate-500 mb-1.5 font-medium">
                Credentials <span className="text-red-400">*</span>
              </label>
              <div className="grid grid-cols-2 gap-3">
                <div className="relative">
                  <User
                    size={13}
                    className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none"
                  />
                  <input
                    type="text"
                    placeholder="Username"
                    value={username}
                    onChange={(e) => {
                      setUsername(e.target.value);
                      emit({ username: e.target.value });
                    }}
                    className={`${inputCls} pl-8 pr-3`}
                  />
                </div>

                <div className="relative">
                  <Lock
                    size={13}
                    className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none"
                  />
                  <input
                    type={showPw ? "text" : "password"}
                    placeholder="Password"
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      emit({ password: e.target.value });
                    }}
                    className={`${inputCls} pl-8 pr-8`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw((p) => !p)}
                    tabIndex={-1}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400 transition cursor-pointer"
                  >
                    {showPw ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                </div>
              </div>
            </div>

            {/* HTML field names */}
            <div>
              <label className="block text-xs text-slate-500 mb-1.5 font-medium">
                HTML Field Names
                <span className="text-slate-600 font-normal ml-1">
                  (name= on the login form)
                </span>
              </label>
              <div className="grid grid-cols-2 gap-3">
                <div className="relative">
                  <Tag
                    size={13}
                    className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none"
                  />
                  <input
                    type="text"
                    placeholder="username"
                    value={userField}
                    onChange={(e) => {
                      setUserField(e.target.value);
                      emit({ login_user_field: e.target.value });
                    }}
                    className={`${inputCls} pl-8 pr-3 font-mono text-xs`}
                  />
                </div>
                <div className="relative">
                  <Tag
                    size={13}
                    className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none"
                  />
                  <input
                    type="text"
                    placeholder="password"
                    value={passField}
                    onChange={(e) => {
                      setPassField(e.target.value);
                      emit({ login_pass_field: e.target.value });
                    }}
                    className={`${inputCls} pl-8 pr-3 font-mono text-xs`}
                  />
                </div>
              </div>
            </div>

            {/* Warning */}
            <div className="flex items-start gap-2 px-3 py-2.5 rounded-lg bg-amber-500/8 border border-amber-500/20">
              <AlertTriangle
                size={13}
                className="text-amber-400 shrink-0 mt-0.5"
              />
              <p className="text-xs text-amber-400/80 leading-relaxed">
                Only provide credentials for systems you own or have explicit
                permission to test.
              </p>
            </div>

            {/* Done */}
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="w-full py-2.5 rounded-lg bg-emerald-500 text-slate-900 font-semibold
                text-sm hover:bg-emerald-400 transition cursor-pointer flex items-center
                justify-center gap-2"
            >
              <CheckCircle2 size={14} />
              Done — click Start Scan to continue
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
