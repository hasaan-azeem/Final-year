export default function AuthButton({ text, loading, disabled }) {
  return (
    <button
      type="submit"
      disabled={disabled || loading}
      className={`w-full py-3 rounded-lg font-medium transition cursor-pointer
      ${
        disabled
          ? "bg-gray-600 cursor-not-allowed"
          : "bg-emerald-600 hover:bg-emerald-700 text-white"
      }
      `}
    >
      {loading ? "Please wait..." : text}
    </button>
  );
}
