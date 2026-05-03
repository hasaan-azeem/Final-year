import { useEffect } from "react";
import { X } from "lucide-react";

const Toast = ({ message, type = "success", onClose }) => {
  useEffect(() => {
    const timer = setTimeout(onClose, 5000);
    return () => clearTimeout(timer);
  }, [onClose]);

  const styles = {
    success:
      "bg-[#059669]/60 border border-[#059669]/30 shadow-[#059669]/20",
    error:
      "bg-red-500/60 border border-red-400/30 shadow-red-500/20",
  };

  return (
    <div className="fixed top-6 right-6 z-50 animate-toast-in">
      <div
        className={`flex items-start gap-4 px-6 py-4 mt-20 rounded-2xl backdrop-blur-xl shadow-xl text-white ${styles[type]}`}
      >
        {/* Message */}
        <p className="text-sm leading-relaxed">
          {message}
        </p>

        {/* Close */}
        <button
          onClick={onClose}
          className="ml-2 mt-0.5 rounded-full p-1 hover:bg-white/10 transition"
        >
          <X size={16} />
        </button>
      </div>
    </div>
  );
};

export default Toast;
