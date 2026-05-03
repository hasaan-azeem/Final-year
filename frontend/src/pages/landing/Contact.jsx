// CONTACT PAGE - Where users can send us messages
// This page includes a contact form that sends data to a backend server
import React, { useState } from "react";
import Toast from "../../components/Landing/Common/Toast";
import CTA from "../../components/Landing/Common/CTA";

const Contact = () => {
  // STATE: Track if form is being submitted
  const [loading, setLoading] = useState(false);

  // STATE: Track success/error messages to show to user
  // null = no message, otherwise it's an object with {type, message}
  const [toast, setToast] = useState(null);

  // FUNCTION: Handle form submission
  // This runs when user clicks the Submit button
  async function handleSubmit(event) {
    // Prevent the page from refreshing (default form behavior)
    event.preventDefault();

    // Show loading state
    setLoading(true);

    // Get the form data from the input fields
    const formData = {
      email: event.target.email.value,
      firstName: event.target.firstName.value,
      lastName: event.target.lastName.value,
      message: event.target.message.value,
    };

    // Try to send the data to the server
    try {
      // Send POST request to backend
      const response = await fetch("http://localhost:5000/api/contact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      // Get the response data
      const data = await response.json();

      // Check if it was successful
      if (response.ok) {
        // Show success message
        setToast({ type: "success", message: data.success });
        // Clear the form
        event.target.reset();
      } else {
        // Show error message
        setToast({
          type: "error",
          message: data.error || "Failed to send message",
        });
      }
    } catch {
      // If something went wrong (server down, network error, etc.)
      setToast({
        type: "error",
        message: "Server error. Please try again later.",
      });
    } finally {
      // Always stop loading when done (success or error)
      setLoading(false);
    }
  }

  return (
    <>
      {/* Show toast message if there is one */}
      {toast && (
        <Toast
          type={toast.type}
          message={toast.message}
          onClose={() => setToast(null)}
        />
      )}

      {/* ========================================
          SECTION 1: HERO SECTION
      ======================================== */}
      <section className="relative w-full h-screen overflow-hidden bg-linear-to-b from-gray-950 to-gray-900 -mb-5 py-32">
        <div className="max-w-7xl mx-auto px-4 md:px-12 flex justify-center flex-col md:flex-row items-center gap-10">
          {/* Text Content */}
          <div className="md:w-3/4 flex flex-col justify-center py-15">
            <h1 className="text-3xl md:text-4xl font-bold text-gray-100 mb-6">
              How can we help?
            </h1>

            <p className="text-gray-300 text-lg mb-6">
              Whether you have inquiries about our security tools, need
              technical support, or wish to share feedback we're here to help.
            </p>

            <a
              href="#get-started"
              className="inline-flex justify-center items-center w-fit px-8 py-4 bg-[#059669]/80 text-gray-100 font-semibold rounded-lg shadow-lg hover:bg-[#059669] transition"
            >
              Drop us a Line
            </a>
          </div>

          {/* Image with glow effect */}
          <div className="md:w-1/4 relative flex justify-center">
            <div className="relative">
              {/* Decorative glow */}
              <div className="absolute w-72 h-72 bg-[#059669] opacity-20 blur-3xl rounded-full"></div>
              <img
                src="/images/contact.webp"
                alt="Contact Illustration"
                className="relative w-full max-w-md object-contain"
              />
            </div>
          </div>
        </div>
        <div className="items-center justify-center hidden md:block">
          <img
            src="hero-grid.svg"
            alt="Hero Grid"
            className="w-full max-w-7xl h-auto pt-1"
          />
        </div>
      </section>

      {/* ========================================
          SECTION 2: CONTACT FORM
      ======================================== */}
      <section
        id="get-started"
        className="w-full bg-linear-to-b from-gray-900 to-gray-950"
      >
        <div className="max-w-7xl mx-auto py-24 px-4 md:px-12 grid grid-cols-1 md:grid-cols-2 gap-12">
          {/* LEFT SIDE: Contact Information */}
          <div>
            <h2 className="text-3xl md:text-4xl font-bold text-gray-100">
              Get in touch
            </h2>
            <p className="mt-6 text-gray-300 text-lg max-w-md">
              For general inquiries, submit the form and we'll get your message
              in front of the right person.
            </p>
            <p className="mt-6 text-lg text-gray-300">
              For press and media inquiries contact{" "}
              <a
                href="mailto:webxgaurd@gmail.com"
                className="text-[#059669] underline"
              >
                webxgaurd@gmail.com
              </a>
            </p>

            {/* Social Media Icons */}
            <div className="flex space-x-6 mt-10">
              {/* Facebook */}
              <a
                href="https://www.facebook.com/yourpage"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-300 hover:text-[#059669] transition-colors"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="w-8 h-8"
                  viewBox="0 0 24 24"
                  fill="currentColor"
                >
                  <path d="M22 12c0-5.522-4.477-10-10-10S2 6.478 2 12c0 4.991 3.657 9.128 8.438 9.878v-6.988H7.898v-2.89h2.54V9.797c0-2.507 1.492-3.89 3.777-3.89 1.094 0 2.238.195 2.238.195v2.462h-1.26c-1.243 0-1.63.772-1.63 1.562v1.875h2.773l-.443 2.89h-2.33v6.988C18.343 21.128 22 16.991 22 12z" />
                </svg>
              </a>

              {/* Twitter */}
              <a
                href="https://twitter.com/yourprofile"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-300 hover:text-[#059669] transition-colors"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="w-8 h-8"
                  viewBox="0 0 24 24"
                  fill="currentColor"
                >
                  <path d="M23 3a10.9 10.9 0 01-3.14 1.53A4.48 4.48 0 0022.4.36a9.05 9.05 0 01-2.88 1.1A4.52 4.52 0 0016.88 0c-2.63 0-4.77 2.13-4.77 4.76 0 .37.04.73.12 1.08A12.8 12.8 0 013 1.64a4.75 4.75 0 00-.64 2.39c0 1.65.84 3.11 2.12 3.97a4.48 4.48 0 01-2.16-.6v.06c0 2.3 1.64 4.22 3.81 4.66a4.52 4.52 0 01-2.15.08 4.77 4.77 0 004.45 3.3A9.04 9.04 0 010 19.54a12.8 12.8 0 006.92 2.03c8.3 0 12.84-6.87 12.84-12.83 0-.2 0-.42-.01-.63A9.18 9.18 0 0023 3z" />
                </svg>
              </a>

              {/* LinkedIn */}
              <a
                href="https://www.linkedin.com/in/yourprofile"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-300 hover:text-[#059669] transition-colors"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="w-8 h-8"
                  viewBox="0 0 24 24"
                  fill="currentColor"
                >
                  <path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-10h3v10zm-1.5-11.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.784 1.764-1.75 1.764zm13.5 11.268h-3v-5.604c0-1.337-.026-3.061-1.865-3.061-1.867 0-2.153 1.46-2.153 2.968v5.697h-3v-10h2.879v1.367h.041c.401-.757 1.379-1.554 2.841-1.554 3.039 0 3.604 2.002 3.604 4.605v5.582z" />
                </svg>
              </a>
            </div>
          </div>

          {/* RIGHT SIDE: Contact Form */}
          <div>
            <form className="space-y-6" onSubmit={handleSubmit}>
              {/* Email Field */}
              <div>
                <label className="text-lg font-medium text-gray-300">
                  Business Email*
                </label>
                <input
                  type="email"
                  name="email"
                  required
                  className="mt-2 w-full rounded-lg bg-[#0b1224] border border-white/10 px-4 py-3 text-gray-300 focus:ring-1 focus:ring-[#059669]"
                />
              </div>

              {/* First and Last Name Fields */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="text-lg font-medium text-gray-300">
                    First Name*
                  </label>
                  <input
                    type="text"
                    name="firstName"
                    required
                    className="mt-2 w-full rounded-lg bg-[#0b1224] border border-white/10 px-4 py-3 text-gray-300 focus:ring-1 focus:ring-[#059669]"
                  />
                </div>

                <div>
                  <label className="text-lg font-medium text-gray-300">
                    Last Name*
                  </label>
                  <input
                    type="text"
                    name="lastName"
                    required
                    className="mt-2 w-full rounded-lg bg-[#0b1224] border border-white/10 px-4 py-3 text-gray-300 focus:ring-1 focus:ring-[#059669]"
                  />
                </div>
              </div>

              {/* Message Field */}
              <div>
                <label className="text-lg font-medium text-gray-300">
                  Message*
                </label>
                <textarea
                  name="message"
                  rows="5"
                  required
                  className="mt-2 w-full rounded-lg bg-[#0b1224] border border-white/10 px-4 py-3 text-gray-300 focus:ring-1 focus:ring-[#059669]"
                ></textarea>
              </div>

              {/* Privacy Policy Notice */}
              <p className="text-sm text-gray-400">
                By submitting this form, you agree to our{" "}
                <a href="/privacy-policy" className="underline text-[#059669]">
                  Privacy Policy
                </a>
                .
              </p>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={loading}
                className="w-fit px-8 py-4 bg-[#059669] text-gray-100 cursor-pointer font-semibold rounded-lg shadow-lg hover:bg-[#059669] transition disabled:opacity-50"
              >
                {/* Show different text when loading */}
                {loading ? "SENDING..." : "SUBMIT"}
              </button>
            </form>
          </div>
        </div>
      </section>

      <CTA />
    </>
  );
};

// Export the component
export default Contact;
