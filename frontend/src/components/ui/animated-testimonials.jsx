/* eslint-disable react-hooks/exhaustive-deps */
/* eslint-disable no-unused-vars */
"use client";

import { useEffect, useState } from "react";
import { IconArrowLeft, IconArrowRight } from "@tabler/icons-react";
import { AnimatePresence, motion } from "motion/react";

export const AnimatedTestimonials = ({
  testimonials = [],
  autoplay = false,
}) => {
  const [active, setActive] = useState(0);

  const handleNext = () => {
    if (!testimonials.length) return;
    setActive((prev) => (prev + 1) % testimonials.length);
  };

  const handlePrev = () => {
    if (!testimonials.length) return;
    setActive((prev) => (prev - 1 + testimonials.length) % testimonials.length);
  };

  const isActive = (index) => index === active;

  useEffect(() => {
    if (!autoplay || !testimonials.length) return;

    const interval = setInterval(() => {
      handleNext();
    }, 5000);

    return () => clearInterval(interval);
  }, [autoplay, handleNext, testimonials]);

  const randomRotateY = () => Math.floor(Math.random() * 21) - 10;

  if (!testimonials.length) return null;

  const current = testimonials[active];

  return (
    <div className="mx-auto max-w-sm px-4 py-20 font-sans antialiased md:max-w-4xl md:px-8 lg:px-12">
      <div className="relative grid grid-cols-1 gap-20 md:grid-cols-2">
        {/* Images */}
        <div>
          <div className="relative h-80 w-full">
            <AnimatePresence>
              {testimonials.map((testimonial, index) => (
                <motion.div
                  key={testimonial.src || index}
                  initial={{
                    opacity: 0,
                    scale: 0.9,
                    z: -100,
                    rotate: randomRotateY(),
                  }}
                  animate={{
                    opacity: isActive(index) ? 1 : 0.7,
                    scale: isActive(index) ? 1 : 0.95,
                    z: isActive(index) ? 0 : -100,
                    rotate: isActive(index) ? 0 : randomRotateY(),
                    zIndex: isActive(index)
                      ? 40
                      : testimonials.length + 2 - index,
                    y: isActive(index) ? [0, -80, 0] : 0,
                  }}
                  exit={{
                    opacity: 0,
                    scale: 0.9,
                    z: 100,
                    rotate: randomRotateY(),
                  }}
                  transition={{
                    duration: 0.4,
                    ease: "easeInOut",
                  }}
                  className="absolute inset-0 origin-bottom"
                >
                  <img
                    src={testimonial.src}
                    alt={testimonial.name || "testimonial"}
                    width={500}
                    height={500}
                    draggable={false}
                    className="h-full w-full rounded-3xl object-cover object-center"
                  />
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>

        {/* Text */}
        <div className="flex flex-col justify-between py-2">
          <AnimatePresence mode="wait">
            <motion.div
              key={active}
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              exit={{ y: -20, opacity: 0 }}
              transition={{ duration: 0.25 }}
            >
              <h3 className="text-2xl font-bold text-white dark:text-white">
                {current?.name}
              </h3>

              <p className="text-sm text-gray-500 dark:text-neutral-500">
                {current?.designation}
              </p>

              <motion.p className="mt-8 text-lg text-gray-500 dark:text-neutral-300">
                {current?.quote?.split(" ").map((word, index) => (
                  <motion.span
                    key={index}
                    initial={{
                      filter: "blur(10px)",
                      opacity: 0,
                      y: 5,
                    }}
                    animate={{
                      filter: "blur(0px)",
                      opacity: 1,
                      y: 0,
                    }}
                    transition={{
                      duration: 0.2,
                      delay: 0.02 * index,
                    }}
                    className="inline-block"
                  >
                    {word}&nbsp;
                  </motion.span>
                ))}
              </motion.p>
            </motion.div>
          </AnimatePresence>

          {/* Buttons */}
          <div className="flex gap-4 pt-4 md:pt-4">
            <button
              onClick={handlePrev}
              className="group/button flex h-8 w-8 items-center justify-center rounded-full bg-gray-100 dark:bg-neutral-800 cursor-pointer"
            >
              <IconArrowLeft className="h-5 w-5 text-black transition-transform duration-300 group-hover/button:rotate-12 dark:text-neutral-400 cursor-pointer" />
            </button>

            <button
              onClick={handleNext}
              className="group/button flex h-8 w-8 items-center justify-center rounded-full bg-gray-100 dark:bg-neutral-800 cursor-pointer"
            >
              <IconArrowRight className="h-5 w-5 text-black transition-transform duration-300 group-hover/button:-rotate-12 dark:text-neutral-400 cursor-pointer" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
