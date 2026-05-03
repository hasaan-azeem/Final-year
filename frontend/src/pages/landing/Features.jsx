import React from "react";
import CTA from "../../components/Landing/Common/CTA";
import FeatureHero from "@/components/Landing/Features/FeatureHero";
import FeatureMain from "@/components/Landing/Features/FeatureMain";

export default function Features() {
  return (
    <>
      {/* Hero Section */}
      <FeatureHero />
      {/* Main Features Section */}
      <FeatureMain />
      {/* Call to Action Section */}
      <CTA />
    </>
  );
}
