import React from "react";
import Hero from "../../components/Landing/Home/Hero";
import SectionTwo from "../../components/Landing/Home/AlwaysSecurity";
import SectionThird from "../../components/Landing/Home/Choose";
import SectionFour from "../../components/Landing/Home/Works";
import SectionFive from "../../components/Landing/Home/VulnerabilityAddressed";
import FAQ from "../../components/Landing/Common/FAQ";
import CTA from "../../components/Landing/Common/CTA";
import VulnerabilityScanning from "@/components/Landing/Home/VulnerabilityScanning";

const Home = () => {
 
  return (
    <>
      {/* ========================================
          SECTION 1: HERO SECTION
          This is the first thing users see
      ======================================== */}
      <Hero />
      {/* ========================================
          SECTION 2: ALWAYS-ON SECURITY
          Explains continuous monitoring
      ======================================== */}
      <SectionTwo />
      {/* ========================================
          SECTION 3: WHY CHOOSE WEBXGUARD
          Feature cards showing benefits
      ======================================== */}
      <SectionThird />
      {/* ========================================
          SECTION 4: HOW IT WORKS
          Step-by-step process explanation
      ======================================== */}
      <SectionFour />
      <VulnerabilityScanning />
      {/* ========================================
          SECTION 5: EVERY VULNERABILITY ADDRESSED
          Comprehensive coverage explanation
      ======================================== */}
      <SectionFive />
      {/* ========================================
          SECTION 6: FAQ SECTION
          Imported from FAQ component
      ======================================== */}
      <FAQ/>
      {/* ========================================
          SECTION 7: CALL TO ACTION
          Imported from CTA component
      ======================================== */}
      <CTA />
    </>
  );
};

// Export the component
export default Home;
