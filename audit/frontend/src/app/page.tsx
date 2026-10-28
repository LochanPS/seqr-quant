import { MarketingNav } from "@/components/marketing/MarketingNav";
import { Hero } from "@/components/marketing/Hero";
import { MirageReveal } from "@/components/marketing/MirageReveal";
import { EdgeVsOrigin } from "@/components/marketing/EdgeVsOrigin";
import { HowItWorks } from "@/components/marketing/HowItWorks";
import { TryItLive } from "@/components/marketing/TryItLive";
import { WhyNow } from "@/components/marketing/WhyNow";
import { ResearchStat } from "@/components/marketing/ResearchStat";
import { Pricing } from "@/components/marketing/Pricing";
import { FinalCTA } from "@/components/marketing/FinalCTA";
import { Footer } from "@/components/marketing/Footer";

export default function MarketingPage() {
  return (
    <main className="relative" style={{ background: "#F4F1E9", color: "#171512" }}>
      <MarketingNav />
      <Hero />
      <MirageReveal />
      <EdgeVsOrigin />
      <HowItWorks />
      <TryItLive />
      <WhyNow />
      <ResearchStat />
      <Pricing />
      <FinalCTA />
      <Footer />
    </main>
  );
}
