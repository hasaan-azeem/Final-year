import React from 'react'

const FeaturesSkeleton = () => {
  return (
    <div className="animate-pulse px-6 md:px-20 py-20 space-y-10">
      
      {/* Heading */}
      <div className="h-8 w-1/3 bg-white/10 rounded-lg" />

      {/* Cards */}
      <div className="grid md:grid-cols-3 gap-6">
        {[...Array(6)].map((_, i) => (
          <div
            key={i}
            className="h-40 bg-white/5 rounded-xl border border-white/10"
          />
        ))}
      </div>
    </div>
  )
}

export default FeaturesSkeleton