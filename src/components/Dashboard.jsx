import React from 'react';
import { MOCK_DATA } from '../data/mockData';

export default function Dashboard({ onPackageSelect }) {
  return (
    <div className="min-h-screen bg-gray-50 p-12 font-sans flex flex-col items-center">
      <div className="max-w-4xl w-full">
        <div className="mb-8">
          <h1 className="text-4xl font-display font-bold text-gray-900 tracking-tight">FerraByte</h1>
          <p className="text-gray-500 mt-2">Select a package to trace its dependencies.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {MOCK_DATA.packages.map((pkg) => (
            <div 
              key={pkg.id}
              onClick={() => {
                if (pkg.isVulnerable) onPackageSelect(pkg.id);
              }}
              className={`
                rounded-xl p-6 shadow-sm transition-all duration-300 flex items-center justify-between
                ${pkg.isVulnerable 
                  ? 'bg-red-50 border-2 border-red-500 cursor-pointer hover:shadow-md hover:-translate-y-1' 
                  : 'bg-green-50 border border-green-200 opacity-80'}
              `}
            >
              <span className={pkg.isVulnerable ? 'font-display text-red-700 font-bold text-xl' : 'font-display text-green-700 font-semibold text-xl'}>
                {pkg.name}
              </span>
              {pkg.isVulnerable && (
                <span className="flex h-4 w-4 relative">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-4 w-4 bg-red-500"></span>
                </span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
