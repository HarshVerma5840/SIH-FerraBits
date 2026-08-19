import React from 'react';
import { MOCK_DATA } from '../data/mockData';
import { ShieldCheck, AlertOctagon, Package, ArrowRight } from 'lucide-react';

export default function DashboardV2({ onPackageSelect }) {
  return (
    <div className="min-h-screen bg-[conic-gradient(at_top_right,_var(--tw-gradient-stops))] from-slate-50 via-gray-50 to-white p-12 font-sans flex flex-col items-center">
      <div className="max-w-5xl w-full">
        
        {/* Header Section */}
        <div className="mb-12 text-center flex flex-col items-center">
          <div className="inline-flex items-center justify-center p-3 bg-white shadow-xl shadow-blue-500/10 rounded-2xl mb-6 border border-slate-200">
            <ShieldCheck className="text-blue-600 w-8 h-8 mr-3" />
            <h1 className="text-4xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-blue-700 to-indigo-500 tracking-tight">
              FerraBits
            </h1>
          </div>
          <p className="text-slate-500 text-lg max-w-2xl">
            Enterprise Supply Chain Security. Select a package below to execute a deep-dive trace on its dependency graph.
          </p>
        </div>

        {/* Packages Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {MOCK_DATA.packages.map((pkg) => {
            if (pkg.isVulnerable) {
              return (
                <div 
                  key={pkg.id}
                  onClick={() => onPackageSelect(pkg.id)}
                  className="group relative bg-white border border-red-200 rounded-2xl p-6 cursor-pointer overflow-hidden shadow-lg shadow-red-500/10 transition-all duration-300 hover:-translate-y-1 hover:shadow-xl hover:shadow-red-500/20"
                >
                  <div className="absolute top-0 right-0 w-32 h-32 bg-red-50 rounded-full blur-2xl -mr-10 -mt-10 transition-transform group-hover:scale-150"></div>
                  
                  <div className="flex items-center justify-between relative z-10 mb-6">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-red-100 rounded-lg text-red-600">
                        <AlertOctagon className="w-5 h-5 animate-pulse" />
                      </div>
                      <span className="text-red-700 font-bold text-lg tracking-tight">{pkg.name}</span>
                    </div>
                  </div>
                  
                  <div className="relative z-10 flex items-center justify-between">
                    <span className="inline-block px-3 py-1 bg-red-50 text-red-600 text-xs font-bold uppercase tracking-wider rounded-full border border-red-200">
                      Vulnerability Detected
                    </span>
                    <ArrowRight className="text-red-400 w-5 h-5 opacity-0 -translate-x-4 group-hover:opacity-100 group-hover:translate-x-0 transition-all" />
                  </div>
                </div>
              );
            }

            return (
              <div 
                key={pkg.id}
                className="group relative bg-white/50 border border-slate-200 rounded-2xl p-6 overflow-hidden shadow-sm transition-all duration-300"
              >
                <div className="flex items-center justify-between relative z-10 mb-6 opacity-70">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-slate-100 rounded-lg text-slate-500">
                      <Package className="w-5 h-5" />
                    </div>
                    <span className="text-slate-600 font-semibold text-lg tracking-tight">{pkg.name}</span>
                  </div>
                </div>
                
                <div className="relative z-10 opacity-70">
                  <span className="inline-block px-3 py-1 bg-green-50 text-green-600 text-xs font-bold uppercase tracking-wider rounded-full border border-green-200">
                    Safe
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
