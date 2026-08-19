import React, { useState } from 'react';
import { MOCK_DATA } from '../data/mockData';
import { ArrowLeft, Box, Code, GitMerge, FileCode2, Zap } from 'lucide-react';

export default function DagViewV2({ selectedPackageId, onBack }) {
  const [selectedMethod, setSelectedMethod] = useState(null);
  const [selectedOccurrence, setSelectedOccurrence] = useState(null);

  const selectedPkg = MOCK_DATA.packages.find(p => p.id === selectedPackageId);
  
  const activeOccurrences = selectedMethod ? MOCK_DATA.occurrences[selectedMethod] : [];
  const activeDependencies = selectedOccurrence ? MOCK_DATA.dependencies[selectedOccurrence] : [];

  return (
    <div className="min-h-screen bg-[conic-gradient(at_top_right,_var(--tw-gradient-stops))] from-slate-50 via-gray-50 to-white p-8 md:p-12 overflow-x-auto relative font-sans text-slate-800">
      
      {/* Header / Back Button */}
      <div className="fixed top-6 left-6 z-50">
        <button 
          onClick={onBack}
          className="group bg-white border border-slate-200 px-5 py-2.5 rounded-xl shadow-lg shadow-blue-500/5 flex items-center gap-3 hover:bg-slate-50 transition-all duration-300 text-sm font-semibold text-slate-600"
        >
          <ArrowLeft size={18} className="group-hover:-translate-x-1 transition-transform" /> 
          Back to FerraBits
        </button>
      </div>

      {/* Solid Line SVG Container with Draw Animation */}
      <div className="absolute inset-0 pointer-events-none z-0">
        <svg className="w-full h-full" fill="none">
          <defs>
            {/* Arrowhead Markers */}
            <marker id="arrow-blue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" className="fill-blue-400" />
            </marker>
            <marker id="arrow-indigo" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" className="fill-indigo-400" />
            </marker>
            <marker id="arrow-purple" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" className="fill-purple-400" />
            </marker>
          </defs>

           {/* Package to Methods */}
           {MOCK_DATA.methods.map((method, i) => {
             const startY = 202; // Center of Package card
             const endY = 157 + i * 78; // Center of Method cards
             return (
               <path 
                 key={method.id} 
                 d={`M 288 ${startY} C 336 ${startY}, 336 ${endY}, 376 ${endY}`} 
                 className="stroke-blue-400 animate-[drawLine_0.5s_ease-out_forwards]" 
                 strokeWidth="2"
                 strokeDasharray="1000" 
                 strokeDashoffset="1000"
                 markerEnd="url(#arrow-blue)"
               />
             );
           })}

           {/* Selected Method to Occurrences */}
           {selectedMethod && activeOccurrences.map((occ, i) => {
             const methodIndex = MOCK_DATA.methods.findIndex(m => m.id === selectedMethod);
             const startY = 157 + methodIndex * 78;
             const endY = 161 + i * 94;
             return (
               <path 
                 key={occ.id} 
                 d={`M 640 ${startY} C 688 ${startY}, 688 ${endY}, 728 ${endY}`} 
                 className="stroke-indigo-400 animate-[drawLine_0.5s_ease-out_forwards]" 
                 strokeWidth="2"
                 strokeDasharray="1000" 
                 strokeDashoffset="1000"
                 markerEnd="url(#arrow-indigo)"
               />
             );
           })}

           {/* Selected Occurrence to Dependencies */}
           {selectedOccurrence && activeDependencies.map((dep, i) => {
             const occIndex = activeOccurrences.findIndex(o => o.id === selectedOccurrence);
             const startY = 161 + occIndex * 94;
             const endY = 210 + i * 84; 
             return (
               <path 
                 key={dep.id} 
                 d={`M 1056 ${startY} C 1104 ${startY}, 1104 ${endY}, 1144 ${endY}`} 
                 className="stroke-purple-400 animate-[drawLine_0.5s_ease-out_forwards]" 
                 strokeWidth="2"
                 strokeDasharray="1000" 
                 strokeDashoffset="1000"
                 markerEnd="url(#arrow-purple)"
               />
             );
           })}
        </svg>
      </div>

      <div className="flex flex-row items-start gap-24 relative z-10 min-w-max pt-20 pl-8">
        
        {/* COLUMN 1: PACKAGE */}
        <div className="flex flex-col gap-4 w-64 shrink-0 animate-slideInRight" style={{ marginTop: '50px' }}>
           <div className="flex items-center gap-2 mb-2">
             <Box className="w-4 h-4 text-slate-400" />
             <h2 className="text-xs font-bold text-slate-500 uppercase tracking-widest">Entry Package</h2>
           </div>
           
           <div className="relative group bg-white border-2 border-red-400 rounded-2xl p-6 shadow-xl shadow-red-500/10">
             <div className="flex items-center justify-between mb-2">
                <span className="text-red-700 font-extrabold text-xl tracking-tight">{selectedPkg.name}</span>
                <Zap className="w-5 h-5 text-red-500 fill-red-500" />
             </div>
             <p className="text-xs text-red-500 font-semibold uppercase tracking-wider">Vulnerability Traced</p>
           </div>
        </div>

        {/* COLUMN 2: METHODS */}
        <div className="flex flex-col gap-6 w-64 shrink-0 animate-slideInRight" style={{ marginTop: '50px' }}>
           <div className="flex items-center gap-2 mb-2 -mt-8">
             <Code className="w-4 h-4 text-blue-500" />
             <h2 className="text-xs font-bold text-blue-600 uppercase tracking-widest">Exported Methods</h2>
           </div>
           
           {MOCK_DATA.methods.map((method) => {
             const isSelected = selectedMethod === method.id;
             return (
               <div 
                 key={method.id}
                 onClick={() => {
                   setSelectedMethod(method.id);
                   setSelectedOccurrence(null);
                 }}
                 className={`
                   relative bg-white border rounded-xl py-4 px-6 font-mono text-sm shadow-lg cursor-pointer transition-all duration-300
                   ${isSelected 
                     ? 'border-blue-400 ring-4 ring-blue-50 text-blue-700 shadow-blue-500/20 translate-x-2' 
                     : 'border-slate-200 text-slate-600 hover:border-blue-300 hover:text-blue-600 hover:shadow-xl hover:-translate-y-0.5'}
                 `}
               >
                 {method.name}
               </div>
             )
           })}
        </div>

        {/* COLUMN 3: OCCURRENCES */}
        {selectedMethod && (
          <div className="flex flex-col gap-8 w-80 shrink-0 animate-slideInRight" style={{ marginTop: '50px' }}>
            <div className="flex items-center gap-2 mb-2 -mt-8">
              <FileCode2 className="w-4 h-4 text-indigo-500" />
              <h2 className="text-xs font-bold text-indigo-600 uppercase tracking-widest">Code Occurrences</h2>
            </div>
            
            {activeOccurrences.map((occ) => {
              const isSelected = selectedOccurrence === occ.id;
              return (
                <div 
                  key={occ.id}
                  onClick={() => setSelectedOccurrence(occ.id)}
                  className={`
                    relative bg-slate-900 rounded-xl p-5 font-mono text-sm shadow-xl cursor-pointer transition-all duration-300
                    ${isSelected 
                      ? 'border border-indigo-400 ring-4 ring-indigo-50 text-indigo-300 shadow-indigo-500/20 translate-x-2' 
                      : 'border border-slate-800 text-slate-300 hover:border-indigo-500 hover:text-indigo-200 hover:-translate-y-0.5'}
                  `}
                >
                  <span className="opacity-50 mr-2">{occ.name.split('.')[0]}.</span>
                  <span>{occ.name.split('.')[1]}</span>
                </div>
              )
            })}
          </div>
        )}

        {/* COLUMN 4: DEPENDENCIES */}
        {selectedOccurrence && (
          <div className="flex flex-col gap-6 w-72 shrink-0 animate-slideInRight" style={{ marginTop: '100px' }}>
            <div className="flex items-center gap-2 mb-2 -mt-8">
              <GitMerge className="w-4 h-4 text-purple-500" />
              <h2 className="text-xs font-bold text-purple-600 uppercase tracking-widest">Internal Logic</h2>
            </div>
            
            {activeDependencies.map((dep) => (
              <div 
                key={dep.id}
                className="relative bg-white border border-slate-200 border-l-4 border-l-purple-500 rounded-xl p-5 font-mono text-sm text-slate-700 shadow-lg hover:shadow-xl hover:shadow-purple-500/10 hover:-translate-y-0.5 transition-all duration-300"
              >
                {dep.name}
              </div>
            ))}
          </div>
        )}

      </div>
      
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes drawLine {
          to { stroke-dashoffset: 0; }
        }
      `}} />
    </div>
  );
}
