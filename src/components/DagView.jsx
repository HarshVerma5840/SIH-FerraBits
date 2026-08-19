import React, { useState } from 'react';
import { MOCK_DATA } from '../data/mockData';
import { ArrowLeft } from 'lucide-react';
import Xarrow, { Xwrapper } from 'react-xarrows';
import { motion, AnimatePresence } from 'framer-motion';

export default function DagView({ selectedPackageId, onBack }) {
  const [selectedMethod, setSelectedMethod] = useState(null);
  const [selectedOccurrence, setSelectedOccurrence] = useState(null);

  const selectedPkg = MOCK_DATA.packages.find(p => p.id === selectedPackageId);
  
  const activeOccurrences = selectedMethod ? MOCK_DATA.occurrences[selectedMethod] : [];
  const activeDependencies = selectedOccurrence ? MOCK_DATA.dependencies[selectedOccurrence] : [];

  // Animation variants for Framer Motion
  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, x: -20 },
    show: { opacity: 1, x: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
  };

  return (
    <div className="min-h-screen bg-gray-50 p-12 overflow-x-auto relative font-sans">
      <button 
        onClick={onBack}
        className="fixed top-8 left-8 z-50 bg-white border border-gray-200 px-4 py-2 rounded-lg shadow-sm flex items-center gap-2 hover:bg-gray-100 transition-colors text-sm font-medium text-gray-700"
      >
        <ArrowLeft size={16} /> Back to Dashboard
      </button>

      <Xwrapper>
        <div className="flex flex-row items-start gap-24 relative z-10 min-w-max pt-20 pl-8 pb-32">
          
          {/* COLUMN 1: PACKAGE */}
          <motion.div 
            className="flex flex-col gap-6 w-64 shrink-0" style={{ marginTop: '50px' }}
            initial="hidden" animate="show" variants={containerVariants}
          >
             <motion.h2 variants={itemVariants} className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Package</motion.h2>
             <motion.div id="pkg-box" variants={itemVariants} className="bg-red-50 border-2 border-red-500 rounded-xl p-5 shadow-sm">
               <span className="text-red-700 font-bold text-lg">{selectedPkg.name}</span>
             </motion.div>
          </motion.div>

          {/* COLUMN 2: METHODS */}
          <motion.div 
            className="flex flex-col gap-6 w-64 shrink-0" style={{ marginTop: '50px' }}
            initial="hidden" animate="show" variants={containerVariants}
          >
             <motion.h2 variants={itemVariants} className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Methods Used</motion.h2>
             {MOCK_DATA.methods.map((method) => {
               const isSelected = selectedMethod === method.id;
               return (
                 <motion.div 
                   id={`method-${method.id}`}
                   key={method.id}
                   variants={itemVariants}
                   onClick={() => {
                     setSelectedMethod(method.id);
                     setSelectedOccurrence(null);
                   }}
                   className={`
                     bg-white border border-gray-300 rounded-lg py-4 px-5 shadow-sm font-mono text-sm text-gray-800 
                     cursor-pointer transition-all hover:border-blue-500 hover:text-blue-600 hover:shadow-md
                     ${isSelected ? 'border-blue-500 ring-2 ring-blue-200' : ''}
                   `}
                 >
                   {method.name}
                 </motion.div>
               )
             })}
          </motion.div>

          {/* COLUMN 3: OCCURRENCES */}
          <AnimatePresence>
            {selectedMethod && (
              <motion.div 
                className="flex flex-col gap-6 w-80 shrink-0" style={{ marginTop: '50px' }}
                initial="hidden" animate="show" exit="hidden" variants={containerVariants}
              >
                <motion.h2 variants={itemVariants} className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Occurrences</motion.h2>
                {activeOccurrences.map((occ) => {
                  const isSelected = selectedOccurrence === occ.id;
                  return (
                    <motion.div 
                      id={`occ-${occ.id}`}
                      key={occ.id}
                      variants={itemVariants}
                      onClick={() => setSelectedOccurrence(occ.id)}
                      className={`
                        bg-slate-800 text-slate-100 rounded-lg p-5 font-mono text-sm shadow-md border border-slate-700 
                        cursor-pointer transition-all hover:bg-slate-700 hover:-translate-y-1 hover:shadow-lg
                        ${isSelected ? 'ring-2 ring-slate-400 bg-slate-700' : ''}
                      `}
                    >
                      {occ.name}
                    </motion.div>
                  )
                })}
              </motion.div>
            )}
          </AnimatePresence>

          {/* COLUMN 4: DEPENDENCIES */}
          <AnimatePresence>
            {selectedOccurrence && (
              <motion.div 
                className="flex flex-col gap-6 w-64 shrink-0" style={{ marginTop: '50px' }}
                initial="hidden" animate="show" exit="hidden" variants={containerVariants}
              >
                <motion.h2 variants={itemVariants} className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Internal Logic</motion.h2>
                {activeDependencies.map((dep) => (
                  <motion.div 
                    id={`dep-${dep.id}`}
                    key={dep.id}
                    variants={itemVariants}
                    className="bg-white border border-gray-200 border-l-4 border-l-blue-500 rounded-lg p-5 font-mono text-sm text-gray-700 shadow-sm transition-all hover:shadow-md"
                  >
                    {dep.name}
                  </motion.div>
                ))}
              </motion.div>
            )}
          </AnimatePresence>

          {/* ARROWS (React-Xarrows) */}
          {/* Package -> Methods */}
          {MOCK_DATA.methods.map((method) => (
            <Xarrow 
              key={`arrow-pkg-${method.id}`}
              start="pkg-box" 
              end={`method-${method.id}`} 
              animateDrawing={0.6}
              color="#d1d5db"
              strokeWidth={2}
              path="smooth"
              showHead={false}
            />
          ))}

          {/* Method -> Occurrences */}
          {selectedMethod && activeOccurrences.map((occ) => (
            <Xarrow 
              key={`arrow-meth-${occ.id}`}
              start={`method-${selectedMethod}`} 
              end={`occ-${occ.id}`} 
              animateDrawing={0.6}
              color="#d1d5db"
              strokeWidth={2}
              path="smooth"
              showHead={false}
            />
          ))}

          {/* Occurrence -> Dependencies */}
          {selectedOccurrence && activeDependencies.map((dep) => (
            <Xarrow 
              key={`arrow-occ-${dep.id}`}
              start={`occ-${selectedOccurrence}`} 
              end={`dep-${dep.id}`} 
              animateDrawing={0.6}
              color="#d1d5db"
              strokeWidth={2}
              path="smooth"
              showHead={false}
            />
          ))}
          
        </div>
      </Xwrapper>
    </div>
  );
}
