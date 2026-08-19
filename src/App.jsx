import React, { useState } from 'react';
import Dashboard from './components/Dashboard';
import DagView from './components/DagView';

function App() {
  const [selectedPackageId, setSelectedPackageId] = useState(null);

  return (
    <>
      {selectedPackageId ? (
        <DagView 
          selectedPackageId={selectedPackageId} 
          onBack={() => setSelectedPackageId(null)} 
        />
      ) : (
        <Dashboard onPackageSelect={setSelectedPackageId} />
      )}
    </>
  );
}

export default App;
