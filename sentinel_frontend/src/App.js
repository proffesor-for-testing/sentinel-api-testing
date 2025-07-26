import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import TestRuns from './pages/TestRuns';
import TestRunDetail from './pages/TestRunDetail';
import Specifications from './pages/Specifications';
import TestCases from './pages/TestCases';
import './index.css';

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/test-runs" element={<TestRuns />} />
          <Route path="/test-runs/:runId" element={<TestRunDetail />} />
          <Route path="/specifications" element={<Specifications />} />
          <Route path="/test-cases" element={<TestCases />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;
