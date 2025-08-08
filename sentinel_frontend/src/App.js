import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import PrivateRoute from './components/PrivateRoute';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import TestRuns from './pages/TestRuns';
import TestRunDetail from './pages/TestRunDetail';
import Specifications from './pages/Specifications';
import TestCases from './pages/TestCases';
import Analytics from './pages/Analytics';
import './index.css';

function App() {
  return (
    <Router>
      <Routes>
        {/* Public routes */}
        <Route path="/login" element={<Login />} />
        
        {/* Protected routes */}
        <Route path="/*" element={
          <PrivateRoute>
            <Layout>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/test-runs" element={<TestRuns />} />
                <Route path="/test-runs/:runId" element={<TestRunDetail />} />
                <Route path="/specifications" element={<Specifications />} />
                <Route path="/test-cases" element={<TestCases />} />
                <Route path="/analytics" element={<Analytics />} />
              </Routes>
            </Layout>
          </PrivateRoute>
        } />
      </Routes>
    </Router>
  );
}

export default App;
