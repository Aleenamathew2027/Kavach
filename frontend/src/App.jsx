import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';

import Landing from './pages/Landing';
import Login from './pages/Login';
import Register from './pages/Register';
import UserDashboard from './pages/UserDashboard';
import UserProfile from './pages/UserProfile';
import UserSecurity from './pages/UserSecurity';
import UserAlerts from './pages/UserAlerts';
import MessageScanner from './pages/MessageScanner';
import LinkChecker from './pages/LinkChecker';
import DocumentChecker from './pages/DocumentChecker';
import AdminDashboard from './pages/AdminDashboard';
import GuardianDashboard from './pages/GuardianDashboard';
import ProtectedRoute from './components/ProtectedRoute';
import { getRole } from './services/api';

/**
 * DynamicDashboardRedirect – routes /dashboard to the user's specific role dashboard
 */
function DynamicDashboardRedirect() {
  const role = getRole();
  if (role === 'admin') return <Navigate to="/admin/dashboard" replace />;
  if (role === 'guardian') return <Navigate to="/guardian/dashboard" replace />;
  return <Navigate to="/user/dashboard" replace />;
}

/**
 * App – root router for KAVACH
 */
export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public Routes */}
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* User Role Protected Routes */}
        <Route
          path="/user/dashboard"
          element={
            <ProtectedRoute allowedRoles={['user']}>
              <UserDashboard />
            </ProtectedRoute>
          }
        />
        <Route
          path="/user/messages"
          element={
            <ProtectedRoute allowedRoles={['user']}>
              <MessageScanner />
            </ProtectedRoute>
          }
        />
        <Route
          path="/user/link-checker"
          element={
            <ProtectedRoute allowedRoles={['user']}>
              <LinkChecker />
            </ProtectedRoute>
          }
        />
        <Route
          path="/user/document-checker"
          element={
            <ProtectedRoute allowedRoles={['user']}>
              <DocumentChecker />
            </ProtectedRoute>
          }
        />
        <Route
          path="/user/security"
          element={
            <ProtectedRoute allowedRoles={['user']}>
              <UserSecurity />
            </ProtectedRoute>
          }
        />
        <Route
          path="/user/alerts"
          element={
            <ProtectedRoute allowedRoles={['user']}>
              <UserAlerts />
            </ProtectedRoute>
          }
        />
        <Route
          path="/user/profile"
          element={
            <ProtectedRoute allowedRoles={['user']}>
              <UserProfile />
            </ProtectedRoute>
          }
        />

        {/* Admin Role Protected Routes */}
        <Route
          path="/admin/dashboard"
          element={
            <ProtectedRoute allowedRoles={['admin']}>
              <AdminDashboard />
            </ProtectedRoute>
          }
        />

        {/* Guardian Role Protected Routes */}
        <Route
          path="/guardian/dashboard"
          element={
            <ProtectedRoute allowedRoles={['guardian']}>
              <GuardianDashboard />
            </ProtectedRoute>
          }
        />

        {/* Dynamic Fallback Route */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <DynamicDashboardRedirect />
            </ProtectedRoute>
          }
        />

        {/* Catch-all redirect to Landing */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}