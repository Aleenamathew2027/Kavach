import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';

// Public Pages
import Landing from './pages/Landing';
import Login from './pages/Login';
import Register from './pages/Register';

// User Role Pages
import UserDashboard from './pages/UserDashboard';
import UserProfile from './pages/UserProfile';
import UserSecurity from './pages/UserSecurity';
import UserAlerts from './pages/UserAlerts';
import MessageScanner from './pages/MessageScanner';
import LinkChecker from './pages/LinkChecker';
import DocumentChecker from './pages/DocumentChecker';
import UserGuardian from './pages/UserGuardian';
import UserReports from './pages/UserReports';

// Admin Role Pages
import AdminDashboard from './pages/AdminDashboard';
import AdminUsers from './pages/AdminUsers';
import AdminSecurityEvents from './pages/AdminSecurityEvents';
import AdminGuardians from './pages/AdminGuardians';
import AdminReports from './pages/AdminReports';
import AdminActivity from './pages/AdminActivity';
import AdminSettings from './pages/AdminSettings';

// Guardian Role Pages
import GuardianDashboard from './pages/GuardianDashboard';
import GuardianProtectedUser from './pages/GuardianProtectedUser';
import GuardianSecurity from './pages/GuardianSecurity';
import GuardianAlerts from './pages/GuardianAlerts';
import GuardianActivity from './pages/GuardianActivity';
import GuardianSettings from './pages/GuardianSettings';
import AIAssistant from './pages/AIAssistant';

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
 * App – root router for KAVACH with strict role-based route isolation
 */
export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* ── Public Routes ── */}
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* ── User Role Protected Routes ── */}
        <Route
          path="/user/dashboard"
          element={
            <ProtectedRoute allowedRoles={['user']}>
              <UserDashboard />
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
          path="/user/alerts"
          element={
            <ProtectedRoute allowedRoles={['user']}>
              <UserAlerts />
            </ProtectedRoute>
          }
        />
        <Route
          path="/user/assistant"
          element={
            <ProtectedRoute allowedRoles={['user']}>
              <AIAssistant />
            </ProtectedRoute>
          }
        />
        <Route
          path="/user/guardian"
          element={
            <ProtectedRoute allowedRoles={['user']}>
              <UserGuardian />
            </ProtectedRoute>
          }
        />
        <Route
          path="/user/reports"
          element={
            <ProtectedRoute allowedRoles={['user']}>
              <UserReports />
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

        {/* ── Admin Role Protected Routes ── */}
        <Route
          path="/admin/dashboard"
          element={
            <ProtectedRoute allowedRoles={['admin']}>
              <AdminDashboard />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/users"
          element={
            <ProtectedRoute allowedRoles={['admin']}>
              <AdminUsers />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/security-events"
          element={
            <ProtectedRoute allowedRoles={['admin']}>
              <AdminSecurityEvents />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/guardians"
          element={
            <ProtectedRoute allowedRoles={['admin']}>
              <AdminGuardians />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/reports"
          element={
            <ProtectedRoute allowedRoles={['admin']}>
              <AdminReports />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/activity"
          element={
            <ProtectedRoute allowedRoles={['admin']}>
              <AdminActivity />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/settings"
          element={
            <ProtectedRoute allowedRoles={['admin']}>
              <AdminSettings />
            </ProtectedRoute>
          }
        />

        {/* ── Guardian Role Protected Routes ── */}
        <Route
          path="/guardian/dashboard"
          element={
            <ProtectedRoute allowedRoles={['guardian']}>
              <GuardianDashboard />
            </ProtectedRoute>
          }
        />
        <Route
          path="/guardian/protected-user"
          element={
            <ProtectedRoute allowedRoles={['guardian']}>
              <GuardianProtectedUser />
            </ProtectedRoute>
          }
        />
        <Route
          path="/guardian/security"
          element={
            <ProtectedRoute allowedRoles={['guardian']}>
              <GuardianSecurity />
            </ProtectedRoute>
          }
        />
        <Route
          path="/guardian/alerts"
          element={
            <ProtectedRoute allowedRoles={['guardian']}>
              <GuardianAlerts />
            </ProtectedRoute>
          }
        />
        <Route
          path="/guardian/assistant"
          element={
            <ProtectedRoute allowedRoles={['guardian']}>
              <AIAssistant />
            </ProtectedRoute>
          }
        />
        <Route
          path="/guardian/activity"
          element={
            <ProtectedRoute allowedRoles={['guardian']}>
              <GuardianActivity />
            </ProtectedRoute>
          }
        />
        <Route
          path="/guardian/settings"
          element={
            <ProtectedRoute allowedRoles={['guardian']}>
              <GuardianSettings />
            </ProtectedRoute>
          }
        />

        {/* ── Direct /assistant Shortcut (User & Guardian) ── */}
        <Route
          path="/assistant"
          element={
            <ProtectedRoute allowedRoles={['user', 'guardian']}>
              <AIAssistant />
            </ProtectedRoute>
          }
        />

        {/* ── Dynamic Fallback Route ── */}
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