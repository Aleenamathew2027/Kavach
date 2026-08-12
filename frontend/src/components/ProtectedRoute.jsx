import { Navigate } from 'react-router-dom';
import { getToken, getRole } from '../services/api';

/**
 * ProtectedRoute – wraps routes requiring authentication.
 * Redirects unauthenticated visitors to /login.
 * Redirects users with mismatched roles to their authorized dashboard.
 */
export default function ProtectedRoute({ children, allowedRoles }) {
  const token = getToken();
  const role = getRole();

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(role)) {
    if (role === 'admin') {
      return <Navigate to="/admin/dashboard" replace />;
    }
    if (role === 'guardian') {
      return <Navigate to="/guardian/dashboard" replace />;
    }
    return <Navigate to="/user/dashboard" replace />;
  }

  return children;
}
