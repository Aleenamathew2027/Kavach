import { Navigate } from 'react-router-dom';

/**
 * ProtectedRoute – wraps a route that requires authentication.
 * If the user is not logged in (no kavach_logged_in in localStorage),
 * they are redirected to /login.
 */
export default function ProtectedRoute({ children }) {
  const isLoggedIn = localStorage.getItem('kavach_logged_in') === 'true';

  if (!isLoggedIn) {
    return <Navigate to="/login" replace />;
  }

  return children;
}
