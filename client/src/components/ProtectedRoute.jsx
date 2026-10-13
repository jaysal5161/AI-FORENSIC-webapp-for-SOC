import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';

export default function ProtectedRoute() {
  const { isAuthenticated, token, user } = useAuthStore();

  if (!isAuthenticated || !token || !user) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
