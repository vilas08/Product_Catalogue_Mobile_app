import React from 'react';
import { StyleSheet, Text, TouchableOpacity, View } from 'react-native';
import { useAuth } from '../context/AuthContext';

export const DashboardScreen: React.FC = () => {
  const { user, authMode, logout, synchronizeActivity, recordLocalActivity } = useAuth();

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Salesperson Dashboard</Text>
      <Text style={styles.meta}>User: {user?.name} ({user?.email})</Text>
      <Text style={styles.meta}>Role: {user?.role}</Text>
      <Text style={styles.badge}>Auth Mode: {authMode}</Text>

      <TouchableOpacity
        style={styles.secondaryButton}
        onPress={() => recordLocalActivity('sales_visit_logged')}
      >
        <Text style={styles.secondaryButtonText}>Record Local Activity</Text>
      </TouchableOpacity>

      <TouchableOpacity style={styles.primaryButton} onPress={synchronizeActivity}>
        <Text style={styles.primaryButtonText}>Synchronize Activity</Text>
      </TouchableOpacity>

      <TouchableOpacity style={styles.logoutButton} onPress={logout}>
        <Text style={styles.logoutButtonText}>Sign Out</Text>
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    padding: 24,
    backgroundColor: '#f8fafc',
  },
  title: {
    fontSize: 24,
    fontWeight: '700',
    marginBottom: 16,
    color: '#0f172a',
  },
  meta: {
    fontSize: 15,
    color: '#334155',
    marginBottom: 6,
  },
  badge: {
    fontSize: 14,
    fontWeight: '600',
    color: '#1d4ed8',
    marginVertical: 12,
  },
  primaryButton: {
    backgroundColor: '#2563eb',
    borderRadius: 8,
    paddingVertical: 14,
    alignItems: 'center',
    marginTop: 12,
  },
  primaryButtonText: {
    color: '#ffffff',
    fontWeight: '600',
  },
  secondaryButton: {
    backgroundColor: '#e2e8f0',
    borderRadius: 8,
    paddingVertical: 14,
    alignItems: 'center',
    marginTop: 12,
  },
  secondaryButtonText: {
    color: '#0f172a',
    fontWeight: '600',
  },
  logoutButton: {
    backgroundColor: '#dc2626',
    borderRadius: 8,
    paddingVertical: 14,
    alignItems: 'center',
    marginTop: 24,
  },
  logoutButtonText: {
    color: '#ffffff',
    fontWeight: '600',
  },
});
