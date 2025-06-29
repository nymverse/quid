/**
 * QuID Identity List Component
 */

import React from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  FlatList,
  StyleSheet,
  Alert,
} from 'react-native';
import { QuIDIdentityListProps, QuIDIdentity, SecurityLevel } from '../types';

interface IdentityItemProps {
  identity: QuIDIdentity;
  onSelect?: (identity: QuIDIdentity) => void;
  onDelete?: (identity: QuIDIdentity) => void;
  style?: any;
  showDetails?: boolean;
}

const IdentityItem: React.FC<IdentityItemProps> = ({
  identity,
  onSelect,
  onDelete,
  style,
  showDetails = true,
}) => {
  const handleDelete = () => {
    if (!onDelete) return;

    Alert.alert(
      'Delete Identity',
      `Are you sure you want to delete "${identity.name}"? This action cannot be undone.`,
      [
        {
          text: 'Cancel',
          style: 'cancel',
        },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: () => onDelete(identity),
        },
      ]
    );
  };

  const getSecurityLevelColor = (level: SecurityLevel): string => {
    switch (level) {
      case SecurityLevel.LEVEL1:
        return '#34C759'; // Green
      case SecurityLevel.LEVEL2:
        return '#FF9500'; // Orange
      case SecurityLevel.LEVEL3:
        return '#FF3B30'; // Red
      default:
        return '#8E8E93'; // Gray
    }
  };

  const formatDate = (date: Date | null): string => {
    if (!date) return 'Never';
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    }).format(date);
  };

  return (
    <TouchableOpacity
      style={[styles.itemContainer, style]}
      onPress={() => onSelect?.(identity)}
      activeOpacity={0.7}
    >
      <View style={styles.itemHeader}>
        <View style={styles.itemTitleContainer}>
          <Text style={styles.itemTitle}>{identity.name}</Text>
          <View
            style={[
              styles.securityBadge,
              { backgroundColor: getSecurityLevelColor(identity.securityLevel) },
            ]}
          >
            <Text style={styles.securityBadgeText}>
              {identity.securityLevel}
            </Text>
          </View>
        </View>
        {onDelete && (
          <TouchableOpacity
            style={styles.deleteButton}
            onPress={handleDelete}
            hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}
          >
            <Text style={styles.deleteButtonText}>×</Text>
          </TouchableOpacity>
        )}
      </View>

      {showDetails && (
        <View style={styles.itemDetails}>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Networks:</Text>
            <Text style={styles.detailValue}>
              {identity.networks.join(', ')}
            </Text>
          </View>
          
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Biometrics:</Text>
            <Text style={styles.detailValue}>
              {identity.requireBiometrics ? 'Required' : 'Optional'}
            </Text>
          </View>
          
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Created:</Text>
            <Text style={styles.detailValue}>
              {formatDate(identity.createdAt)}
            </Text>
          </View>
          
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Last Used:</Text>
            <Text style={styles.detailValue}>
              {formatDate(identity.lastUsedAt)}
            </Text>
          </View>
        </View>
      )}
    </TouchableOpacity>
  );
};

export const QuIDIdentityList: React.FC<QuIDIdentityListProps> = ({
  identities,
  onSelect,
  onDelete,
  style,
  itemStyle,
  showDetails = true,
}) => {
  const renderItem = ({ item }: { item: QuIDIdentity }) => (
    <IdentityItem
      identity={item}
      onSelect={onSelect}
      onDelete={onDelete}
      style={itemStyle}
      showDetails={showDetails}
    />
  );

  const renderEmpty = () => (
    <View style={styles.emptyContainer}>
      <Text style={styles.emptyTitle}>No Identities</Text>
      <Text style={styles.emptyMessage}>
        Create your first QuID identity to get started with quantum-resistant authentication.
      </Text>
    </View>
  );

  return (
    <View style={[styles.container, style]}>
      <FlatList
        data={identities}
        renderItem={renderItem}
        keyExtractor={(item) => item.id}
        ListEmptyComponent={renderEmpty}
        showsVerticalScrollIndicator={false}
        contentContainerStyle={styles.listContent}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f8f9fa',
  },
  listContent: {
    padding: 16,
  },
  itemContainer: {
    backgroundColor: '#ffffff',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
    shadowColor: '#000',
    shadowOffset: {
      width: 0,
      height: 2,
    },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  itemHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
  },
  itemTitleContainer: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
  },
  itemTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#1c1c1e',
    marginRight: 12,
  },
  securityBadge: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 12,
  },
  securityBadgeText: {
    color: '#ffffff',
    fontSize: 12,
    fontWeight: '600',
  },
  deleteButton: {
    width: 28,
    height: 28,
    borderRadius: 14,
    backgroundColor: '#ff3b30',
    alignItems: 'center',
    justifyContent: 'center',
  },
  deleteButtonText: {
    color: '#ffffff',
    fontSize: 18,
    fontWeight: '600',
    lineHeight: 20,
  },
  itemDetails: {
    marginTop: 12,
    paddingTop: 12,
    borderTopWidth: 1,
    borderTopColor: '#e5e5ea',
  },
  detailRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 6,
  },
  detailLabel: {
    fontSize: 14,
    color: '#8e8e93',
    fontWeight: '500',
  },
  detailValue: {
    fontSize: 14,
    color: '#1c1c1e',
    fontWeight: '400',
    textAlign: 'right',
    flex: 1,
    marginLeft: 16,
  },
  emptyContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 32,
    paddingVertical: 64,
  },
  emptyTitle: {
    fontSize: 24,
    fontWeight: '600',
    color: '#1c1c1e',
    marginBottom: 12,
    textAlign: 'center',
  },
  emptyMessage: {
    fontSize: 16,
    color: '#8e8e93',
    textAlign: 'center',
    lineHeight: 24,
  },
});