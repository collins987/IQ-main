import { format, formatDistanceToNow, parseISO } from 'date-fns';

/**
 * Format a date string to a human-readable format
 */
export function formatDate(date: string | Date | null, pattern = 'MMM d, yyyy HH:mm'): string {
  if (!date) return 'N/A';
  const d = typeof date === 'string' ? parseISO(date) : date;
  return format(d, pattern);
}

/**
 * Format a date as relative time (e.g., "2 hours ago")
 */
export function formatRelativeTime(date: string | Date | null): string {
  if (!date) return 'N/A';
  const d = typeof date === 'string' ? parseISO(date) : date;
  return formatDistanceToNow(d, { addSuffix: true });
}

/**
 * Format a number with commas for thousands
 */
export function formatNumber(num: number): string {
  return new Intl.NumberFormat().format(num);
}

/**
 * Format a percentage
 */
export function formatPercent(value: number, decimals = 1): string {
  return `${value.toFixed(decimals)}%`;
}

/**
 * Get initials from a name
 */
export function getInitials(firstName?: string, lastName?: string): string {
  const first = firstName?.charAt(0)?.toUpperCase() || '';
  const last = lastName?.charAt(0)?.toUpperCase() || '';
  return first + last || '?';
}

/**
 * Get risk level from score
 */
export function getRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

/**
 * Get color class for risk level
 */
export function getRiskColorClass(level: 'low' | 'medium' | 'high' | 'critical'): string {
  const colors = {
    low: 'text-green-400',
    medium: 'text-yellow-400',
    high: 'text-red-400',
    critical: 'text-red-600',
  };
  return colors[level];
}

/**
 * Get background color class for risk level
 */
export function getRiskBgClass(level: 'low' | 'medium' | 'high' | 'critical'): string {
  const colors = {
    low: 'bg-green-500/20',
    medium: 'bg-yellow-500/20',
    high: 'bg-red-500/20',
    critical: 'bg-red-600/30',
  };
  return colors[level];
}

/**
 * Truncate a string to a maximum length
 */
export function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength) + '...';
}

/**
 * Mask sensitive data like email
 */
export function maskEmail(email: string): string {
  const [user, domain] = email.split('@');
  if (!user || !domain) return email;
  const maskedUser = user.slice(0, 2) + '***';
  return `${maskedUser}@${domain}`;
}

/**
 * Mask IP address
 */
export function maskIP(ip: string | null): string {
  if (!ip) return 'N/A';
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.***.**`;
  }
  return ip;
}

/**
 * Get status badge class
 */
export function getStatusBadgeClass(status: string): string {
  const statusLower = status.toLowerCase();
  if (statusLower === 'active' || statusLower === 'healthy') {
    return 'badge-success';
  }
  if (statusLower === 'suspended' || statusLower === 'degraded') {
    return 'badge-warning';
  }
  if (statusLower === 'disabled' || statusLower === 'unhealthy' || statusLower === 'critical') {
    return 'badge-danger';
  }
  return 'badge-neutral';
}

/**
 * Get role badge class
 */
export function getRoleBadgeClass(role: string): string {
  const roleLower = role.toLowerCase();
  if (roleLower === 'admin') {
    return 'badge-danger';
  }
  if (roleLower === 'analyst') {
    return 'badge-info';
  }
  if (roleLower === 'viewer') {
    return 'badge-neutral';
  }
  return 'badge-neutral';
}

/**
 * Debounce a function
 */
export function debounce<T extends (...args: unknown[]) => void>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: number | null = null;
  
  return (...args: Parameters<T>) => {
    if (timeout) {
      clearTimeout(timeout);
    }
    timeout = window.setTimeout(() => {
      func(...args);
    }, wait);
  };
}

/**
 * Copy text to clipboard
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
