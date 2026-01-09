import { formatNumber } from '../../utils/helpers';
import { ArrowUpIcon, ArrowDownIcon } from '@heroicons/react/20/solid';
import clsx from 'clsx';

interface StatsCardProps {
  title: string;
  value: number;
  change?: string;
  changeType?: 'increase' | 'decrease';
  subtitle?: string;
  icon: React.ForwardRefExoticComponent<React.SVGProps<SVGSVGElement>>;
}

export default function StatsCard({
  title,
  value,
  change,
  changeType,
  subtitle,
  icon: Icon,
}: StatsCardProps) {
  return (
    <div className="card">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-gray-400">{title}</p>
          <p className="mt-2 text-3xl font-bold text-white">{formatNumber(value)}</p>
          
          {change && changeType && (
            <div
              className={clsx(
                'mt-2 flex items-center text-sm',
                changeType === 'increase' ? 'text-green-400' : 'text-red-400'
              )}
            >
              {changeType === 'increase' ? (
                <ArrowUpIcon className="h-4 w-4" />
              ) : (
                <ArrowDownIcon className="h-4 w-4" />
              )}
              <span className="ml-1">{change}</span>
              <span className="ml-1 text-gray-500">vs last period</span>
            </div>
          )}
          
          {subtitle && <p className="mt-2 text-sm text-gray-500">{subtitle}</p>}
        </div>
        
        <div className="p-3 bg-sentinel-500/10 rounded-lg">
          <Icon className="h-6 w-6 text-sentinel-400" />
        </div>
      </div>
    </div>
  );
}
