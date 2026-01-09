import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Area,
  AreaChart,
} from 'recharts';
import { formatDate } from '../../utils/helpers';

interface LoginTrendChartProps {
  data: Array<{
    date: string;
    logins: number;
  }>;
}

export default function LoginTrendChart({ data }: LoginTrendChartProps) {
  // Transform data for display
  const chartData = data.map((item) => ({
    ...item,
    displayDate: formatDate(item.date, 'MMM d'),
  }));
  
  return (
    <div className="card h-full">
      <div className="card-header">
        <h3 className="card-title">Login Trend</h3>
        <span className="text-sm text-gray-400">Last 7 days</span>
      </div>
      
      <div className="h-64">
        {data.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-400">
            No data available
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="loginGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis
                dataKey="displayDate"
                axisLine={false}
                tickLine={false}
                tick={{ fill: '#9ca3af', fontSize: 12 }}
              />
              <YAxis
                axisLine={false}
                tickLine={false}
                tick={{ fill: '#9ca3af', fontSize: 12 }}
                width={40}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  color: '#fff',
                }}
                labelStyle={{ color: '#9ca3af' }}
                formatter={(value: number) => [value, 'Logins']}
              />
              <Area
                type="monotone"
                dataKey="logins"
                stroke="#0ea5e9"
                strokeWidth={2}
                fill="url(#loginGradient)"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
