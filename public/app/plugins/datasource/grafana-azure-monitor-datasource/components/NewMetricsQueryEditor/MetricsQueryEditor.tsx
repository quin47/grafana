import React from 'react';
import { InlineFieldRow } from '@grafana/ui';
import AggregationField from '../MetricsQueryEditor/AggregationField';
import MetricNameField from '../MetricsQueryEditor/MetricNameField';
import MetricNamespaceField from '../MetricsQueryEditor/MetricNamespaceField';
import TimeGrainField from '../MetricsQueryEditor/TimeGrainField';
import DimensionFields from '../MetricsQueryEditor/DimensionFields';
import TopField from '../MetricsQueryEditor/TopField';
import LegendFormatField from '../MetricsQueryEditor/LegendFormatField';
import ResourceField from '../ResourceField';
import { ResourceRowType } from '../ResourcePicker/types';
import type Datasource from '../../datasource';
import type { AzureMonitorQuery, AzureMonitorOption, AzureMonitorErrorish } from '../../types';
import { useMetricNames, useMetricNamespaces, useMetricMetadata } from './dataHooks';
import { setResource } from '../MetricsQueryEditor/setQueryValue';

interface MetricsQueryEditorProps {
  query: AzureMonitorQuery;
  datasource: Datasource;
  onChange: (newQuery: AzureMonitorQuery) => void;
  variableOptionGroup: { label: string; options: AzureMonitorOption[] };
  setError: (source: string, error: AzureMonitorErrorish | undefined) => void;
}

const MetricsQueryEditor: React.FC<MetricsQueryEditorProps> = ({
  query,
  datasource,
  variableOptionGroup,
  onChange,
  setError,
}) => {
  const metricsMetadata = useMetricMetadata(query, datasource, onChange);
  const metricNamespaces = useMetricNamespaces(query, datasource, onChange, setError);
  const metricNames = useMetricNames(query, datasource, onChange, setError);
  return (
    <div data-testid="azure-monitor-metrics-query-editor-with-resource-picker">
      <InlineFieldRow>
        <ResourceField
          query={query}
          datasource={datasource}
          variableOptionGroup={variableOptionGroup}
          onQueryChange={onChange}
          setError={setError}
          selectableEntryTypes={[ResourceRowType.Resource]}
          setResource={setResource}
          resourceUri={query.azureMonitor?.resourceUri}
        />
      </InlineFieldRow>

      <InlineFieldRow>
        <MetricNamespaceField
          metricNamespaces={metricNamespaces}
          query={query}
          datasource={datasource}
          variableOptionGroup={variableOptionGroup}
          onQueryChange={onChange}
          setError={setError}
        />
        <MetricNameField
          metricNames={metricNames}
          query={query}
          datasource={datasource}
          variableOptionGroup={variableOptionGroup}
          onQueryChange={onChange}
          setError={setError}
        />
      </InlineFieldRow>
      <InlineFieldRow>
        <AggregationField
          query={query}
          datasource={datasource}
          variableOptionGroup={variableOptionGroup}
          onQueryChange={onChange}
          setError={setError}
          aggregationOptions={metricsMetadata?.aggOptions ?? []}
          isLoading={metricsMetadata.isLoading}
        />
        <TimeGrainField
          query={query}
          datasource={datasource}
          variableOptionGroup={variableOptionGroup}
          onQueryChange={onChange}
          setError={setError}
          timeGrainOptions={metricsMetadata?.timeGrains ?? []}
        />
      </InlineFieldRow>
      <DimensionFields
        query={query}
        datasource={datasource}
        variableOptionGroup={variableOptionGroup}
        onQueryChange={onChange}
        setError={setError}
        dimensionOptions={metricsMetadata?.dimensions ?? []}
      />
      <TopField
        query={query}
        datasource={datasource}
        variableOptionGroup={variableOptionGroup}
        onQueryChange={onChange}
        setError={setError}
      />
      <LegendFormatField
        query={query}
        datasource={datasource}
        variableOptionGroup={variableOptionGroup}
        onQueryChange={onChange}
        setError={setError}
      />
    </div>
  );
};

export default MetricsQueryEditor;
