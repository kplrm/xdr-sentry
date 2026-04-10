import React from 'react';
import ReactDOM from 'react-dom';
import { AppMountParameters, CoreStart } from '../../OpenSearch-Dashboards/src/core/public';
import { XdrSentryApp } from './components';

export const renderApp = ({ http, notifications }: CoreStart, { appBasePath, element }: AppMountParameters) => {
  ReactDOM.render(
    <XdrSentryApp basename={appBasePath} http={http} notifications={notifications} />,
    element
  );

  return () => ReactDOM.unmountComponentAtNode(element);
};
