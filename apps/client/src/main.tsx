import '@patternfly/react-core/dist/styles/base.css';
import { createRoot } from 'react-dom/client';
import { App } from './ui/app.tsx';

const root = document.getElementById('root');
if (root) createRoot(root).render(<App />);
