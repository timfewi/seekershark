import { render } from 'solid-js/web';
import App from './App';
import './styles.css';

const root = document.getElementById('root');
if (!root) throw new Error('App entry element #root is missing.');
render(() => <App />, root);
