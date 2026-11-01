// Polyfills must run before any protocol module is evaluated.
import './src/polyfills';
import { registerRootComponent } from 'expo';
import App from './src/App';

registerRootComponent(App);
