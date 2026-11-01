// Polyfills must run before any protocol module is evaluated.
import './src/polyfills';
import { AppRegistry } from 'react-native';
import { registerRootComponent } from 'expo';
import App from './src/App';
import DcApiRoot from './src/DcApiRoot';

registerRootComponent(App);
// Rendered by the Credential Manager activity of the dc-api module (Android development / release builds only).
AppRegistry.registerComponent('dcapi', () => DcApiRoot);
