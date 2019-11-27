import { deprecate } from 'util';
import encryption from './encryption';

export default deprecate((app) => {
  app.loopback.modelBuilder.mixins.define('Encryption', encryption);
}, 'DEPRECATED: Use mixinSources, see https://github.com/prototype-berlin/loopback-mixin-db-encryption');

module.exports = exports.default;