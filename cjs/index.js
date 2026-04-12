'use strict';

Object.assign(
    exports,
    require('./registration/generateRegistrationOptions.js'),
    require('./registration/verifyRegistrationResponse.js'),
    require('./authentication/generateAuthenticationOptions.js'),
    require('./authentication/verifyAuthenticationResponse.js'),
    require('./services/metadataService.js'),
    require('./services/settingsService.js'),
    require('./metadata/mdsTypes.js')
);