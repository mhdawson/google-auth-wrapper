// Copyright 2016 the project authors as listed in the AUTHORS file.
// All rights reserved. Use of this source code is governed by the
// license that can be found in the LICENSE file.

const fs = require('fs');
const path = require('path');
const google = require('googleapis');
const googleAuth = require('google-auth-library');

// For both calls clientsSecets must contain the name
// of the file with the secrets for the client minus
//  the trailing '.json' and this file must be located
// in the directory specified by storage path

// authorize and store creditials for later use
// scopes specifies the requested priviledges
// and authCallback must be a function with the
// the folowing signature:
//   function(url, provideCode)
// which will be called with the url that the 
// user should be asked to natigate to and
// provideCode is a function with the following
// signaure
//   function(code, completion)
// that the call should invoke with the code
// provided to the user when they navigate to 
// the url passed into authCallback. 
// completion is a function with the folowing
// signature:
//   function(err)
// which will be invoked once the credentials
// are stored.  err will be undefined if the
// sequence is successful
function authorize(storagePath,
                   clientSecrets,
                   scopes,
                   authCallback) {
  const oauthClient = createOauthClient(storagePath, clientSecrets);
  const url = oauthClient.generateAuthUrl({ access_type: 'offline', 
                                          scope: scopes });
  
  authCallback(url, function(code, completion) {
    oauthClient.getToken(code, function(err, token) {
      if (err) {
        completion(new Error('Invalid token entered'));
      } else {  
        try {
          fs.writeFile(path.join(storagePath, clientSecrets + '.token'), JSON.stringify(token)); 
          completion();
        } catch (err) {
          completion(new Error('failed to write token to file:' + err));
        }
      }
    });
  });
}


// execute an operation using the authorization previously setup
// by a call to authorize.  execute action must be a function 
// with the following signature:
//   function(oauthClient, google)
// which will be called with the oauthClient and google objects
// that can be used to interact with the google APIs
function execute(storagePath, clientSecrets, executeAction) {
  const oauthClient = createOauthClient(storagePath, clientSecrets);

  // read existing credentials from token
  var existingToken = fs.readFileSync(path.join(storagePath, clientSecrets + '.token'));
  if (existingToken !== undefined) {
    oauthClient.credentials = JSON.parse(existingToken);
  } else {
    throw new Error('No existing authorization');
  }
  
  executeAction(oauthClient, google); 
}


// common parts of oauth client creation
function createOauthClient(storagePath, clientSecrets) {
  var secrets = fs.readFileSync(path.join(storagePath,  clientSecrets + '.json'));
  if (secrets === undefined) { 
    throw new Error('failed to read secrets file');
  }
  secrets = JSON.parse(secrets);

  var gAuth = new googleAuth();
  var oauthClient = new gAuth.OAuth2(secrets.installed.client_id,
                                     secrets.installed.client_secret,
                                     secrets.installed.redirect_uris[0]);
  return oauthClient;
}

exports.authorize = authorize;
exports.execute = execute;
