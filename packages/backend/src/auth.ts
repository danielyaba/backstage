import { createBackendModule } from '@backstage/backend-plugin-api';
import { googleAuthenticator } from '@backstage/plugin-auth-backend-module-google-provider';
import {
  authProvidersExtensionPoint,
  createOAuthProviderFactory,
} from '@backstage/plugin-auth-node';
import {
  DEFAULT_NAMESPACE,
  stringifyEntityRef,
} from '@backstage/catalog-model';
import { Config } from '@backstage/config';

const customAuth = createBackendModule({
  // This ID must be exactly "auth" because that's the plugin it targets
  pluginId: 'auth',
  // This ID must be unique, but can be anything
  moduleId: 'custom-auth-provider',
  register(reg) {
    reg.registerInit({
      deps: { 
        providers: authProvidersExtensionPoint, 
        config: Config,
      },
      async init({ providers, config }) {
        const allowedDomain = config.getString('auth.providers.google.development.domain');
        providers.registerProvider({
          // This ID must match the actual provider config, e.g. addressing
          // auth.providers.google means that this must be "google".
          providerId: 'google',
          // Use createProxyAuthProviderFactory instead if it's one of the proxy
          // based providers rather than an OAuth based one
          factory: createOAuthProviderFactory({
            authenticator: googleAuthenticator,
            async signInResolver(info, ctx) {
              const { profile: { email } } = info;
            
              // Profiles are not always guaranteed to to have an email address.
              // You can also find more provider-specific information in `info.result`.
              // It typically contains a `fullProfile` object as well as ID and/or access
              // tokens that you can use for additional lookups.
              if (!email) {
                throw new Error('User profile contained no email');
              }
            
              // You can add your own custom validation logic here.
              // Logins can be prevented by throwing an error like the one above.
              // myEmailValidator(email);
            
              // This example resolver simply uses the local part of the email as the name.
              const [name, domain] = email.split('@');

              // Verify the email domain against the allowed domain.
              if (domain !== allowedDomain) {
                throw new Error(
                  `Login failed, '${email}' does not belong to the expected domain '${allowedDomain}'`
                );
              }
            
              // This helper function handles sign-in by looking up a user in the catalog.
              // The lookup can be done either by reference, annotations, or custom filters.
              //
              // The helper also issues a token for the user, using the standard group
              // membership logic to determine the ownership references of the user.
              //
              // There are a number of other methods on the ctx, feel free to explore them!
              // return ctx.signInWithCatalogUser({
              //   entityRef: { name },
              // });
              const userEntityRef = stringifyEntityRef({
                kind: 'User',
                name: userId,
                namespace: DEFAULT_NAMESPACE,
              });
              return ctx.issueToken({
                claims: {
                  sub: userEntityRef,
                  ent: [userEntityRef],
                },
              });
            }
          }),
        });
      },
    });
  },
});

export default customAuth;