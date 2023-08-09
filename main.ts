import { SigninRedirectArgs, SignoutRedirectArgs, User, UserManager, UserManagerSettings } from "oidc-client-ts";

export type SigninRedirectCallbackOptions = {
  defaultReturnTo: (user: User) => string;
};

/**
 * Handles the callback from the identity provider after a user has signed in.
 * Removes the current page from the session history and navigates to the return URL in the user's state or the default return URL.
 *
 * @param {UserManagerSettings} userManagerSettings - The configuration settings for the UserManager.
 * @param {SigninRedirectCallbackOptions} options - The options containing a function that determines the default return URL based on the user's data. Only called if the user's state does not contain a return URL.
 *
 * @remarks The sid is passed as a query parameter to the return URL.
 *
 *
 * @example
 * await signinRedirectCallback(userManagerConfig, {
 *   defaultReturnTo: (user) => 'https://default-return-url.com/' + user.profile.sub
 * });
 */
export async function signinRedirectCallback(
  userManagerSettings: UserManagerSettings,
  options: SigninRedirectCallbackOptions,
) {
  const userManager = new UserManager(pick(userManagerSettings));
  const user = await userManager.signinRedirectCallback();
  const { returnTo } = (user.state as { returnTo?: string }) ?? {};
  const url = new URL(returnTo || options.defaultReturnTo(user));
  const sid = user.profile.sid;
  if (sid) {
    url.searchParams.set("sid_hint", sid);
  }

  window.location.replace(url.href);
  await new Promise(() => {});
}

/**
 * Handles the silent callback after a silent sign-in by notifying the parent window of the response from the authorization endpoint.
 *
 * @param {UserManagerSettings} userManagerSettings - The configuration settings for the UserManager.
 *
 * @example
 * await signinSilentCallback(userManagerConfig);
 */
export function signinSilentCallback(userManagerSettings: UserManagerSettings) {
  const userManager = new UserManager(pick(userManagerSettings));
  return userManager.signinSilentCallback();
}

/**
 * Handles the callback from the identity provider after a user has signed out. It then redirects the user for a new sign-in.
 *
 * @param {UserManagerSettings} userManagerSettings - The configuration settings for the UserManager.
 *
 * @example
 * await signoutRedirectCallback(userManagerConfig);
 */
export async function signoutRedirectCallback(userManagerSettings: UserManagerSettings) {
  const userManager = new UserManager(pick(userManagerSettings));
  const signoutResponse = await userManager.signoutRedirectCallback();
  return userManager.signinRedirect({ redirectMethod: "replace", state: signoutResponse.userState });
}

export type SignoutRedirectOptions = {
  beforeSignout?: (user: User) => Promise<void>;
};

/**
 * Redirects the user for sign-out. If the user is not logged in, redirects for sign-in.
 * Before sign-out, a provided callback (if available) is invoked.
 *
 * @param {UserManagerSettings} userManagerSettings - The configuration settings for the UserManager.
 * @param {SignoutRedirectOptions} [options={}] - The options containing a callback that is invoked before the sign-out.
 *
 * @remarks If the `beforeSignout` callback is provided in the options, it will be executed before the sign-out process.
 *
 *
 * @example
 * await signoutRedirect(userManagerConfig, {
 *   beforeSignout: async (user) => {
 *     // perform some pre-signout actions or logging or navigation to a different page to prevent signout
 *   }
 * });
 */
export async function signoutRedirect(userManagerSettings: UserManagerSettings, options: SignoutRedirectOptions = {}) {
  const userManager = new UserManager(pick(userManagerSettings));
  const user = await userManager.getUser();

  const redirectMethod = "replace";
  const url = new URL(window.location.href);
  const returnTo = url.searchParams.get("returnTo");
  const state = returnTo ? { returnTo } : undefined;
  if (user) {
    if (options?.beforeSignout) {
      await options?.beforeSignout(user);
    }
    return userManager.signoutRedirect({ redirectMethod, state });
  } else {
    return userManager.signinRedirect({ redirectMethod, state });
  }
}

/**
 * Authenticates the user. If the user is not authenticated or the session is expired, it will try to
 * re-authenticate the user silently. If that fails, it will redirect the user to the identity provider's signin page.
 *
 * @param {UserManagerSettings} userManagerSettings - The configuration settings for the UserManager.
 *
 * @example
 * await authenticate(userManagerConfig);
 */
export async function authenticate(userManagerSettings: UserManagerSettings) {
  const userManager = new UserManager(userManagerSettings);

  // let's grab the local user from the local store
  let user = await userManager.getUser();

  // if the user is null or expired, it means we need to re-authenticate with the identity provider
  // we'll try to do it silently first and if it fails, we'll redirect to the identity provider
  if (!user || user.expired) {
    try {
      user = await userManager.signinSilent();
    } catch (e) {
      return signin(userManager);
    }

    if (!user) {
      return signin(userManager);
    }
  }

  let sessionId = getSessionIdFromUrl();
  if (!sessionId) {
    try {
      const sessionStatus = await userManager.querySessionStatus();
      sessionId = sessionStatus?.sid;
    } catch (e) {
      return signout(userManager);
    }

    if (!sessionId) {
      return signout(userManager);
    }
  }

  // if the session id doesn't match the one in the local user,
  // it means we need to re-authenticate with the identity provider
  if (sessionId !== user.profile.sid) {
    return signout(userManager);
  }
}

async function signin(userManager: UserManager) {
  const payload: SigninRedirectArgs = { redirectMethod: "replace" };
  const returnTo = getReturnToUrl();
  if (returnTo) {
    payload.state = { returnTo };
  }

  await userManager.signinRedirect(payload);
  // create a promise that will never resolve
  // this is to prevent the rest of the application from loading
  // until the user is redirected back to the identity provider
  await new Promise(() => {});
}

async function signout(userManager: UserManager) {
  const payload: SignoutRedirectArgs = { redirectMethod: "replace" };
  const returnTo = getReturnToUrl();
  if (returnTo) {
    payload.state = { returnTo };
  }

  await userManager.signoutRedirect(payload);
  // create a promise that will never resolve
  // this is to prevent the rest of the application from loading
  // until the user is redirected back to the identity provider
  await new Promise(() => {});
}

/**
 * Extracts the session ID (`sid`) from the current URL. If found, it removes the `sid_hint` parameter from the URL.
 *
 * @returns The session ID if found, otherwise undefined.
 *
 * @example
 * const sessionId = getSessionIdFromUrl();
 */
function getSessionIdFromUrl() {
  const url = new URL(window.location.href);
  if (url.searchParams.has("sid_hint")) {
    const sid = url.searchParams.get("sid_hint");
    // let's remove the sid_hint from the url
    url.searchParams.delete("sid_hint");
    window.history.replaceState({}, "", url.toString());
    if (sid) {
      return sid;
    }
  }
}

/**
 * Gets the return URL to be used after a redirect. If the current path is the root and there's no query or hash,
 * it returns the full URL.
 *
 * @returns The return URL or undefined.
 *
 * @example
 * const returnUrl = getReturnToUrl();
 */
function getReturnToUrl() {
  if (window.location.pathname !== "/" || window.location.search !== "" || window.location.hash) {
    return window.location.href;
  }
}

/**
 * Picks necessary fields from the UserManagerSettings for creating a new UserManager.
 *
 * @param {UserManagerSettings} userManagerSettings - The full configuration settings for the UserManager.
 * @returns The picked settings.
 *
 * @example
 * const pickedSettings = pick(userManagerConfig);
 */
function pick(userManagerSettings: UserManagerSettings) {
  const { client_id, authority, redirect_uri, silent_redirect_uri, post_logout_redirect_uri, scope, userStore } =
    userManagerSettings;

  return {
    client_id,
    authority,
    redirect_uri,
    silent_redirect_uri,
    post_logout_redirect_uri,
    scope,
    userStore,
    automaticSilentRenew: false,
  };
}
