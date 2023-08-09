import { SigninRedirectArgs, SignoutRedirectArgs, UserManager, UserManagerSettings } from "oidc-client-ts";

export type AuthenticateOptions = Pick<
  UserManagerSettings,
  | "client_id"
  | "authority"
  | "redirect_uri"
  | "silent_redirect_uri"
  | "post_logout_redirect_uri"
  | "scope"
  | "userStore"
>;

export async function signinRedirectCallback(options: AuthenticateOptions, defaultReturnTo: string) {
  const userManager = new UserManager({ ...options, automaticSilentRenew: false });
  const user = await userManager.signinRedirectCallback();
  const { returnTo } = (user.state as { returnTo?: string }) ?? {};
  const url = new URL(returnTo || defaultReturnTo);
  const sid = user.profile.sid;
  if (sid) {
    url.searchParams.set("sid_hint", sid);
  }

  window.location.replace(url.href);
  await new Promise(() => {});
}
export function signinSilentCallback(options: AuthenticateOptions) {
  const userManager = new UserManager({ ...options, automaticSilentRenew: false });
  return userManager.signinSilentCallback();
}

export async function signoutRedirectCallback(options: AuthenticateOptions) {
  const userManager = new UserManager({ ...options, automaticSilentRenew: false });
  const signoutResponse = await userManager.signoutRedirectCallback();
  return userManager.signinRedirect({ redirectMethod: "replace", state: signoutResponse.userState });
}

export async function signoutRedirect(options: AuthenticateOptions) {
  const userManager = new UserManager({ ...options, automaticSilentRenew: false });
  const user = await userManager.getUser();

  const redirectMethod = "replace";
  const url = new URL(window.location.href);
  const returnTo = url.searchParams.get("returnTo");
  const state = returnTo ? { returnTo } : undefined;

  return user
    ? userManager.signoutRedirect({ redirectMethod, state })
    : userManager.signinRedirect({ redirectMethod, state });
}

export async function authenticate(options: AuthenticateOptions) {
  const userManager = new UserManager(options);

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

function getReturnToUrl() {
  if (window.location.pathname !== "/" || window.location.search !== "" || window.location.hash) {
    return window.location.href;
  }
}
