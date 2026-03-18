import { set } from "@ember/object";
import { cancel } from "@ember/runloop";
import setupMirage from "ember-cli-mirage/test-support/setup-mirage";
import { setupTest } from "ember-qunit";
import { module, test } from "qunit";
import sinon from "sinon";

const getTokenBody = (expired) => {
  const time = expired ? -30 : 120;
  return btoa(
    JSON.stringify({
      exp: Date.now() + time,
    }),
  );
};

module("Unit | Authenticator | OIDC", function (hooks) {
  setupTest(hooks);
  setupMirage(hooks);

  test("it can authenticate", async function (assert) {
    const subject = this.owner.lookup("authenticator:oidc");

    set(subject, "redirectUri", "test");

    const data = await subject.authenticate({ code: "test" });

    assert.ok(data.access_token, "Returns an access token");
    assert.ok(data.refresh_token, "Returns a refresh token");
    assert.ok(data.userinfo, "Returns the user info");
    assert.ok(data.expireTime, "Returns the time at which the token expires");
  });

  test("it can restore a session", async function (assert) {
    const subject = this.owner.lookup("authenticator:oidc");

    const data = await subject.restore({
      refresh_token: `refresh.${getTokenBody(false)}.token`,
      expireTime: new Date().getTime(),
      redirectUri: "test",
    });

    assert.ok(data.access_token, "Returns an access token");
    assert.ok(data.refresh_token, "Returns a refresh token");
    assert.ok(data.userinfo, "Returns the user info");
    assert.ok(data.expireTime, "Returns the time at which the token expires");
  });

  test("it can invalidate a session", async function (assert) {
    const subject = this.owner.lookup("authenticator:oidc");

    assert.ok(await subject.invalidate());
  });

  test("it can refresh a session", async function (assert) {
    const subject = this.owner.lookup("authenticator:oidc");

    const data = await subject._refresh("x.y.z");

    assert.ok(data.access_token, "Returns an access token");
    assert.ok(data.refresh_token, "Returns a refresh token");
    assert.ok(data.userinfo, "Returns the user info");
    assert.ok(data.expireTime, "Returns the time at which the token expires");
  });

  module("single logout", function (hooks) {
    hooks.beforeEach(function () {
      this.env =
        this.owner.resolveRegistration("config:environment")[
          "ember-simple-auth-oidc"
        ];
      this._originalHost = this.env.host;
      this.env.host = "https://some-other-domain.com";
    });

    hooks.afterEach(function () {
      this.env.host = this._originalHost;
    });

    test("it can make a single logout", async function (assert) {
      const { endSessionEndpoint, afterLogoutUri } = this.owner.lookup(
        "service:esa-oidc-config",
      );
      const subject = this.owner.lookup("authenticator:oidc");
      const { protocol, host } = location;

      subject._redirectToUrl = (url) => {
        assert.ok(new RegExp(endSessionEndpoint).test(url));
        assert.ok(
          new RegExp(
            `post_logout_redirect_uri=${protocol}//${host}${afterLogoutUri}`,
          ).test(url),
        );
        assert.ok(new RegExp("id_token_hint=myIdToken").test(url));
      };

      subject.singleLogout("myIdToken");
    });
  });

  test("it supports sending custom parameters", function (assert) {
    const bodyOptions = {
      code: "test-code",
      codeVerifier: "test-verifier",
      redirectUri: "test/redirect",
      isRefresh: true,
      refresh_token: "test-refresh-token",
      customParams: { foo: "bar" },
    };

    const subject = this.owner.lookup("authenticator:oidc");
    const bodyWithRefresh = subject._buildBodyQuery(bodyOptions);
    assert.strictEqual(
      bodyWithRefresh,
      "redirect_uri=test%2Fredirect&client_id=test-client&grant_type=refresh_token&foo=bar&refresh_token=test-refresh-token",
    );

    bodyOptions.isRefresh = false;
    const bodyWithoutRefresh = subject._buildBodyQuery(bodyOptions);
    assert.strictEqual(
      bodyWithoutRefresh,
      "redirect_uri=test%2Fredirect&client_id=test-client&grant_type=authorization_code&foo=bar&code=test-code",
    );
  });

  module("_scheduleRefresh error handling", function () {
    test("it does nothing when expireTime is falsy (0)", function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      subject._scheduleRefresh(0, "token");
      assert.strictEqual(
        subject._upcomingRefresh,
        undefined,
        "No refresh is scheduled when expireTime is 0",
      );
    });

    test("it does nothing when expireTime is null", function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      subject._scheduleRefresh(null, "token");
      assert.strictEqual(
        subject._upcomingRefresh,
        undefined,
        "No refresh is scheduled when expireTime is null",
      );
    });

    test("it does nothing when expireTime is undefined (NaN guard)", function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      subject._scheduleRefresh(undefined, "token");
      assert.strictEqual(
        subject._upcomingRefresh,
        undefined,
        "No refresh is scheduled when expireTime is undefined",
      );
    });

    test("it does nothing when expireTime is in the past", function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      const pastTime = new Date().getTime() - 10000;
      subject._scheduleRefresh(pastTime, "token");
      assert.strictEqual(
        subject._upcomingRefresh,
        undefined,
        "No refresh is scheduled when expireTime is in the past",
      );
    });

    test("it schedules a refresh when expireTime is in the future", function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      const futureTime = new Date().getTime() + 60000;
      subject._scheduleRefresh(futureTime, "token");
      assert.notStrictEqual(
        subject._upcomingRefresh,
        undefined,
        "A refresh is scheduled when expireTime is in the future",
      );
      // Clean up the scheduled timer
      cancel(subject._upcomingRefresh);
      subject._upcomingRefresh = null;
    });
  });

  module("_scheduleRefresh generation counter", function () {
    test("it bumps the generation counter on each call", function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      const futureTime = new Date().getTime() + 60000;

      subject._scheduleRefresh(futureTime, "token");
      const gen1 = subject._refreshGeneration;

      subject._scheduleRefresh(futureTime, "token");
      const gen2 = subject._refreshGeneration;

      assert.ok(gen2 > gen1, "Generation counter is bumped on each call");

      // Clean up
      cancel(subject._upcomingRefresh);
      subject._upcomingRefresh = null;
    });

    test("it cancels the previous timer when scheduling a new one", function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      const futureTime = new Date().getTime() + 60000;

      subject._scheduleRefresh(futureTime, "token");
      const firstTimer = subject._upcomingRefresh;
      assert.ok(firstTimer, "First timer is scheduled");

      subject._scheduleRefresh(futureTime, "token");
      const secondTimer = subject._upcomingRefresh;
      assert.ok(secondTimer, "Second timer is scheduled");
      assert.notEqual(
        firstTimer,
        secondTimer,
        "A new timer replaced the old one",
      );

      // Clean up
      cancel(subject._upcomingRefresh);
      subject._upcomingRefresh = null;
    });
  });

  module("invalidate cancels refresh", function () {
    test("it cancels a pending scheduled refresh", async function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      // Stub _refresh to prevent network requests from the scheduled timer
      sinon.stub(subject, "_refresh").resolves({});

      // Manually set a truthy _upcomingRefresh so invalidate's guard fires
      subject._upcomingRefresh = 42;

      await subject.invalidate();
      assert.strictEqual(
        subject._upcomingRefresh,
        null,
        "Pending refresh is cancelled (set to null) after invalidate",
      );
    });

    test("it bumps _refreshGeneration so stale callbacks are discarded", async function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");

      // Set a known generation value
      subject._refreshGeneration = 5;

      await subject.invalidate();
      assert.strictEqual(
        subject._refreshGeneration,
        6,
        "Generation counter is bumped after invalidate",
      );
    });
  });

  module("_handleAuthResponse preserves refresh_token", function () {
    test("it uses _lastRefreshToken when response has no refresh_token", async function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      subject._lastRefreshToken = "stashed-refresh-token";

      // Stub _scheduleRefresh to avoid side effects
      sinon.stub(subject, "_scheduleRefresh");

      const result = await subject._handleAuthResponse({
        access_token: "new-access",
        refresh_token: undefined,
        expires_in: 300,
        id_token: "id",
        redirectUri: "test",
      });

      assert.strictEqual(
        result.refresh_token,
        "stashed-refresh-token",
        "Falls back to _lastRefreshToken",
      );
    });

    test("it uses response refresh_token and updates _lastRefreshToken", async function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      subject._lastRefreshToken = "old-refresh-token";

      sinon.stub(subject, "_scheduleRefresh");

      const result = await subject._handleAuthResponse({
        access_token: "new-access",
        refresh_token: "new-refresh-token",
        expires_in: 300,
        id_token: "id",
        redirectUri: "test",
      });

      assert.strictEqual(
        result.refresh_token,
        "new-refresh-token",
        "Uses the refresh_token from the response",
      );
      assert.strictEqual(
        subject._lastRefreshToken,
        "new-refresh-token",
        "_lastRefreshToken is updated to the new value",
      );
    });

    test("it throws when both response and _lastRefreshToken are empty", async function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      subject._lastRefreshToken = undefined;

      sinon.stub(subject, "_scheduleRefresh");

      await assert.rejects(
        subject._handleAuthResponse({
          access_token: "new-access",
          refresh_token: undefined,
          expires_in: 300,
          id_token: "id",
          redirectUri: "test",
        }),
        /refresh_token is missing/,
        "Throws when no refresh_token is available",
      );
    });
  });

  module("restore refresh conditions", function () {
    test("it refreshes when access_token is missing", async function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      const refreshStub = sinon
        .stub(subject, "_refresh")
        .resolves({ access_token: "new", refresh_token: "rt" });

      await subject.restore({
        refresh_token: "rt",
        expireTime: new Date().getTime() + 60000,
        redirectUri: "test",
      });

      assert.ok(
        refreshStub.calledOnce,
        "_refresh is called when access_token is missing",
      );
    });

    test("it refreshes when expireTime is undefined", async function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      const refreshStub = sinon
        .stub(subject, "_refresh")
        .resolves({ access_token: "new", refresh_token: "rt" });

      await subject.restore({
        refresh_token: "rt",
        access_token: "at",
        expireTime: undefined,
        redirectUri: "test",
      });

      assert.ok(
        refreshStub.calledOnce,
        "_refresh is called when expireTime is undefined",
      );
    });

    test("it refreshes when expireTime is in the past", async function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      const refreshStub = sinon
        .stub(subject, "_refresh")
        .resolves({ access_token: "new", refresh_token: "rt" });

      await subject.restore({
        refresh_token: "rt",
        access_token: "at",
        expireTime: new Date().getTime() - 10000,
        redirectUri: "test",
      });

      assert.ok(
        refreshStub.calledOnce,
        "_refresh is called when expireTime is in the past",
      );
    });

    test("it returns sessionData when token is still valid", async function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");
      const futureTime = new Date().getTime() + 60000;
      const sessionData = {
        refresh_token: "rt",
        access_token: "at",
        expireTime: futureTime,
        redirectUri: "test",
      };

      // Stub _scheduleRefresh to avoid side effects
      sinon.stub(subject, "_scheduleRefresh");

      const result = await subject.restore(sessionData);

      assert.strictEqual(
        result,
        sessionData,
        "Returns the original session data when token is still valid",
      );
    });

    test("it stashes refresh_token in _lastRefreshToken before calling _refresh", async function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");

      let capturedLastRefreshToken;
      sinon.stub(subject, "_refresh").callsFake(function () {
        capturedLastRefreshToken = subject._lastRefreshToken;
        return Promise.resolve({ access_token: "new", refresh_token: "rt" });
      });

      await subject.restore({
        refresh_token: "my-refresh-token",
        expireTime: new Date().getTime() - 10000,
        redirectUri: "test",
      });

      assert.strictEqual(
        capturedLastRefreshToken,
        "my-refresh-token",
        "_lastRefreshToken is set before _refresh is called",
      );
    });

    test("it throws when refresh_token is missing", async function (assert) {
      const subject = this.owner.lookup("authenticator:oidc");

      await assert.rejects(
        subject.restore({
          access_token: "at",
          expireTime: new Date().getTime() + 60000,
          redirectUri: "test",
        }),
        /Refresh token is missing/,
        "Throws when refresh_token is missing from session data",
      );
    });
  });
});
