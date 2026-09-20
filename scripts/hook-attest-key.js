// Generate-time attest-key hook. Runs INSIDE keystore2 (attached by
// 03-hook-attest.sh before the app's first launch). TEESimulator's
// KeyMintSecurityLevelInterceptor holds every generated key in a
// GeneratedKeyInfo (KeyPair, nspace, response); the constructor fires at
// generatedKeys.put() time for the three keygen branches. We grab the
// PKCS8 bytes the moment the key is created and write attest.json directly.
//
// Only target-app (co.twickets.droid) traffic is intercepted, so any captured
// key is the app's attest key. attest.json is only complete once key_id is
// known, so the script writes /data/output/attest-raw.txt (b64 PKCS8) and
// the runner composes the final JSON.

function findTeeLoader() {
  let found = null;
  Java.enumerateClassLoadersSync().forEach(function (loader) {
    if (found) return;
    try {
      loader.loadClass("org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor");
      found = loader;
    } catch (e) { }
  });
  return found;
}

Java.perform(function () {
  let loader = findTeeLoader();
  if (!loader) {
    // The module's injector may not have finished hooking keystore2 yet.
    send({ type: "status", payload: "TEESimulator classloader not found yet" });
    return;
  }
  const factory = Java.ClassFactory.get(loader);

  const Info = factory.use(
    "org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor$GeneratedKeyInfo"
  );

  Info.$init.overload(
    "java.security.KeyPair",
    "long",
    "android.system.keystore2.KeyEntryResponse"
  ).implementation = function (keyPair, nspace, response) {
    this.$init(keyPair, nspace, response);
    try {
      const enc = keyPair.getPrivate().getEncoded();
      const b64 = Java.use("android.util.Base64")
        .encodeToString(enc, 2);
      send({ type: "attest", payload: b64, nspace: String(nspace) });
    } catch (e) {
      send({ type: "status", payload: "extract failed: " + e });
    }
  };
  send({ type: "status", payload: "hook armed on GeneratedKeyInfo$init" });
});