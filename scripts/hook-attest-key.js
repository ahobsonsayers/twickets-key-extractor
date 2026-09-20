// Attest-key hook. Runs INSIDE the TEESimulator daemon (attached by
// 03-hook-attest.sh before the app's first launch). Two capture points:
//  - GeneratedKeyInfo$init: fires at keygen (fresh AVD => 04's first launch).
//  - Signer$init: fires on EVERY sign op the daemon executes for the app
//    (SoftwareOperation purpose=2), so capture works even when the app is
//    already attested and keygen never fires.
// Only target-app (co.twickets.droid) traffic is intercepted, so any
// captured key is the app's attest key. attest.json needs key_id (prefs),
// so the hook only emits b64 PKCS8 and 05 composes the final JSON.
//
// The daemon (app_process) has no package data dir, so Java.perform's init
// path throws — arm from a timer instead; the Java bridge lazily
// initializes fine from there. Hooks arm on EVERY classloader resolving
// TEESimulator and re-arm every tick: a once-armed hook can end up bound
// to a classloader copy the app's calls never reach.

const seen = {};
let tries = 0;

// Frida wrappers for interface-typed returns can miss methods inherited
// from parent interfaces (Key.getEncoded) — walk direct/reflection/cast
// until one returns bytes.
function encodedOf(priv) {
	const attempts = [
		["direct", () => priv.getEncoded()],
		[
			"refl",
			() => priv.getClass().getMethod("getEncoded", null).invoke(priv, null),
		],
		[
			"castPK",
			() => Java.cast(priv, Java.use("java.security.PrivateKey")).getEncoded(),
		],
		[
			"castK",
			() => Java.cast(priv, Java.use("java.security.Key")).getEncoded(),
		],
	];
	const why = [];
	for (const [name, get] of attempts) {
		try {
			const enc = get();
			if (enc) return enc;
		} catch (e) {
			why.push(`${name}:${e}`);
		}
	}
	throw new Error(why.join(" | "));
}

function emitKey(keyPair, nspace, label) {
	try {
		const b64 = Java.use("android.util.Base64").encodeToString(
			encodedOf(keyPair.getPrivate()),
			2,
		);
		if (!seen[b64]) {
			seen[b64] = true;
			send({ type: "attest", payload: b64, nspace: nspace });
		}
	} catch (e) {
		if (!seen[label + String(e)]) {
			seen[label + String(e)] = true;
			send({
				type: "status",
				payload: `${label} extract failed: ${e} stack=${e.stack}`,
			});
		}
	}
}

const timer = setInterval(() => {
	tries += 1;
	if (tries > 600) {
		clearInterval(timer);
		send({
			type: "status",
			payload: "TEESimulator classloader never appeared",
		});
		return;
	}
	if (tries % 30 === 0) send({ type: "status", payload: "hook alive" });

	Java.enumerateClassLoadersSync().forEach((loader) => {
		try {
			loader.loadClass(
				"org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor",
			);
		} catch (_e) {
			return;
		}
		const factory = Java.ClassFactory.get(loader);

		try {
			const Info = factory.use(
				"org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor$GeneratedKeyInfo",
			);
			// Re-arm every tick: a daemon restart or late injector pass can swap
			// the classloader, leaving a once-armed hook bound to a dead class.
			Info.$init.overload(
				"java.security.KeyPair",
				"long",
				"android.system.keystore2.KeyEntryResponse",
			).implementation = function (keyPair, nspace, response) {
				this.$init(keyPair, nspace, response);
				emitKey(keyPair, String(nspace), "keygen");
			};
			if (!Info.$init.hooked) {
				Info.$init.hooked = true;
				send({
					type: "status",
					payload: "hook armed on GeneratedKeyInfo$init",
				});
			}
		} catch (_e) {}

		try {
			const Signer = factory.use(
				"org.matrix.TEESimulator.interception.keystore.shim.Signer",
			);
			Signer.$init.implementation = function (keyPair, params) {
				this.$init(keyPair, params);
				emitKey(keyPair, "sign-op", "signer");
			};
			if (!Signer.$init.hooked) {
				Signer.$init.hooked = true;
				send({ type: "status", payload: "hook armed on Signer$init" });
			}
		} catch (_e) {}
	});
}, 500);
