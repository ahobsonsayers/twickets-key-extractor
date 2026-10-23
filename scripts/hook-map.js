// Attest-key extraction WITHOUT hooks: TrickyStoreOSS keeps keys ONLY in the
// daemon's RAM maps (SecurityLevelInterceptor.keyPairs / .keys /
// .patchedResponses). Walk the daemon's classloader, read the static maps,
// pull every EC private key we can reach, emit each PKCS8 once. 05's python
// verifier matches them against the leaf cert's pubkey.
const seen = {};

function clsName(obj) {
	const ob = Java.cast(obj, Java.use("java.lang.Object"));
	const c = ob.getClass();
	return String(Java.cast(c, Java.use("java.lang.Class")).getName());
}

function invokeObj(obj, method, ...margs) {
	const ob = Java.cast(obj, Java.use("java.lang.Object"));
	const c = ob.getClass();
	const cl = Java.cast(c, Java.use("java.lang.Class"));
	const ms = cl.getMethods();
	for (let i = 0; i < ms.length; i++) {
		if (String(ms[i].getName()) === method) {
			const argBox = Java.array("java.lang.Object", margs);
			return ms[i].invoke(ob, argBox);
		}
	}
	throw new Error(`no method ${method} on ${clsName(obj)}`);
}

function encodedOf(priv) {
	const attempts = [
		["direct", () => priv.getEncoded()],
		[
			"castK",
			() => Java.cast(priv, Java.use("java.security.Key")).getEncoded(),
		],
		[
			"castPK",
			() => Java.cast(priv, Java.use("java.security.PrivateKey")).getEncoded(),
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

function privFrom(obj, depth) {
	// Return a java.security.PrivateKey hiding inside obj, or null. The
	// daemon's types are R8-erased to Object, so everything goes through the
	// platform-reflection path (Array.get handles bind no methods directly).
	if (obj === null || obj === undefined || depth > 3) return null;
	const name = clsName(obj);
	if (name.indexOf("KeyPair") !== -1) {
		return privFrom(invokeObj(obj, "getPrivate"), depth + 1);
	}
	for (const iface of [
		"java.security.interfaces.ECPrivateKey",
		"java.security.PrivateKey",
	]) {
		try {
			const casted = Java.cast(obj, Java.use(iface));
			const enc = encodedOf(casted);
			if (enc) return casted;
		} catch (_e) {}
	}
	if (depth >= 3) return null;
	const ob = Java.cast(obj, Java.use("java.lang.Object"));
	const clsObj = Java.cast(ob.getClass(), Java.use("java.lang.Class"));
	const fields = clsObj.getDeclaredFields();
	for (let i = 0; i < fields.length; i++) {
		try {
			const f = Java.cast(fields[i], Java.use("java.lang.reflect.Field"));
			f.setAccessible(true);
			const v = f.get(ob);
			if (v === null) continue;
			const vcls = clsName(v);
			if (vcls === "java.lang.String") continue;
			const inner = privFrom(v, depth + 1);
			if (inner) return inner;
		} catch (err) {
			console.log(`privFrom field walk err @${name}[${i}]: ${err}`);
		}
	}
	return null;
}

function emitEncoded(priv) {
	try {
		const enc = encodedOf(priv);
		const b64 = Java.use("android.util.Base64").encodeToString(enc, 2);
		if (!seen[b64]) {
			seen[b64] = true;
			console.log(`PKCS8:${b64}`);
		}
	} catch (e) {
		console.log(`emit err: ${e}`);
	}
}

let fired = false;
const timer = setInterval(() => {
	if (fired) return;
	let loaders;
	try {
		loaders = Java.enumerateClassLoadersSync();
	} catch (_e) {
		return;
	}
	for (const loader of loaders) {
		try {
			loader.loadClass(
				"io.github.beakthoven.TrickyStoreOSS.interceptors.SecurityLevelInterceptor",
			);
		} catch (_e) {
			continue;
		}
		const factory = Java.ClassFactory.get(loader);
		let SLC;
		try {
			SLC = factory.use(
				"io.github.beakthoven.TrickyStoreOSS.interceptors.SecurityLevelInterceptor",
			);
		} catch (_e) {
			continue;
		}
		fired = true;
		console.log("SLC resolved — walking key maps");
		for (const mapName of ["keyPairs", "keys", "patchedResponses"]) {
			try {
				const holder = SLC[mapName];
				if (!holder) {
					console.log(`map ${mapName}: no such static`);
					continue;
				}
				const map = holder.value;
				if (!map) {
					console.log(`map ${mapName}: null`);
					continue;
				}
				// Frida's wrapper binds no java.util methods here; everything
				// goes through reflection.
				const size = invokeObj(map, "size");
				console.log(`map ${mapName}: size=${size}`);
				const es = invokeObj(map, "entrySet");
				const arr = invokeObj(es, "toArray");
				const ArrayCls = Java.use("java.lang.reflect.Array");
				console.log(`map ${mapName}: entries=${ArrayCls.getLength(arr)}`);
				for (let i = 0; i < ArrayCls.getLength(arr); i++) {
					const entry = ArrayCls.get(arr, i);
					const kk = invokeObj(entry, "getKey");
					const vv = invokeObj(entry, "getValue");
					let alias = "?";
					try {
						const kf = kk.getClass().getDeclaredFields();
						for (let j = 0; j < kf.length; j++) {
							kf[j].setAccessible(true);
							let v = null;
							try {
								v = kf[j].get(kk);
							} catch (_e) {
								continue;
							}
							if (v) {
								const vn = String(v.getClass().getName());
								if (vn === "java.lang.String") alias = String(v).slice(0, 40);
							}
						}
					} catch (_e) {}
					const priv = privFrom(vv, 0);
					console.log(
						`map ${mapName}[${i}] alias-like=${alias} -> ${priv ? "KEY FOUND" : "none"}`,
					);
					if (priv) emitEncoded(priv);
				}
			} catch (e) {
				console.log(`map ${mapName} walk failed: ${e}`);
			}
		}
		clearInterval(timer);
	}
}, 500);
