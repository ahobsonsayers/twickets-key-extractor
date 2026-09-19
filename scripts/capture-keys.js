// Capture the 4 Twickets catalogue API keys and emit them as JSON.
//
// R8 obfuscated names rotate every release (the chain class ha0.i in v3.19
// no longer exists in v3.20), so nothing obfuscated is hardcoded here: hook
// the app's own un-obfuscated interceptors, take the live OkHttp chain they
// receive, then hook that chain class's proceed-shaped methods. When a
// request's toString() carries the integrity JWE, all 4 keys are ready.
// (toString() redacts only Cookie, which the endpoint doesn't need.)

// Header keys to capture from each request's toString() block. The sdk
// version is new in v3.20 (static, on all protect + main-API requests);
// keys.json still carries only the 4 proven replay keys.
const KEYS = [
	"User-Agent",
	"x-prosopo-site-key",
	"x-prosopo-android-integrity-token",
	"x-prosopo-android-sdk-version",
];

// The chain is an R8-tiny name ("ha0.i", "c60.p") unless okhttp is kept.
const isChainClass = (name) =>
	/^[a-z][a-z0-9]{0,4}\.[a-zA-Z][a-zA-Z0-9]{0,4}$/.test(name) ||
	name.startsWith("okhttp3.");

function extract(reqStr) {
	const keys = {};

	// Pull the headers=[...] block out of the request's toString().
	const headers = reqStr.match(/headers=\[([^\]]*)\]/);
	if (headers) {
		const lines = headers[1].split(", ");
		for (const line of lines) {
			// Each entry is "Name:Value"; split on the first colon.
			const colonIdx = line.indexOf(":");
			if (colonIdx === -1) continue;

			const name = line.slice(0, colonIdx);
			if (KEYS.includes(name)) keys[name] = line.slice(colonIdx + 1);
		}
	}

	// api_key is a query param, not a header.
	const apiKeyMatch = reqStr.match(/[?&]api_key=([^&,]+)/);
	if (apiKeyMatch) keys.api_key = decodeURIComponent(apiKeyMatch[1]);

	return keys;
}

let chainHooked = false;
let chainFailures = 0;

function capture(urlStr) {
	const hasToken = urlStr.includes("x-prosopo-android-integrity-token");

	// Diagnostic: log every request so we can see if the hook is live.
	send({
		type: "debug",
		payload: `${hasToken ? "TOKEN" : "no-token"} ${urlStr}`,
	});

	if (hasToken) {
		send({ type: "keys", payload: extract(urlStr) });
	}
}

// Hook every instance method of the live chain's class shaped like
// proceed(request): one param, non-void return. The Request{ check skips
// any argument that isn't an okhttp Request.
function hookChain(chain) {
	const className = String(chain.$className);
	const Chain = Java.use(className);
	const STATIC = 0x8;

	let hookedCount = 0;
	const methods = Chain.class.getDeclaredMethods();
	for (let i = 0; i < methods.length; i++) {
		let name;
		let param;
		try {
			const m = methods[i];
			const params = m.getParameterTypes();
			if (params.length !== 1 || (m.getModifiers() & STATIC) !== 0) continue;
			if (String(m.getReturnType().getName()) === "void") continue;
			name = String(m.getName());
			param = String(params[0].getName());
		} catch (_e) {
			// Unloaded parameter types can't be reflected past; skip.
			continue;
		}

		try {
			Chain[name].overload(param).implementation = function (req) {
				try {
					const urlStr = req.toString();
					if (urlStr.startsWith("Request{method=")) capture(urlStr);
				} catch (_e) {
					// ignore non-request args and requests mid-build
				}

				return this[name](req);
			};
			hookedCount++;
		} catch (_e) {
			// skip methods frida can't overload (synthetic/bridge)
		}
	}

	if (hookedCount === 0) {
		throw new Error(`no proceed candidates in ${className}`);
	}

	send({
		type: "status",
		payload: `hooked chain ${className} (${hookedCount} candidates)`,
	});
}

// The co.twickets.droid.networking.interceptor package is kept by R8
// (unrenamed v3.19 -> v3.20); their 1-param instance method is intercept().
function hookBootstrapClass(className) {
	const Cls = Java.use(className);
	const STATIC = 0x8;
	let hookedAny = false;
	const methods = Cls.class.getDeclaredMethods();
	for (let i = 0; i < methods.length; i++) {
		let name;
		let param;
		try {
			const m = methods[i];
			const params = m.getParameterTypes();
			if (params.length !== 1 || (m.getModifiers() & STATIC) !== 0) continue;
			if (String(m.getReturnType().getName()) === "void") continue;
			name = String(m.getName());
			param = String(params[0].getName());
		} catch (_e) {
			continue;
		}

		try {
			Cls[name].overload(param).implementation = function (chain) {
				const runtimeName = chain ? String(chain.$className) : "";
				if (!chainHooked && isChainClass(runtimeName)) {
					try {
						hookChain(chain);
						chainHooked = true;
					} catch (_e) {
						// A structural failure won't heal; stop spamming after 3 tries.
						chainHooked = ++chainFailures >= 3;
						send({ type: "status", payload: `chain ${_e}` });
					}
				}

				return this[name](chain);
			};
			hookedAny = true;
		} catch (_e) {
			// skip methods frida can't overload (synthetic/bridge)
		}
	}

	send({
		type: "status",
		payload: `hooked ${className}${hookedAny ? "" : " (no intercept candidates)"}`,
	});

	return hookedAny;
}

function hookBootstrap() {
	let classHooked = false;
	for (const cls of [
		"co.twickets.droid.networking.interceptor.ApiKeyInterceptor",
		"co.twickets.droid.networking.interceptor.UseAgentInterceptor",
	]) {
		try {
			if (hookBootstrapClass(cls)) classHooked = true;
		} catch (_e) {
			send({ type: "status", payload: `bootstrap ${_e}` });
		}
	}

	return classHooked;
}

Java.perform(() => {
	// The interceptors load with the networking stack; retry in case frida
	// attached before that happened.
	let attempts = 0;
	const tryHook = () => {
		if (hookBootstrap()) return;

		if (++attempts < 3) {
			setTimeout(tryHook, 3000);
		} else {
			send({
				type: "status",
				payload: "outer Error: no bootstrap interceptor found",
			});
		}
	};

	tryHook();
});
