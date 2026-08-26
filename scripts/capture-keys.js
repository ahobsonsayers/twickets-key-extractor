// Capture the 4 Twickets catalogue API keys and emit them as JSON.
//
// The 3 header keys are added once the integrity JWE is generated, possibly on
// a non-catalogue request, so watch all requests carrying the token. api_key
// is a query param; any token request also carries User-Agent + site-key.
// (Request.toString() redacts only Cookie, which the endpoint doesn't need.)

// Header keys to capture from each request's toString() block.
const KEYS = [
	"User-Agent",
	"x-prosopo-site-key",
	"x-prosopo-android-integrity-token",
];

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

Java.perform(() => {
	try {
		// ha0.i is the obfuscated OkHttp Chain; .f() is proceed(request).
		const Chain = Java.use("ha0.i");
		Chain.f.overload("mz.p2").implementation = function (req) {
			try {
				const urlStr = req.toString();
				const hasToken = urlStr.includes("x-prosopo-android-integrity-token");

				// Diagnostic: log every call so we can see if the hook is live
				// and what requests actually look like.
				send({
					type: "debug",
					payload: `${hasToken ? "TOKEN" : "no-token"} ${urlStr}`,
				});

				// Emit only when the integrity JWE is present — all 4 keys are ready.
				if (hasToken) {
					send({ type: "keys", payload: extract(urlStr) });
				}
			} catch (_e) {
				// ignore parse errors on requests mid-build
			}

			return this.f(req);
		};

		send({ type: "status", payload: "hooked ha0.i.f" });
	} catch (_e) {
		send({ type: "status", payload: `outer ${_e}` });
	}
});
