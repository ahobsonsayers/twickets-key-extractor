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
	const out = {};

	// Pull the headers=[...] block out of the request's toString().
	const headers = reqStr.match(/headers=\[([^\]]*)\]/);
	if (headers) {
		const lines = headers[1].split(", ");
		for (const l of lines) {
			// Each entry is "Name:Value"; split on the first colon.
			const idx = l.indexOf(":");
			if (idx === -1) continue;

			const name = l.slice(0, idx);
			if (KEYS.indexOf(name) !== -1) out[name] = l.slice(idx + 1);
		}
	}

	// api_key is a query param, not a header.
	const m = reqStr.match(/[?&]api_key=([^&,]+)/);
	if (m) out.api_key = decodeURIComponent(m[1]);

	return out;
}

Java.perform(() => {
	try {
		// ha0.i is the obfuscated OkHttp Chain; .f() is proceed(request).
		const Chain = Java.use("ha0.i");
		Chain.f.overload("mz.p2").implementation = function (req) {
			try {
				const urlStr = req.toString();

				// Emit only when the integrity JWE is present — all 4 keys are ready.
				if (urlStr.indexOf("x-prosopo-android-integrity-token") !== -1) {
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
