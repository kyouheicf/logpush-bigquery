// Need npm install js-base64
import { Base64 } from 'js-base64'

export default {
	async fetch(request, env, ctx) {
		// Check pre-shared key header
		const PRESHARED_AUTH_HEADER_KEY = 'X-Logpush-Auth';
		const PRESHARED_AUTH_HEADER_VALUE = 'mypresharedkey';
		const psk = request.headers.get(PRESHARED_AUTH_HEADER_KEY);
		const contentEncoding = request.headers.get('content-encoding')
		if (psk !== PRESHARED_AUTH_HEADER_VALUE) {
			return new Response('Sorry, you have submitted an invalid key.', {
				status: 403,
			});
		}

		// Signing the JWT by Service Account Credential
		const serviceAccount = JSON.parse(env.GOOGLE_APPLICATION_CREDENTIALS)
		const pem = serviceAccount.private_key.replace(/\n/g, '')
		const pemHeader = '-----BEGIN PRIVATE KEY-----';
		const pemFooter = '-----END PRIVATE KEY-----';

		if (!pem.startsWith(pemHeader) || !pem.endsWith(pemFooter)) {
			throw new Error('Invalid service account private key');
		}

		const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);

		const buffer = Base64.toUint8Array(pemContents)

		const algorithm = {
			name: 'RSASSA-PKCS1-v1_5',
			hash: {
				name: 'SHA-256',
			}
		}

		const extractable = false
		const keyUsages = ['sign']

		const privateKey = await crypto.subtle.importKey('pkcs8', buffer, algorithm, extractable, keyUsages)

		const header = Base64.encodeURI(
			JSON.stringify({
				alg: 'RS256',
				typ: 'JWT',
				kid: serviceAccount.private_key_id,
			}),
		)

		const iat = Math.floor(Date.now() / 1000)
		const exp = iat + 3600

		const payload = Base64.encodeURI(
			JSON.stringify({
				iss: serviceAccount.client_email,
				sub: serviceAccount.client_email,
				aud: 'https://bigquery.googleapis.com/',
				exp,
				iat
			})
		)

		const textEncoder = new TextEncoder()
		const inputArrayBuffer = textEncoder.encode(`${header}.${payload}`)

		const outputArrayBuffer = await crypto.subtle.sign(
			{ name: 'RSASSA-PKCS1-v1_5' },
			privateKey,
			inputArrayBuffer
		)

		const signature = Base64.fromUint8Array(new Uint8Array(outputArrayBuffer), true)
		const token = `${header}.${payload}.${signature}`

		// Request Handling Start
		const buf = await request.arrayBuffer();
		const enc = new TextDecoder("utf-8");

		if (contentEncoding === 'gzip') {
			// Decompress gzipped logpush body to json
			const blob = new Blob([buf])
			const ds = new DecompressionStream('gzip');
			const decompressedStream = blob.stream().pipeThrough(ds);
			const buffer = await new Response(decompressedStream).arrayBuffer();
			const decompressed = new Uint8Array(buffer)
			const ndjson = enc.decode(decompressed)
			console.log(`Received ndjson === ${ndjson}`)
			const json = ndjson.split('\n')

			// Retrieve Column String from json keys
			const columns = Object.keys(JSON.parse(json[0]))
			const columns_string = columns.join(",")
			console.log(`columns_string === ${columns_string}`)

			// Make Values String
			const replace = `\"(${columns.join("|")})\":`;
			const re = new RegExp(replace, "g");
			const values = json.map(item => item.replace(re, '').replace(/{/g, '(').replace(/}/g, ')'))
			const values_string = values.join(",")
			console.log(`values_string === ${values_string}`)

			// Make POST data to Big Query
			const payload = {
				kind: "bigquery#queryRequest",
				query: `INSERT INTO ${serviceAccount.project_id}.${env.DATASET_ID}.${env.TABLE_ID} (${columns_string}) VALUES ${values_string}`,
				location: "US",
				useLegacySql: false,
			}
			console.log(`POST data === ${JSON.stringify(payload)}`)

			// POST QueryRequest
			return await fetch(
				`https://bigquery.googleapis.com/bigquery/v2/projects/${serviceAccount.project_id}/queries`,
				{
					method: 'POST',
					body: JSON.stringify(payload),
					headers: {
						'Content-Type': 'application/json',
						Authorization: `Bearer ${token}`
					}
				}
			)
		} else {
			// Initial pre-flight Logpush Request to confirm the integration check
			const compressed = new Uint8Array(buf);
			console.log(enc.decode(compressed).trim()) //{"content":"test","filename":"test.txt"}')
			const json = '{"content":"test","filename":"test.txt"}';
			return new Response('Initial pre-flight Logpush Request has been confirmed', {
				status: 200,
			})
		}
	},
};
