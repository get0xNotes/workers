# 0xNotes Worker
Backend for 0xNotes, powered by Cloudflare Workers.

## Setting up development environment
1. Clone the repository `git clone git@github.com:get0xNotes/workers.git`
2. Run `cd workers && yarn`
3. Create a `.dev.vars` file containing the following:
```env
POSTGREST_ENDPOINT = "https://pg.example.com/rest/v1"
POSTGREST_APIKEY = "A bearer token to access the endpoint"
SERVER_JWK = '{"alg":"EdDSA","kty":"OKP","crv":"Ed25519","x":"","d":""}'
```
4. Run `wrangler dev`

## License

MIT License
