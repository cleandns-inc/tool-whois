import { whois } from "./index.js";

whois(process.argv[2], { thinOnly: Boolean(process.argv[3]), server: process.argv[4] }).then((r) =>
  console.log(JSON.stringify(r, undefined, 2))
);
