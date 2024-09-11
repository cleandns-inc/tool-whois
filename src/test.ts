import { whois } from "./index.js";

whois(process.argv[2], { thinOnly: Boolean(process.argv[3]) }).then((r) =>
  console.log(JSON.stringify(r, undefined, 2))
);
