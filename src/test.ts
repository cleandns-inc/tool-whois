import { whois } from "./index.js";

whois(process.argv[2]).then((r) =>
  console.log(JSON.stringify(r, undefined, 2))
);
