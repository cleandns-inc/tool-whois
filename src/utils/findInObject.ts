export function findInObject(
  obj: Object,
  condition: (el: any) => boolean,
  extractor: (el: any) => any,
  fallback: any
): any {
  const found = _findInObject(obj, condition);
  return found === undefined ? fallback : extractor(found);
}
function _findInObject(obj: any, condition: (el: any) => boolean): any {
  for (const key in obj) {
    if (condition(obj[key])) {
      return obj[key];
    }

    if (typeof obj[key] === "object") {
      const result = _findInObject(obj[key], condition);
      if (result !== undefined) {
        return result;
      }
    }
  }
}
