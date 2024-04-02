// turn an object with sequential numeric keys into an array
export function fixArrays (data: any) {
  if (Array.isArray(data)) {
    data = data.map(fixArrays);
  }
  else if (data && typeof data === "object") {
    if (data['0']) {
      data = Object.values(data).map(fixArrays);
    }
    else {
      data = Object.fromEntries(
        Object.entries(data).map(([key, value]) => [key, fixArrays(value)])
      );
    }
  }
  return data;
}
