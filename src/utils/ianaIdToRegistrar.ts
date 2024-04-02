type IanaRegistrarId = number;
type IanaRegistrarStatus = "Terminated" | "Accredited" | "Reserved";

interface IanaRegistrar {
  id: IanaRegistrarId;
  name: string;
  status: IanaRegistrarStatus;
  url: string;
}

export const ianaToRegistrarCache = new Map<IanaRegistrarId, IanaRegistrar>();
export async function ianaIdToRegistrar(
  item: number
): Promise<IanaRegistrar | undefined> {
  if (ianaToRegistrarCache.size === 0) {
    // console.warn(`fetching iana-to-registrar`);
    const response = await fetch(
      `https://www.iana.org/assignments/registrar-ids/registrar-ids-1.csv`
    ).then((r) => r.text());
    const records = response.matchAll(
      /^(?:"(\d+)"|(\d+)),(?:"([^\n\r"]*)"|([^\n\r",]*)),(?:"([^\n\r"]*)"|([^\n\r",]*)),(?:"([^\n\r"]*)"|([^\n\r",]*))/gm
    );
    for (const record of records) {
      const id = parseInt(record[1] || record[2]);
      const name = record[3] || record[4];
      const status = (record[5] || record[6]) as IanaRegistrarStatus;
      const url = record[7] || record[8];

      ianaToRegistrarCache.set(id, { id, name, status, url });
    }
  }

  return ianaToRegistrarCache.get(item);
}
