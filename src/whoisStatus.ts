const statusMap: Record<string,string> = {
  'inactive': 'inactive',

  'active': 'active',
  'ok': 'active',

  'pendingcreate': 'pending create',
  'pendingdelete': 'pending delete',
  'pendingrenew': 'pending renew',
  'pendingrestore': 'pending restore',
  'pendingtransfer': 'pending transfer',
  'pendingupdate': 'pending update',

  'addperiod': 'add period',
  'autorenewperiod': 'auto renew period',
  'redemptionperiod': 'redemption period',
  'renewperiod': 'renew period',
  'transferperiod': 'transfer period',

  'serverhold': 'server hold',
  'serverdeleteprohibited': 'server delete prohibited',
  'serverdeletedprohibited': 'server delete prohibited',
  'serverrenewprohibited': 'server renew prohibited',
  'servertransferprohibited': 'server transfer prohibited',
  'serverupdateprohibited': 'server update prohibited',

  'clienthold': 'client hold',
  'clientdeleteprohibited': 'client delete prohibited',
  'clientrenewprohibited': 'client renew prohibited',
  'clienttransferprohibited': 'client transfer prohibited',
  'clientupdateprohibited': 'client update prohibited',

  'hold': 'client hold',
  'deleteprohibited': 'client delete prohibited',
  'renewprohibited': 'client renew prohibited',
  'transferprohibited': 'client transfer prohibited',
  'updatedprohibited': 'client update prohibited',
};

export function normalizeWhoisStatus(status: string) {
  status = (status || "").toLocaleLowerCase();
  return statusMap[status.replace(/[ _]/g, '')] || status;
}
