
LOG_FILE = '/var/log/intangd.log'

cost = {}


f = open(LOG_FILE, 'r')

for line in f:
    line = line[:-1]
    parts = line.split()
    ts = float(parts[0])
    if 'DNS request' in line:
        txn_id = parts[-1]
        cost[txn_id] = [0,ts,0,0]
    if 'DNS UDP response' in line:
        txn_id = parts[-1]
        if txn_id not in cost: print('%s has no req' % txn_id)
        else:
            cost[txn_id][2] = ts
            cost[txn_id][3] = ts - cost[txn_id][1]
    if 'DNS TCP response' in line:
        txn_id = parts[-1]
        if txn_id not in cost: print('%s has no req' % txn_id)
        else:
            cost[txn_id][0] = 1
            cost[txn_id][2] = ts
            cost[txn_id][3] = ts - cost[txn_id][1]
f.close()

#print(cost)

for t, _, _, c in cost.values():
    if c == 0: continue
    if t == 0:
        print('UDP %f' % c)
    else:
        print('TCP %f' % c)


