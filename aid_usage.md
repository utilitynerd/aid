
# aid

aid is a collection of tools for interacting with UC Berkeley's AID (Aggressive IP Distribution) List.  The aid package consists of:

- aid module - python library for retrieving the AID list
- aid-iptables - cli script that generates IPTables Rules to block IPs contained in the AID List

## Using the aid module

First import the aid module


```python
import aid
from pprint import pprint
```

### Get all AID entries for the past week

By default, get_aidlist() will return all AID List entries from the past week


```python
aid_list = aid.get_aidlist()
```

get_aidlist returns a list of AidEntry namedtuples.

An AidEntry is a simple object (Named Tuple) with the following fields


```python
print(aid.AIDEntry._fields)
```

    ('ip', 'tags', 'dst_port', 'last_seen_ts', 'first_seen_ts', 'service', 'seen_count')



```python
print(aid_list[0])

entry = aid_list[0]
print()
print(entry.ip, entry.dst_port)
```

    AidEntry(ip=IPv4Address('122.224.6.150'), tags=[], dst_port=3306, last_seen_ts='2015-09-29T14:33:05.000-07:00', first_seen_ts='2015-05-17T16:20:23.000-07:00', service='mysql', seen_count=108)
    
    122.224.6.150 3306


### Filtering by service

The AID List can be filtered to only return a subset of services by passing a list to the services parameter.   The default value for services is "", and does apply any filtering by service.


```python
aid_list_ssh = aid.get_aidlist(services=['ssh'])
aid_list_rdp = aid.get_aidlist(services=['rdp'])

aid_list_ssh_and_rdp = aid.get_aidlist(services=['ssh', 'rdp'])

print(aid_list_ssh[0])
print()
print("aid_list_ssh: {0} entries\naid_list_rdp: {1} entries\naid_list_ssh_and_rdp {2} entries".format(
        len(aid_list_ssh), len(aid_list_rdp), len(aid_list_ssh_and_rdp)))
```

    AidEntry(ip=IPv4Address('58.218.211.166'), tags=[], dst_port=22, last_seen_ts='2015-09-29T14:49:49.000-07:00', first_seen_ts='2015-04-24T13:46:51.000-07:00', service='ssh', seen_count=17836)
    
    aid_list_ssh: 101 entries
    aid_list_rdp: 16 entries
    aid_list_ssh_and_rdp 117 entries


### Filtering by date

The AID List can also be filtered to only include IP's detected since a start date.  The default value for start_date is 1 week.


```python
aid_list_last_day = aid.get_aidlist(start_date='1 day')
aid_list_two_weeks = aid.get_aidlist(start_date='2 weeks')
aid_list_since_sept = aid.get_aidlist(start_date="2015-09-01")

print("aid_list_last_day: {}".format(len(aid_list_last_day)))
print("aid_list_two_weeks: {}".format(len(aid_list_two_weeks)))
print("aid_list_since_sept: {}".format(len(aid_list_since_sept)))
```

    aid_list_last_day: 51
    aid_list_two_weeks: 241
    aid_list_since_sept: 369


### Filtering by Aggressiveness

Each time an IP generates an alert, it's "seen_count" is incremented.  This can be used to filter out less aggressive IPs.  The default value for seen_count is 10.


```python
all_ips = aid.get_aidlist()
more_aggro_ips = aid.get_aidlist(seen_count=50)

print("all_ips: {}\naggro_ips: {}".format(len(all_ips), len(more_aggro_ips)))
```

    all_ips: 187
    aggro_ips: 86


### Combing Filters

All the above filtering techniques can be combined


```python
combo_filter = aid.get_aidlist(services=['ssh', 'rdp'], start_date='1 month', seen_count=25)
print("combo_filter: {}".format(len(combo_filter)))
```

    combo_filter: 155


### Getting Unique IP Addresses

If an IP generates alerts for multiple services (ssh and rdp for example) then that IP will have multiple entries in the aid list (one per service).  The aid modules also proves get_aidlist_ips which returns a list of unique IP addresses only.


```python
all_ips = aid.get_aidlist()
unique_ips = aid.get_aidlist_ips()

print("all_ips: {}\nunique_ips: {}".format(len(all_ips), len(unique_ips)))
print("\n")
for ip in unique_ips[:5]:
    print(ip)
```

    all_ips: 187
    unique_ips: 162
    
    
    5.45.79.24
    23.95.82.74
    27.24.213.194
    36.72.228.72
    43.229.53.13



```python

```
