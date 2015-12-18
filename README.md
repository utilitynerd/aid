

## Installation

To install the latest aid module, run:

    pip install -U aid

The aid module contains scripts to create IPtables rules based on the AID list.  This functionality requires the python-iptables package, which requires iptables.  To automatically install the python-iptables along with the latest aid module, run:  

    pip install -U "aid[iptables]"

## Configuration

By default the aid module expects a configuration file in the user's home folder named '.aid.json'.  The configuration file is a single JSON dictionary containing two keys, "server" and "api_key".  

### Example .aid.json configuration file


    {
      "server": "https://aid.example.com",
      "api_key": "234a9c9bd909f90df023810aced0bef0752a"
    }



## General aid-list usage

The aid module installs a CLI script, named aid-list

    $ aid-list
    Usage: aid-list [OPTIONS] COMMAND [ARGS]...

    Options:
      -h, --help  Show this message and exit.

    Commands:
      entries   get list of entries from AID list
      ips       get list of IP Addresses from AID list
      iptables  Create IPTables rules based on the AID list
      services  List services monitored by AID list
 
 To show help for specific commands, run:
  
  aid-list COMMAND -h
 
    aid-list ips -h
    Usage: aid-list ips [OPTIONS]

      get list of IP Addresses from AID list

    Options:
      --start-date TEXT     default='1 week ago' - Generate AID list with IPs
                            detected since start-date (accepts most datetime
                            formats)
      --service TEXT        default='' filter results to only include specified
                            service(s), ex: --service=ssh,rdp
      --seen-count INTEGER  default=10 - Minimum # of alerts an aid list IP has
                            generated
      -h, --help            Show this message and exit.
      
 
## aid-list iptables usage
 
The iptables command will query the ISP AID List and automatically create iptables rules to block ips on the AID List.
 
    $ aid-list iptables -h
    Usage: aid-list iptables [OPTIONS]

      Create IPTables rules based on the AID list

    Options:
      --start-date TEXT          default='1 week ago' - Generate AID list with IPs
                                 detected since start-date (accepts most datetime
                                 formats)
      --service TEXT             default='' filter results to only include
                                 specified service(s), ex: --service=ssh,rdp
      --whitelist PATH           Path to whitelist file containing one ip address
                                 or subnet per line
      --seen-count INTEGER       default=10 - Minimum # of alerts an aid list IP
                                 has generated
      --chain-name TEXT          default=aid - The name of the iptables chain to
                                 use for the aid list
      --input-chain-pos INTEGER  default=0 - Position in INPUT chain to add a jump
                                 to the aid chain
      -h, --help                 Show this message and exit.
      
#### Default behavior
Running the **iptables** command with no arguments will:

- Query the AID List for all entries added within the last 7 days
- create (if needed) an IPTables Chain named "aid"
- add an unconditional jump to the "aid" chain as the first rule in the IPTables INPUT chain
- For each entry in the returned AID List, add an IPTables rule, with target=DROP, to the "aid" chain

#### Using a whitelist

Using the --whitelist parameter, a whitelist, a text file containing one IP Addresses or Subnet in CIDR notation per line, can be used to prevent IPTables block rules from being created for whitelist addresses / subnets.

#### chain-name

The **chain-name** parameter controls the name of the IPtables chain used by the iptables command.  By default, the chain's name is aid.  Caution must be taken if this parameter is changed after the iptables command has been run, as it will not attempt to flush or remove the old chain, this must be done manually

#### input-chain-pos 

By default, the iptables command will insert an unconditional jump to **chain-name** as the first rule in the INPUT chain.  The postion of this unconditional jump can be changed with **input-chain-pos** argument