

## Installation

To just install the python aid library

    pip install aid

 To also install the aid-iptables script.  **NOTE:** the aid-iptables script requires (and will install as a dependency) the python-iptables library, which requires iptables.

    pip install "aid[iptables]"

## Configuration

By default the aid module expects a configuration file in the user's home folder named '.aid.json'.  The configuration file is a single JSON dictionary containing two keys, "server" and "api_key".  

### Example .aid.json configuration file


    {
      "server": "https://aid.example.com",
      "token": "234a9c9bd909f90df023810aced0bef0752a",
    }

See the individual documentation for the aid module or the aid-iptables script for infomation about changing the location and name of the configuration file.

## Documentation

### [aid module api](docs/aid.html)
### [aid module usage](docs/aid_usage.html)
### [aid-iptables usage](docs/aid-iptables.html)
