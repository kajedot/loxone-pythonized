# loxone-pythonized

## What does this program do?
1. Establishing connection to the Loxone Miniserver using WebSockets
2. Authenticating with the user account
3. Sending commands that are added to the queue in the `Controller.py` file.

Communication is made using the flow described by the document provided by the Loxone Company: [COMMUNICATING WITH
THE LOXONE MINISERVER](https://www.loxone.com/dede/wp-content/uploads/sites/2/2022/06/1300_Communicating-with-the-Miniserver.pdf#h.59u218wukskj) (version 13.0)

## How to run?
0. Clone this repo and go to its root folder: \
  `git clone https://github.com/kajedot/loxone-pythonized.git` \
  `cd loxone-pythonized` 
  
1. Install requirements:
`pip install src/requirements.txt`

2. Define environment variables:
   - `MINISERVER_SN`: serial number of your Miniserver (12 alpha-numeric digits)
   - `MINISERVER_USER`: username on the miniserver that you want to use
   - `MINISERVER_PASSWD`: password of the user
  For example (Linux / macOS):
  `export MINISERVER_SN=ABCD12345678`

Disclaimer:
This software comes without any warranty. 
Feel free to fork and contribute :)

