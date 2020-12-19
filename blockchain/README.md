# Bitcoin task implementation

At first, I analyzed the vulnerable clone of *bitaddress.org.html* website. Where is a modified key generator that is able to generate just 3000 distinct keys. Using browsers console I managed to get the correct values for key generation (*BigInteger: mod, multiply, add*, stored at *console.log*) that I later used in my python code. 

The Whole implementation is in the file named *main.py*. At the begining we generate all possible keys that need to be modified, double hashed, and converted to *base58* to meet the specific blockchain key format criteria. Using library *bitcoin* we can easily transform the private-key to the corresponding address. 

These addresses are then one by one looked up by API provided by *blockchaing.com*. Searching for non-zero parameter *n_tx* which represents the number of transactions.

This way I got to the address `1E2mSN7MXVuS4ecafhTLtaokf5RixcYUEU` with the corresponding private-key `KwDiBf89QgGbjEhKnhXJuY4GUMKjkbiQLBXrUaWStqmWnp3XBMte` that we searched for.

### Michal Ščupák, 19.12.2020