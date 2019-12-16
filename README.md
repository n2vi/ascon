# ascon
Ascon is a family of lightweight authenticated encryption schemes with associated data (AEAD); see github.com/ascon/ascon-c.
The ascon80pq cipher in particular seems attractively simple and quantum-resistant. This repository provides a Go implementation.

I created this for the github.com/n2vi/hotline project in order to have a cipher not invented within a NATO country, in case international partners wanted that.

# paxz
This repository also provides the command paxz, an archiver implemented in Go roughly corresponding to "tar|gzip|openssl enc". Besides providing a concrete example of calling ascon80pq, paxz is a backup tool that handles long filenames, has almost no options to fuss with, and when in doubt picks security.
