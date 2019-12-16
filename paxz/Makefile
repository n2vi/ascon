T=/tmp/ehg.paxz

test:
	go install
	P="abracadabra" paxz > $T
	ls -l $T
	@echo 'to recover, P="abracadabra" paxz -d junk < '$T
