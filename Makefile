LDLIBS=-lpcap -lpthread

all: deauth-attack

deauth-attack: main.o mac.o radiotap.o beaconframe.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f deauth-attack *.o
