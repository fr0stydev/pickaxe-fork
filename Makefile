# Makefile

CC := x86_64-w64-mingw32-gcc
STRIP := x86_64-w64-mingw32-strip
MCS := mcs
NM := x86_64-w64-mingw32-nm
SMA_REF ?=

OUT := _bin
BOF := $(OUT)/powerpick-fork.x64.o
HOST := $(OUT)/PowerPickForkHost.dll
MANAGED := $(OUT)/PowerPickFork.exe

CFLAGS_BOF := -Os -w -Wno-incompatible-pointer-types -I include \
	-fno-stack-check -fno-stack-protector -mno-stack-arg-probe
CFLAGS_HOST := -Os -w -I include -I native -shared -static-libgcc
LIBS_HOST := -loleaut32 -lshell32 -luser32 -lole32

.PHONY: all bof host managed verify clean

all: bof host managed verify

$(OUT):
	mkdir -p $(OUT)

bof: $(BOF)

$(BOF): native/powerpick_fork.c native/powerpick_fork_kayn_inject.h include/powerpick_fork_bof.h include/beacon.h | $(OUT)
	$(CC) $(CFLAGS_BOF) -c native/powerpick_fork.c -o $(BOF)
	$(STRIP) --strip-unneeded $(BOF)

host: $(HOST)

$(HOST): native/powerpick_fork_host.c native/kayn_ldr.c native/kayn_ldr.h native/PowerPickForkHost.def include/powerpick_fork_clr.h | $(OUT)
	$(CC) $(CFLAGS_HOST) native/powerpick_fork_host.c native/kayn_ldr.c native/PowerPickForkHost.def -o $(HOST) $(LIBS_HOST)
	$(STRIP) --strip-unneeded $(HOST)

managed: $(MANAGED)

$(MANAGED): managed/PowerPickFork.cs | $(OUT)
	@test -n "$(SMA_REF)" || (echo "SMA_REF must point to System.Management.Automation.dll" >&2; exit 1)
	@test -f "$(SMA_REF)" || (echo "SMA_REF does not exist: $(SMA_REF)" >&2; exit 1)
	$(MCS) -sdk:4 -platform:x64 -optimize+ -target:exe \
		-out:$(MANAGED) -r:"$(SMA_REF)" -r:System.Core \
		managed/PowerPickFork.cs

verify: $(BOF) $(HOST) $(MANAGED)
	@file $(BOF) $(HOST) $(MANAGED)
	@$(NM) $(BOF) | grep -Eq ' T go$$'
	@file $(MANAGED) | grep -Eq 'PE32\+|x86-64'
	@! strings $(BOF) $(HOST) | grep -Eiq 'patch(AMSI|ETW)|AmsiScanBuffer|EtwEventWrite'
	@! grep -REiq 'patch(AMSI|ETW)|AmsiScanBuffer|EtwEventWrite|ExecutionPolicy' native include managed

clean:
	rm -rf $(OUT)
