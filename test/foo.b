ld [4]
jne #0xc000003e, bad
ld [0]
jeq #15, good
jeq #231, good
jeq #60, good
jeq #0, good
jeq #1, good
jeq #5, good
jeq #9, good
jeq #14, good
jeq #13, good
jeq #35, good
bad: ret #0
good: ret #0x7fff0000
