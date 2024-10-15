# Fetch + Evict Side Channel Communication

transmit data (in this case, some simple shellcode) between 2 processes without the use of shared memory, but instead using a shared buffer mapped between 2 files (in this case a .dll) and a fetch + evict side channel. This is only a simple implementation for my own learning and nothing more after reading a few sources.

# usage

1. compile
2. fec recv to recv fec hello to send shellcode
3. receiving client will print result 

# Sources

- https://github.com/Peribunt/CTC
- https://github.com/moehajj/Flush-Reload
- https://github.com/pavel-kirienko/cpu-load-side-channel/tree/main
- https://github.com/jiyongyu/covert_channel_chatbot
- https://github.com/yshalabi/covert-channel-tutorial
- https://yuval.yarom.org/pdfs/KosasihFCYZ24.pdf