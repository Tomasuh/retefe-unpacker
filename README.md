---
layout: post
title: "Retefe unpacker"
date: 2018-12-28
comments: true
categories:
---

# Retefe unpacker

This is a writeup on how to implement an unpacker for current versions (at the time of publication) of the banking malware Retefe.

Resources about the threat:
* [Retefe banking Trojan leverages EternalBlue exploit in Swiss campaigns](https://www.proofpoint.com/us/threat-insight/post/retefe-banking-trojan-leverages-eternalblue-exploit-swiss-campaigns)
* [The Retefe Saga](https://www.govcert.admin.ch/blog/33/the-retefe-saga)
* [Reversing Retefe](https://www.govcert.admin.ch/blog/35/reversing-retefe)
* [New version of Retefe Banking Trojan Uses EternalBlue](https://www.mysonicwall.com/sonicalert/searchresults.aspx?ev=article&id=1094)

Historically there seems to be some variance of ways the malware has stored it's Javascript payload. Some sources mentions self extracting ZIP files and other XORed data. The current version makes use of a 4 byte XOR key which is generated based on the scripts length and a few mathematical operations performed on it.
The post [Reversing Retefe](https://www.govcert.admin.ch/blog/35/reversing-retefe) from about two months back (2018-11-08) shows use of a one byte 
XOR key which indicates that the threat actor has changed its code base after the release of that post.
This post is made with the intention to shed some light on the current way the threat Retefe stores its payload.

Looking at the mapped binary image with IDA shows a large amount of unexplored data that is in the `.data` segment.

<div style="text-align:center"><img src="readme_images/code-explored.png"></div>

Browsing the `.data` segment with Binary Ninja shows a large segment of data whose top is referenced in a 
copy instruction:

<div style="text-align:center"><img src="readme_images/copy-instruction.png" width="75%" height="75%"></div>

The copy instruction is part of a function that passes the address of this copied data as an argument to a decoding function together with the length of the buffer:

<div style="text-align:center"><img src="readme_images/decoder-setup.png" width="75%" height="75%"></div>

The `decoder` function passes the `buffer length` and another `int` to a function that takes `buffer length` to the power of that `int`.
Then a shift and subtraction is performed. The result is the XOR key that is used to decode the buffer.

<div style="text-align:center"><img src="readme_images/xor-key.png" width="75%" height="75%"></div>

Later on the decode operation is performed:

<div style="text-align:center"><img src="readme_images/decoder-decode.png" width="60%" height="60%"></div>

That the data actually becomes decoded can be verified with a debugger, watching the memory of the buffer after the decoder function 
has ran:

![](readme_images/dbg.png)

With the above research its possible to write an unpacker.

The actions performed by the unpacker:
* Use yara rules to find buffer location buffer length, number of shifts, subtraction value and power to value of it.
* Calculate the buffer RVA as the extracted location is relative to the LEA instruction that references it
* Calculate XOR array based on values extracted with the help of the yara rules
* Extract and decode the script

The sourcecode to do this is available in [this](https://github.com/Tomasuh/retefe_unpacker) github repo.

Recent hashes that it has been confirmed to work on:
```
352b78b8ed38be7ada1d9f4d82352da5015a853bf3c3bdb8982e4977d98f981c
5c548447203104e9a26c355beaf2367a8fa4793a1b0d3668701ee9ba120b9a7b
1a3f25f4067e50aa113dfd9349fc4bdcf346d2e589ed6b4cebbc0a33e9eea50d
```

Example run:

![](readme_images/example-run.png)

Screenshots in this post are based on the sample `1a3f25f4067e50aa113dfd9349fc4bdcf346d2e589ed6b4cebbc0a33e9eea50d`.
