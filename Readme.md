# HopNet

It all started with me unable to being able to communicate with a server at home. So instead of learnign trace route commands, I wrote my own.
Then I discovered I was being blocked due to NAT and firewall issues. So I decided to see how Skype worked without me having to bind a listening socket and opening ports.

I then found out about hole punching and implemented my own protocol for establishing hole punched UDP sockets.
I will be working on writing reliable delivery over UDP, as well as figuring out how to not need to do bullcrap like use a state store for information relay of control state during handshake. 

We also need a formal model of the protocol, so I need to implement that as well.

There's no license, so copy paste whatever you want and go brrr. Heads up there, are definitely race conditions that exist in protocol but everytime i run it, it eventually converges (liveness property)