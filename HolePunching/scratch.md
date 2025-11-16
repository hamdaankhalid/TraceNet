Core problkem is that I am not able to know when my writes have been ack'd
after I start getting reads.

(peerA ctr, peerB ctr)

Initially they both send:
(0, 0)

peerA keeps sending his ctrs and peerB keeps sending their views of the ctrs

when peerA recvs they will increment peerB's ctr and now start sending this back.


Any time a peer sees their own counter has been incremented by the other peer
let's say peerA ctr is incremented by peerB.
This means that peerB recvd

The problem is that if A or B resets then the other one's A and B view does not change..