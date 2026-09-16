# Protocol and implementation sources

`rocev2-rs` does not infer packet layouts from packet captures. Wire constants,
header semantics, ICRC masking and the Linux interoperability target are pinned
to primary specifications and maintained reference implementations.

## Normative protocol sources

- InfiniBand Trade Association, *InfiniBand Architecture Specification*, Volume
  1, especially the transport header/opcode tables, RC transport clauses, PSN
  rules, ACK/NAK/RNR behavior, and Annex A16/A17 invariant CRC and RoCE rules:
  <https://www.infinibandta.org/ibta-specification/>
- InfiniBand Trade Association, RoCE overview and specification materials:
  <https://www.infinibandta.org/roce/>
- IANA Service Name and Transport Protocol Port Number Registry, UDP port 4791
  (`roce`): <https://www.iana.org/assignments/service-names-port-numbers/>

The IBTA specification is authoritative where any reference implementation
appears to differ.

## Interoperability references

- Linux InfiniBand opcode values and fixed header sizes:
  <https://github.com/torvalds/linux/blob/master/include/rdma/ib_pack.h>
- Linux RXE BTH, RETH and AETH field masks/accessors:
  <https://github.com/torvalds/linux/blob/master/drivers/infiniband/sw/rxe/rxe_hdr.h>
- Linux RXE opcode-to-header table:
  <https://github.com/torvalds/linux/blob/master/drivers/infiniband/sw/rxe/rxe_opcode.c>
- Linux RXE requester state and RDMA READ PSN reservation:
  <https://github.com/torvalds/linux/blob/master/drivers/infiniband/sw/rxe/rxe_req.c>
- Linux RXE task wakeup coalescing and bounded requester/responder scheduling:
  <https://github.com/torvalds/linux/blob/master/drivers/infiniband/sw/rxe/rxe_task.c>
- Linux RXE responder, duplicate suppression and READ replay:
  <https://github.com/torvalds/linux/blob/master/drivers/infiniband/sw/rxe/rxe_resp.c>
- Linux RXE ICRC canonicalization and seed:
  <https://github.com/torvalds/linux/blob/master/drivers/infiniband/sw/rxe/rxe_icrc.c>
- Linux RXE RNR timer decoding:
  <https://github.com/torvalds/linux/blob/master/drivers/infiniband/sw/rxe/rxe_comp.c>

Linux RXE is an interoperability oracle, not the normative specification.
Tests should include independent vectors and hardware captures so that a shared
implementation bug does not become a project invariant.

## Packet I/O and Rust sources

- Linux kernel AF_XDP documentation:
  <https://docs.kernel.org/networking/af_xdp.html>
- Linux UAPI AF_XDP definitions:
  <https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_xdp.h>
- Rust `core` and `no_std` documentation:
  <https://doc.rust-lang.org/reference/names/preludes.html#the-no_std-attribute>
- Rust unsafe-code guidelines and Nomicon:
  <https://doc.rust-lang.org/nomicon/>

Every unsafe block must state its local invariants. Unsafe code is confined to
registered-memory pointer access and OS packet-ring/syscall boundaries.
