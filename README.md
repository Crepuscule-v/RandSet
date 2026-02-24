# RandSet

RandSet is a randomized corpus reduction technique for coverage-guided fuzzing. It reduces corpus size and yields diverse seed selection simultaneously, with minimal runtime overhead suited for high-frequency seed scheduling. 

RandSet introduces randomness into corpus reduction by formulating it as a classic **set cover problem**. It computes a subset of the seed corpus via randomized algorithm as a set cover to cover all features of the entire corpus. Seeds are then scheduled from this small, randomized subset rather than the full corpus, effectively mitigating seed explosion while maintaining diversity.

This project has been accepted at OOPSLA'26. Checkout our paper for more technical details about the project.

## Repository Structure

RandSet is implemented on top of three popular fuzzing frameworks:

| Directory | Framework
|-----------|-----------|
| `randset_aflpp/` | [AFL++](https://github.com/AFLplusplus/AFLplusplus)
| `randset_libafl/` | [LibAFL](https://github.com/AFLSec/LibAFL) 
| `randset_centipede/` | [Centipede](https://github.com/google/fuzztest)

## Cite
