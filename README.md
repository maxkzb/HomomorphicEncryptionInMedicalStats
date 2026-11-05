# Pure HE Vault: Longitudinal EHR & Medical Analytics

A secure clinical dashboard demonstrating "Data in Use" privacy through **Homomorphic Encryption (HE)**. This application was developed as a thesis project to prove that medical statistics and longitudinal patient tracking can be performed on purely encrypted ciphertext without exposing raw data to the processing server.

**Author:** Maksymilian Kozub  

---

## 🛡️ Core Architecture & Features

This application implements **Ring Learning With Errors (RLWE)** lattice cryptography via the Microsoft TenSEAL library. It eliminates the need for decrypting data during statistical analysis. 

* **Dual-Algorithm Benchmarking:** Dynamically compare execution time and accuracy between two HE schemes:
  * **CKKS (Cheon-Kim-Kim-Song):** Optimized for floating-point arithmetic and global statistical averages.
  * **BFV (Brakerski/Fan-Vercauteren):** Optimized for strict integer precision and exact categorical counting.
* **Secure Key Management:** Cryptographic Galois and Secret keys are heavily isolated in a master-password-locked SQLite database using `simple-keystore`. 
* **Longitudinal Patient Tracking:** A collapsible, hierarchical EHR interface allowing doctors to track historical patient visits without expanding cognitive load.
* **Zero-Knowledge Computation:** Calculates global health metrics (Prevalence, Average Blood Pressure, Cholesterol) entirely in the encrypted domain.
