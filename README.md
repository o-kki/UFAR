## UFAR: Ubifs Forensic Analysis and Recovery 
---
Forensic Tools : Recovering deleted data on UBIFS and removing OOB spare area in some NAND chips.

(Note: The tool only supports Python 3 and lzo files.)
### 1. Contribution

Until now, there have been tools available for analyzing UBIFS file system(like ubidump, ubi reader, etc), but none specifically designed to recover deleted data by analyzing the internal structure of UBIFS.
Our tool fills this gap, this can do this!

### 2. How to extract deleted data from a Chip-off image on UBIFS.


- If you don't have an image file (like a chip-off memory dump file, UART memory dump file, etc.), start by detaching the NAND chip from the hardware equipment and proceed with imaging. 
  - Remember, there's no single 'correct' way to generate a memory dump.
  - In case you find yourself unable to perform a memory dump, a dataset will be provided. Give it a try.
- How to Execute the Code
  - The input file should be a memory dump file (raw file, and only one file at a time).
  ```python
  python main_recovery.py --file {Flash Memory Image file} {-m or -c or -t}
  ```
  - Here are some options you can use with the command:
    - Use <b>'--meta' or '-m'</b> to search for deleted files by metadata data.
    - Use <b>'--combination' or '-c'</b> to change the full dump image file to UART format.
    <!-- - Use <b>'--data' or '-d'</b> to search for deleted files by node data by data nodes.-->
    - Include <b>'--dumptree' or '-t'</b> to output to the UBIFS file tree structure.
  - If UBIFS contains data nodes, they will be decompressed according to their compression type to recover deleted data.

### 3. History Logs


- We will document and modifications made to the algorithm or source code.
    - 2023.06.05 First commit
    - 2023.07.20 Write 'README.md'
    - 2023.09.27 Modify dump tree related code
    - 2023.09.30 Modify feature about change image format

### 4. REF
- Sample Image 1: https://works.do/FzOK0et
- Sample Image 2: https://works.do/xRI57uu
