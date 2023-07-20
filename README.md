# UBIFS-DANAWA
---
Forensic Tools : Recovering deleted data on UBIFS and removing OOB spare area in some NAND chips.

(Note: The tool only supports Python 3 and lzo files.)

## 1. How to extract deleted data from a Chip-off image on UBIFS.


- If you don't have an image file (like a chip-off memory dump file, UART memory dump file, etc.), start by detaching the NAND chip from the hardware equipment and proceed with imaging. 
  - Remember, there's no single 'correct' way to generate a memory dump.
  - In case you find yourself unable to perform a memory dump, a dataset will be provided. Give it a try.
- How to Execute the Code
  - The input file should be a memory dump file (raw file, and only one file at a time).
  ```python
  python main_recovery.py --file memoryfile.raw 
  ```
  - Here are some options you can use with the command:
    - Use <b>'--meta' or '-m'</b> to search for deleted data centered on metadata.
    - Use <b>'--data' or '-d'</b> to search for deleted node data centered on data nodes.
    - Include <b>'--dumptree' or '-t'</b> to output to the UBIFS file tree structure.
  - If UBIFS contains data nodes, they will be decompressed according to their compression type to recover deleted data.

## 2. History Logs


- We will document and modifications made to the algorithm or source code.
    - 2023.06.05 First commit
    - 2023.07.20 Write 'README.md'
