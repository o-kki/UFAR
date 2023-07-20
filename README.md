# UBIFS-DANAWA
---
Forensic Tools : Recovering deleted data on UBIFS and removing OOB spare area in some NAND chips.

(python 3 and lzo file only.)

## 1. How to extract deleted data from Chip-off image.


- If you do not have an image file(such as chip-off memory dump file, UART memory dump file, etc.), proceed with the imaging by detaching the NAND chip from the H/W Eqip.
    - There's no single 'correct' method for generating a memory dump
    - If you're in a situation where you can't perform a memory dump, I will upload a dataset. Try with that."
- How to Code Execution
    - Input File: Memory dump file(raw file, Only 1)    
    ```python
    python main_recovery.py --file memoryfile.raw 
    ```
    - Use <b>'--meta' or '-m'</b> to search for deleted data centered on metadata.
    - Use <b>'--data' or '-d'</b> to search for deleted node data centered on data nodes.
    - Include <b>'--dumptree' or '-t'</b> to output to the UBIFS file tree structure.
    - If there are data nodes in UBIFS, they will be decompressed according to their compression type to recover deleted data.

## 2. History Logs


- We will record if the algorithm and source are modified.
    - 2023.06.05 First commit
    - 2023.07.20 Write 'README.md'
