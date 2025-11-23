#  Set-Associative Cache Simulator using Python

A fully interactive **Set-Associative Cache Simulator** built using Python and Tkinter, designed for Computer Organization & Architecture (COA) learning.  
The simulator visualizes cache mapping, replacement policies, and memory access behavior in an intuitive, student-friendly interface.

---

##  Features

###  Set-Associative Cache Mapping  
- User-configurable cache size, block size, and associativity  
- Automatic calculation of number of sets  
- Real-time simulation of mapping (Set + Tag + Block)

###  Replacement Policies  
- **LRU (Least Recently Used)**  
- **FIFO (First-In-First-Out)**  
Selectable from a GUI dropdown.

###  Interactive GUI (Tkinter)  
- Manual address input (spaces or commas)  
- Color-coded output:
  -  **Green** = HIT  
  -  **Red** = MISS  
- Summary of total accesses, hits, misses, hit ratio  
- Clean theme using ttk styles

###  Cache Content Table  
Shows the final state of every set & way:
- Set number  
- Way number  
- Valid bit  
- Tag  
- Last-used timestamp  

###  Save & Reset Functions  
- Save entire output to `.txt`  
- Reset all inputs and outputs in one click  

---

##  What You Will Learn

This simulator helps students understand:

- Memory hierarchy basics  
- Cache mapping techniques  
- Set-associative cache behavior  
- Replacement algorithms  
- Effect of parameters on hit/miss ratio  

Highly useful for COA mini-projects and practical demonstrations.



