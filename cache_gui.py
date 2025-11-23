import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk

# ---------- Globals for saving last result ---------- #
last_save_text = ""  # plain text to save to file


# ---------- Cache Simulation Logic ---------- #
def run_cache_sim(cache_size, block_size, associativity, addresses, policy):
    """
    Runs set-associative cache simulation with LRU or FIFO policy.
    Returns:
      steps: list of {addr, set_index, tag, hit}
      cache_state: 2D list [set][way] -> dict(valid, tag, last_used)
      stats: dict with totals and ratios
    """
    num_sets = cache_size // (block_size * associativity)
    if num_sets <= 0:
        raise ValueError("Number of sets must be > 0. Check parameters.")

    # cache[set_index][way] = {valid, tag, last_used}
    cache = [
        [
            {"valid": False, "tag": None, "last_used": -1}
            for _ in range(associativity)
        ]
        for _ in range(num_sets)
    ]

    time = 0
    hits = 0
    misses = 0
    steps = []

    policy = policy.upper()

    for addr in addresses:
        time += 1
        block = addr // block_size
        set_index = block % num_sets
        tag = block // num_sets

        cache_set = cache[set_index]
        hit = False

        # Check hit
        for line in cache_set:
            if line["valid"] and line["tag"] == tag:
                hit = True
                hits += 1
                if policy == "LRU":
                    line["last_used"] = time  # only LRU updates on hit
                break

        # On miss
        if not hit:
            misses += 1
            empty_line = None
            for line in cache_set:
                if not line["valid"]:
                    empty_line = line
                    break

            if empty_line is not None:
                victim = empty_line
            else:
                # FIFO and LRU both choose smallest last_used,
                # difference is when last_used gets updated.
                victim = min(cache_set, key=lambda x: x["last_used"])

            victim["valid"] = True
            victim["tag"] = tag
            victim["last_used"] = time  # insertion time (used by both policies)

        steps.append(
            {
                "addr": addr,
                "set_index": set_index,
                "tag": tag,
                "hit": hit,
            }
        )

    total = hits + misses
    stats = {
        "total": total,
        "hits": hits,
        "misses": misses,
        "hit_ratio": hits / total if total else 0.0,
        "miss_ratio": misses / total if total else 0.0,
        "num_sets": num_sets,
        "associativity": associativity,
    }

    return steps, cache, stats


# ---------- GUI Callbacks ---------- #
def run_simulation():
    global last_save_text
    try:
        cache_size = int(cache_entry.get())
        block_size = int(block_entry.get())
        associativity = int(assoc_entry.get())
        policy = policy_combo.get().strip() or "LRU"

        raw = address_entry.get().strip()
        if not raw:
            messagebox.showerror("Error", "Please enter memory addresses.")
            return

        # parse addresses: allow spaces and commas
        parts = raw.replace(",", " ").split()
        addresses = [int(p) for p in parts]

        # run simulation
        steps, cache_state, stats = run_cache_sim(
            cache_size, block_size, associativity, addresses, policy
        )

        # clear previous outputs
        output_box.config(state="normal")
        output_box.delete("1.0", tk.END)

        # colored HIT/MISS lines + build text for saving
        lines_for_save = []
        for step in steps:
            line_text = (
                f"Address {step['addr']} -> "
                f"Set {step['set_index']}, Tag {step['tag']}: "
                f"{'HIT' if step['hit'] else 'MISS'}\n"
            )
            tag_name = "hit" if step["hit"] else "miss"
            output_box.insert(tk.END, line_text, tag_name)
            lines_for_save.append(line_text.rstrip("\n"))

        # summary
        summary = (
            "\n--- Summary ---\n"
            f"Total Accesses : {stats['total']}\n"
            f"Hits           : {stats['hits']}\n"
            f"Misses         : {stats['misses']}\n"
            f"Hit Ratio      : {stats['hit_ratio']:.3f}\n"
            f"Miss Ratio     : {stats['miss_ratio']:.3f}\n"
            f"Policy         : {policy.upper()}\n"
        )
        output_box.insert(tk.END, summary, "summary")
        output_box.config(state="disabled")

        lines_for_save.append("")
        lines_for_save.append("--- Summary ---")
        lines_for_save.append(f"Total Accesses : {stats['total']}")
        lines_for_save.append(f"Hits           : {stats['hits']}")
        lines_for_save.append(f"Misses         : {stats['misses']}")
        lines_for_save.append(f"Hit Ratio      : {stats['hit_ratio']:.3f}")
        lines_for_save.append(f"Miss Ratio     : {stats['miss_ratio']:.3f}")
        lines_for_save.append(f"Policy         : {policy.upper()}")

        # populate cache table
        populate_cache_table(cache_state)

        # also add cache contents to save-text
        cache_text_lines = cache_state_to_text(cache_state)
        lines_for_save.append("")
        lines_for_save.append("--- Final Cache Contents ---")
        lines_for_save.extend(cache_text_lines)

        last_save_text = "\n".join(lines_for_save)

    except ValueError:
        messagebox.showerror("Error", "Please enter valid integers in all fields.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def populate_cache_table(cache_state):
    # clear old content
    for row in cache_table.get_children():
        cache_table.delete(row)

    for set_index, cache_set in enumerate(cache_state):
        for way_index, line in enumerate(cache_set):
            valid = 1 if line["valid"] else 0
            tag = "-" if line["tag"] is None else str(line["tag"])
            last_used = "-" if line["last_used"] == -1 else str(line["last_used"])
            cache_table.insert(
                "",
                tk.END,
                values=(set_index, way_index, valid, tag, last_used),
            )


def cache_state_to_text(cache_state):
    lines = ["Set  Way  Valid  Tag  LastUsed"]
    for set_index, cache_set in enumerate(cache_state):
        for way_index, line in enumerate(cache_set):
            valid = 1 if line["valid"] else 0
            tag = "-" if line["tag"] is None else str(line["tag"])
            last_used = "-" if line["last_used"] == -1 else str(line["last_used"])
            lines.append(
                f"{set_index:3}  {way_index:3}   {valid:5}  {tag:3}  {last_used}"
            )
    return lines


def save_output():
    if not last_save_text:
        messagebox.showinfo("Info", "No simulation result to save yet.")
        return

    filename = filedialog.asksaveasfilename(
        title="Save Output As",
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
    )
    if not filename:
        return

    try:
        with open(filename, "w") as f:
            f.write(last_save_text)
        messagebox.showinfo("Saved", f"Output saved to:\n{filename}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not save file:\n{e}")


def reset_all():
    global last_save_text
    last_save_text = ""
    cache_entry.delete(0, tk.END)
    block_entry.delete(0, tk.END)
    assoc_entry.delete(0, tk.END)
    address_entry.delete(0, tk.END)
    policy_combo.set("LRU")

    output_box.config(state="normal")
    output_box.delete("1.0", tk.END)
    output_box.config(state="disabled")

    for row in cache_table.get_children():
        cache_table.delete(row)


# ---------- Create GUI ---------- #
root = tk.Tk()
root.title("Set-Associative Cache Simulator (Advanced)")

# nicer default font
root.option_add("*Font", ("Segoe UI", 10))

style = ttk.Style()
# 'clam' is usually nicer than default on Windows
try:
    style.theme_use("clam")
except:
    pass

main_frame = ttk.Frame(root, padding=10)
main_frame.grid(row=0, column=0, sticky="nsew")

root.rowconfigure(0, weight=1)
root.columnconfigure(0, weight=1)

# --- Top: parameters --- #
params_frame = ttk.LabelFrame(main_frame, text="Cache Parameters", padding=10)
params_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
params_frame.columnconfigure(1, weight=1)

ttk.Label(params_frame, text="Cache Size (bytes):").grid(row=0, column=0, sticky="w")
cache_entry = ttk.Entry(params_frame, width=15)
cache_entry.grid(row=0, column=1, sticky="w", padx=5)

ttk.Label(params_frame, text="Block Size (bytes):").grid(row=1, column=0, sticky="w")
block_entry = ttk.Entry(params_frame, width=15)
block_entry.grid(row=1, column=1, sticky="w", padx=5)

ttk.Label(params_frame, text="Associativity (ways):").grid(row=2, column=0, sticky="w")
assoc_entry = ttk.Entry(params_frame, width=15)
assoc_entry.grid(row=2, column=1, sticky="w", padx=5)

ttk.Label(params_frame, text="Replacement Policy:").grid(
    row=0, column=2, sticky="w", padx=(20, 0)
)
policy_combo = ttk.Combobox(params_frame, values=["LRU", "FIFO"], width=10, state="readonly")
policy_combo.grid(row=0, column=3, sticky="w")
policy_combo.set("LRU")

# --- Middle: address input + buttons --- #
input_frame = ttk.LabelFrame(main_frame, text="Memory Access Pattern", padding=10)
input_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))
input_frame.columnconfigure(1, weight=1)

ttk.Label(input_frame, text="Enter Addresses:").grid(row=0, column=0, sticky="nw")
address_entry = ttk.Entry(input_frame)
address_entry.grid(row=0, column=1, sticky="ew", padx=5)
ttk.Label(
    input_frame,
    text="Example: 0 8 16 0 24 8 (spaces or commas allowed)",
    foreground="gray",
).grid(row=1, column=1, sticky="w", pady=(2, 0))

buttons_frame = ttk.Frame(input_frame)
buttons_frame.grid(row=0, column=2, rowspan=2, padx=(10, 0))

run_button = ttk.Button(buttons_frame, text="Run Simulation", command=run_simulation)
run_button.grid(row=0, column=0, pady=2, sticky="ew")

save_button = ttk.Button(buttons_frame, text="Save Output", command=save_output)
save_button.grid(row=1, column=0, pady=2, sticky="ew")

reset_button = ttk.Button(buttons_frame, text="Reset", command=reset_all)
reset_button.grid(row=2, column=0, pady=2, sticky="ew")

# --- Bottom: output + cache table --- #
output_frame = ttk.LabelFrame(main_frame, text="Simulation Output", padding=10)
output_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
main_frame.rowconfigure(2, weight=1)

output_box = tk.Text(output_frame, width=60, height=20, wrap="none")
output_box.grid(row=0, column=0, sticky="nsew")
output_frame.rowconfigure(0, weight=1)
output_frame.columnconfigure(0, weight=1)

# scrollbars for output
out_scroll_y = ttk.Scrollbar(output_frame, orient="vertical", command=output_box.yview)
out_scroll_y.grid(row=0, column=1, sticky="ns")
output_box.config(yscrollcommand=out_scroll_y.set)

out_scroll_x = ttk.Scrollbar(output_frame, orient="horizontal", command=output_box.xview)
out_scroll_x.grid(row=1, column=0, sticky="ew")
output_box.config(xscrollcommand=out_scroll_x.set)

# color tags
output_box.tag_configure("hit", foreground="green")
output_box.tag_configure("miss", foreground="red")
output_box.tag_configure("summary", font=("Segoe UI", 10, "bold"))
output_box.config(state="disabled")

# cache table
table_frame = ttk.LabelFrame(main_frame, text="Final Cache Contents", padding=10)
table_frame.grid(row=2, column=1, sticky="nsew", pady=(0, 10), padx=(10, 0))
main_frame.columnconfigure(0, weight=1)
main_frame.columnconfigure(1, weight=1)

columns = ("set", "way", "valid", "tag", "last_used")
cache_table = ttk.Treeview(
    table_frame,
    columns=columns,
    show="headings",
    height=20,
)
for col in columns:
    cache_table.heading(col, text=col.title())
    cache_table.column(col, width=70, anchor="center")

cache_table.grid(row=0, column=0, sticky="nsew")
table_frame.rowconfigure(0, weight=1)
table_frame.columnconfigure(0, weight=1)

table_scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=cache_table.yview)
table_scroll_y.grid(row=0, column=1, sticky="ns")
cache_table.config(yscrollcommand=table_scroll_y.set)

root.mainloop()
