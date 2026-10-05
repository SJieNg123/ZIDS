from src.client.io.gdfa_loader import load_gdfa
g = load_gdfa(r'.\artifacts\L8\gdfa.bin')
print(g.num_states, g.outmax, g.cell_bytes, g.row_bytes, g.num_states * g.row_bytes)
