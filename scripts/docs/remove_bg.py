from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
logo_path = ROOT / "frontend" / "public" / "argus-logo.png"

img = Image.open(logo_path).convert('RGBA')
data = np.array(img)

r, g, b, a = data[:,:,0], data[:,:,1], data[:,:,2], data[:,:,3]
# 白色及接近白色区域设为透明
white_mask = (r > 220) & (g > 220) & (b > 220)
data[white_mask, 3] = 0

result = Image.fromarray(data)
result.save(logo_path)
print('done')
