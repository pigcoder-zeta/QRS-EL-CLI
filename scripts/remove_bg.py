from PIL import Image
import numpy as np

img = Image.open('frontend/public/argus-logo.png').convert('RGBA')
data = np.array(img)

r, g, b, a = data[:,:,0], data[:,:,1], data[:,:,2], data[:,:,3]
# 白色及接近白色区域设为透明
white_mask = (r > 220) & (g > 220) & (b > 220)
data[white_mask, 3] = 0

result = Image.fromarray(data)
result.save('frontend/public/argus-logo.png')
print('done')
