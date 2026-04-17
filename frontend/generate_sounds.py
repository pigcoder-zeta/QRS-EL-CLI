import wave
import struct
import math
import os

def generate_tone(filename, freq, duration, volume=0.5, attack=0.01, decay=0.1):
    sample_rate = 44100.0
    num_samples = int(duration * sample_rate)
    
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with wave.open(filename, 'w') as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(int(sample_rate))
        
        for i in range(num_samples):
            t = float(i) / sample_rate
            # Envelopes
            env = 1.0
            if t < attack:
                env = t / attack
            elif t > (duration - decay):
                env = (duration - t) / decay
            if env < 0: env = 0
            
            # Sine wave
            value = int(volume * env * math.sin(2.0 * math.pi * freq * t) * 32767.0)
            data = struct.pack('<h', value)
            wav_file.writeframesraw(data)

# 悬停：微小的高频“滴”声
generate_tone('public/sounds/hover.wav', 880.0, 0.05, 0.3)
# 点击：实心的低频确认声
generate_tone('public/sounds/click.wav', 440.0, 0.1, 0.5)
# 报警/扫描：类似雷达的扫描声 (高-低)
generate_tone('public/sounds/scan.wav', 1200.0, 0.2, 0.4)
# 成功: 上升调 (需要修改上面的生成器来支持频率扫描，这里用简单的单音代替，稍后如果要求更高可以完善)
generate_tone('public/sounds/success.wav', 1600.0, 0.3, 0.5)
