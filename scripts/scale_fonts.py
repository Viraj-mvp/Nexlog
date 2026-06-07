import os
import re
import glob

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Increase font sizes by 1.5
    def replace_font_size(match):
        current_size = int(match.group(1))
        # Keep it an integer
        new_size = int(round(current_size * 1.5))
        return f"font-size: {new_size}px;"
    
    content = re.sub(r'font-size:\s*(\d+)px;', replace_font_size, content)

    # Convert fixed size constraints to minimum constraints so layout acts fluidly
    content = content.replace("setFixedSize", "setMinimumSize")
    content = content.replace("setFixedHeight", "setMinimumHeight")
    content = content.replace("setFixedWidth", "setMinimumWidth")

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Processed {filepath}")

if __name__ == '__main__':
    gui_files = glob.glob(r"nexlog\interface\gui\*.py")
    for f in gui_files:
        process_file(f)
