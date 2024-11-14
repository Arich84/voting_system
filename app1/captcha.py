from PIL import Image, ImageDraw, ImageFont
import random
import string
import io

def generate_captcha_text(length=5):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def create_captcha_image(captcha_text):
    # Set up image dimensions and background color
    width, height = 80, 23
    background_color = (255, 255, 255)  # White background

    # Create an image with RGB mode
    image = Image.new('RGB', (width, height), background_color)
    draw = ImageDraw.Draw(image)

    # Set up the font for the CAPTCHA
    try:
        font = ImageFont.truetype("arial.ttf", 15)
    except IOError:
        font = ImageFont.load_default()

    # Calculate the text position using textbbox to center it
    text_bbox = draw.textbbox((0, 0), captcha_text, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]
    text_x = (width - text_width) // 2
    text_y = (height - text_height) // 2

    # Draw the CAPTCHA text on the image
    text_color = (0, 0, 0)  # Black text
    draw.text((text_x, text_y), captcha_text, fill=text_color, font=font)

    # Add noise lines or dots if desired
    for _ in range(5):
        start = (random.randint(0, width), random.randint(0, height))
        end = (random.randint(0, width), random.randint(0, height))
        draw.line([start, end], fill=(0, 0, 0), width=1)

    for _ in range(20):
        dot_position = (random.randint(0, width), random.randint(0, height))
        draw.point(dot_position, fill=(0, 0, 0))

    # Save the image to a BytesIO object
    image_bytes = io.BytesIO()
    image.save(image_bytes, format='PNG')
    image_bytes.seek(0)

    return image_bytes
