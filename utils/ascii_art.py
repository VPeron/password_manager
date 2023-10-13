import PIL.Image
import os

from utils.get_config import fetch_config

config = fetch_config(["special_chars", "asci_size", "asci_img_path"])

ASCII_CHARS = config["special_chars"]
SIZE = config["asci_size"]
IMG_PATH = config["asci_img_path"]

# resize image according to width
def resize_image(image, new_width=SIZE):
    width, height = image.size
    ratio = height / width
    new_height = int(new_width * ratio)
    resized_image = image.resize((new_width, new_height))
    return (resized_image)

# grayscale
def grayify(image):
    grayscale_image = image.convert("L")
    return (grayscale_image)

# convert pixels to ASCII chars
def pixels_to_ascii(image):
    pixels = image.getdata()
    characters = "".join([ASCII_CHARS[pixel//25] for pixel in pixels])
    return (characters)

def gen_new_ascii_art(new_width=SIZE):
    path = input("Image path:\n")
    #path = "modules/padlock.png"
    try:
        image = PIL.Image.open(path)
    except:
        print(path, "is not a valid pathname to an image.")
        return
    # chain methods
    new_image_data = pixels_to_ascii(grayify(resize_image(image)))
    # format
    pixel_count = len(new_image_data)
    ascii_img = "\n".join([new_image_data[index:(index+new_width)] for index in range(0, pixel_count, new_width)])
    # print result to terminal
    print(ascii_img)
    # specify the directory path and count files to enumerate filename
    img_dir_path = 'images'
    # get a list of all regular files in the directory
    files = [f for f in os.listdir(img_dir_path) if os.path.isfile(os.path.join(img_dir_path, f))]
    # count the number of files in the directory
    num_files = len(files)
    filename = f"ascii_image_{num_files}.txt"
    # save result to file, ### very fragile enumeration system
    with open(f"images/{filename}", "w") as f:
        f.write(ascii_img)

def get_ascii_art():
    with open(IMG_PATH) as img_obj:
        ascii_art = img_obj.read()
    print(ascii_art)
