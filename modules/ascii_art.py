import PIL.Image



# ascii pool in descending order of intensity
ASCII_CHARS = ["@", "#", "S", "%", "?", "*", "+", ";", ":", ",", "."]
SIZE = 25

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

def get_new_ascii_art(new_width=SIZE):
    # path = input("Image path:\n")
    path = "modules/padlock.png"
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
    # save result to file
    with open("modules/ascii_image.txt", "w") as f:
        f.write(ascii_img)

def get_ascii_art():
    with open('modules/ascii_image.txt') as img_obj:
        ascii_art = img_obj.read()
    print(ascii_art)
