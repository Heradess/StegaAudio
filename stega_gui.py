import tkinter as tk
from tkinter import filedialog, messagebox
import wave

# Convert message to binary
def message_to_binary(message):
    return ''.join(format(ord(char), '08b') for char in message)

# Encoding
def encode_audio(input_path, message):
    audio = wave.open(input_path, mode='rb')
    frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

    # Add delimiter to end of message
    message += '###'
    binary_message = message_to_binary(message)

    if len(binary_message) > len(frame_bytes):
        messagebox.showerror("Error", "Message is too long for this audio file.")
        return

    # Modify LSB of each byte
    for i in range(len(binary_message)):
        frame_bytes[i] = (frame_bytes[i] & 254) | int(binary_message[i])

    # Save to new file
    output_path = filedialog.asksaveasfilename(defaultextension=".wav",
                                                filetypes=[("WAV files", "*.wav")],
                                                title="Save encoded audio as")
    if output_path:
        encoded_audio = wave.open(output_path, 'wb')
        encoded_audio.setparams(audio.getparams())
        encoded_audio.writeframes(frame_bytes)
        encoded_audio.close()
        messagebox.showinfo("Success", f"Message encoded and saved to:\n{output_path}")

    audio.close()

def decode_audio(input_path):
    audio = wave.open(input_path, mode='rb')
    frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

    # Extract the LSBs and build binary string
    extracted_bits = [str(byte & 1) for byte in frame_bytes]
    binary_str = ''.join(extracted_bits)

    # Convert binary to characters of 8 bits
    chars = [chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)]
    message = ''.join(chars)

    # Delimiter
    hidden_message = message.split('###')[0]
    return hidden_message


# File select
def select_file():
    global selected_file
    file_path = filedialog.askopenfilename(filetypes=[("WAV files", "*.wav")])
    if file_path:
        selected_file = file_path
        file_label.config(text=selected_file)
        encode_button.config(state=tk.NORMAL)
        decode_button.config(state=tk.NORMAL)

# Encode button
def on_decode():
    if not selected_file:
        messagebox.showwarning("Warning", "Please select a file to decode.")
        return
    hidden_message = decode_audio(selected_file)
    if hidden_message:
        messagebox.showinfo("Hidden Message", hidden_message)
    else:
        messagebox.showinfo("Result", "No hidden message found.")

# Encode click
def on_encode():
    message = message_entry.get("1.0", tk.END).strip()
    if not message:
        messagebox.showwarning("Warning", "Please enter a message to encode.")
        return
    encode_audio(selected_file, message)

# GUI
root = tk.Tk()
root.title("Audio Steganography")
root.geometry("450x400")
root.resizable(False, False)

selected_file = None

# GUI stuff
file_label = tk.Label(root, text="No file selected", wraplength=400)
file_label.pack(pady=10)

select_button = tk.Button(root, text="Select WAV File", command=select_file)
select_button.pack(pady=5)

tk.Label(root, text="Enter your secret message:").pack(pady=(15, 0))
message_entry = tk.Text(root, height=5, width=50)
message_entry.pack(pady=5)

encode_button = tk.Button(root, text="Encode Message", command=on_encode, state=tk.DISABLED)
encode_button.pack(pady=10)

decode_button = tk.Button(root, text="Decode Message", command=on_decode, state=tk.DISABLED)
decode_button.pack(pady=5)

root.mainloop()
