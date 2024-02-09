# About
This PoC first adds a new section containing machine language instructions to the target PE file. Then, it rewrites the entrypoint and patches the jump instructions, causing the instructions to execute in the new section. Finally, control of the program returns to the original point.
