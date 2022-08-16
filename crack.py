#!/usr/bin/env python3
# coding:utf8
import time
import argparse
import atexit
from utils import *
from cracker import *
import multiprocessing

debut = time.time()


def display_name():
    print("Durée : " + str(time.time() - debut))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Cracker")
    parser.add_argument("-f",
                        "--file",
                        dest="file",
                        help="Path of dictionnary file",
                        required=False)
    parser.add_argument("-g",
                        "--gen",
                        dest="gen",
                        help="Generate MD5 hash of password",
                        required=False)
    parser.add_argument("-md5",
                        dest="md5",
                        help="Hashed password (MD5)",
                        required=False)
    parser.add_argument("-l",
                        dest="plength",
                        help="Password length",
                        required=False,
                        type=int)

    parser.add_argument("-o",
                        dest="online",
                        help="Cherche le hash en ligne (google)",
                        required=False,
                        action="store_true")

    parser.add_argument(
        "-p",
        dest="pattern",
        help="Utilise le motif de mot de passe (^=MAJ, *=MIN, ²=CHIFFRES)")

    args = parser.parse_args()

    processes = []
    work_queue = multiprocessing.Queue()
    done_queue = multiprocessing.Queue()
    cracker = Cracker()

    atexit.register(display_name)

    if args.md5:
        print("[+] CRACKING HASH " + args.md5 + "]")
        if args.file:
            print("[USIN G DICTIONNARY FILE " + args.file + "]")
            p1 = multiprocessing.Process(target=Cracker.work,
                                         args=(work_queue, done_queue,
                                               args.md5, args.file, False))
            work_queue.put(cracker)
            p1.start()

            p2 = multiprocessing.Process(target=Cracker.work,
                                         args=(work_queue, done_queue,
                                               args.md5, args.file, True))

            work_queue.put(cracker)
            p2.start()

            not_found = 0
            while True:
                data = done_queue.get()
                if data == "Found" or data == "Not Found":
                    p1.kill()
                    p2.kill()
                    break

            #Cracker.crack_dict(args.md5, args.file)
        elif args.plength:
            print("[USING INCREMENTAL MODE FOR " + str(args.plength) +
                  " letter(s)]")
            Cracker.crack_incr(args.md5, args.plength)
        elif args.online:
            print("[*] USING MODE ONLINE")
            Cracker.crack_online(args.md5)
        elif args.pattern:
            print("[*] UTILISANT LE MODELE DE MOT DE PASSE : " + args.pattern)
            Cracker.crack_smart(args.md5, args.pattern)
        else:
            print(Color.ORANGE + "[?] Please choose either -f or -l argument" +
                  Color.END)
    else:
        print("[*] MD5 hash not provided")

    if args.gen:
        print("[*] MD5 HASH OF " + args.gen + " : " +
              hashlib.md5(args.gen.encode("utf8")).hexdigest())
