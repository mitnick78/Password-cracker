import string
import sys
import hashlib
import urllib.request
import urllib.response
import urllib.error
from utils import *


class Cracker:

    @staticmethod
    def crack_dict(md5, file, order, done_queue):
        """
      Casse un HASH MD5 (md5) via une liste de mot-clés (file)

      Arguments:
          md5 --  Hash MD5 à casser
          file -- _FIchier de mots-clés à utiliser
      """
        try:
            search = False
            openFile = open(file, "r")

            if Order.TOP == order:
                content = reversed(list(openFile.readlines()))
            else:
                content = openFile.readlines()
            for word in content:
                word = word.strip("\n")
                hashMd5 = hashlib.md5(word.encode("utf8")).hexdigest()
                if hashMd5 == md5:
                    print(Color.GREEN + "[+] Mot de passe trouvé : " +
                          str(word) + " (" + hashMd5 + ")" + Color.END)
                    search = True
                    done_queue.put("Found")
                    break
            if not search:
                print(Color.RED + "[-] Mot de passe non trouvé !" + Color.END)
                done_queue.put("Not Found")
                openFile.close()

        except FileNotFoundError:
            print(Color.RED +
                  "[-] Erreur : nom du fichier ou fichier introuvable !" +
                  Color.END)
            sys.exit(1)
        except Exception as err:
            print(Color.RED + "[-] Erreur : " + str(err) + Color.END)
            sys.exit(2)

    @staticmethod
    def crack_incr(md5, length, currentPassword=[]):
        """
      Casse un HASH MD5 VIa une méthode incrémentale pour un mdp de longeur lenght

      Arguments:
          md5 -- Le HASH md5 à casser
          length -- La longeur du mot de passe à trouver

      Keyword Arguments:
          currentPassword -- liste temporaire automatiquement utilisée via recursion contenent l'essaidu mdp actuel
      """

        letters = string.printable

        if length >= 1:
            if len(currentPassword) == 0:
                currentPassword = ['a' for _ in range(length)]
                Cracker.crack_incr(md5, length, currentPassword)
            else:
                for c in letters:
                    currentPassword[length - 1] = c

                    currentHash = hashlib.md5(
                        "".join(currentPassword).encode("utf8")).hexdigest()
                    print("trying : " + "".join(currentPassword) + " (" +
                          currentHash + ")")
                    if currentHash == md5:
                        print(Color.GREEN + "[+] Password found ! " +
                              "".join(currentPassword) + Color.END)
                        sys.exit(0)
                    else:
                        Cracker.crack_incr(md5, length - 1, currentPassword)

    @staticmethod
    def crack_online(md5):
        """
      Cherche un HASH MD5 via google.fr

      Arguments:
          md5 -- Hash md5 à utiliser pour la recherche en ligne 
      """
        try:
            user_agent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; fr-FR; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7"
            headers = {'User-Agent': user_agent}
            url = "http://www.google.fr/search?hl=fr&q=" + md5
            req = urllib.request.Request(url, None, headers)
            response = urllib.request.urlopen(req)

        except urllib.error.HTTPError as e:
            print(Color.RED + "Erreur HTTP : " + e.code + Color.end)
        except urllib.error.URLError as e:
            print(Color.RED + "Erreur D'URL : " + e.reason + Color.end)

        if "Aucun document" in response.read().decode("utf8"):
            print(Color.RED + "[-] HASH NOT FOUND WITH GOOGLE" + Color.END)
        else:
            print(Color.GREEN + "[+] PASSWORD FOUND WITH GOOGLE : " + url +
                  Color.END)

    @staticmethod
    def crack_smart(md5, pattern, _index=0):
        """
        :param md5:
        :param pattern:
        :param _index:
        :return:
        """
        MAJ = string.ascii_uppercase
        CHIFFRES = string.digits
        MIN = string.ascii_lowercase

        if _index < len(pattern):
            if pattern[_index] in MAJ + CHIFFRES + MIN:
                Cracker.crack_smart(md5, pattern, _index + 1)
            if "^" == pattern[_index]:
                for c in MAJ:
                    p = pattern.replace("^", c, 1)
                    currhash = hashlib.md5(p.encode("utf8")).hexdigest()
                    if currhash == md5:
                        print(Color.GREEN + "[+] PASSWORD FOUND : " + p +
                              Color.END)
                        sys.exit(0)
                    print("[*] TEST DE : " + p + " (" + currhash + ")")
                    Cracker.crack_smart(md5, p, _index + 1)

            if "*" == pattern[_index]:
                for c in MIN:
                    p = pattern.replace("*", c, 1)
                    currhash = hashlib.md5(p.encode("utf8")).hexdigest()
                    if currhash == md5:
                        print(Color.GREEN + "[+] PASSWORD FOUND : " + p +
                              Color.END)
                        sys.exit(0)
                    print("[*] TEST DE : " + p + " (" + currhash + ")")
                    Cracker.crack_smart(md5, p, _index + 1)

            if "²" == pattern[_index]:
                for c in CHIFFRES:
                    p = pattern.replace("²", c, 1)
                    currhash = hashlib.md5(p.encode("utf8")).hexdigest()
                    if currhash == md5:
                        print(Color.GREEN + "[+] PASSWORD FOUND : " + p +
                              Color.END)
                        sys.exit(0)
                    print("[*] TEST OF : " + p + " (" + currhash + ")")
                    Cracker.crack_smart(md5, p, _index + 1)
        else:
            return

    @staticmethod
    def work(work_queue, done_queue, md5, file, order):
        o = work_queue.get()
        o.crack_dict(md5, file, order, done_queue)
