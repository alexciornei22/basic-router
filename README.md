## CIORNEI ALEXANDRU-ȘTEFAN, 324CD

---

# Cerințe rezolvate:

### 1. Procesul de dirijare
La început se alocă memorie și se inițializează structurile
interne ale router-ului:
- Tabela de rutare implementată prin **trie**
- Tabela de intrări ARP (IP-MAC) care este inițial goală

Se primesc pachete, se verifică dacă adresa MAC de destinație
a acestora este router-ul sau *Broadcast*, apoi se verifică
protocolul pachetului (**IPv4** sau **ARP**) și se apelează
funcția corespunzătoare acelui tip de pachet: 
``handle_ip()`` sau ``handle_arp()``

### 2. Longest Prefix Match eficient
Algoritmul LPM a fost implementat folosind o structură trie
implementată în fișierele ``trie.c`` și ``trie.h``.

Pentru implementare au fost adaptate noțiunile de la:
- [geeksforgeeks](https://www.geeksforgeeks.org/trie-insert-and-search/)
- [Resursă enunț](https://www.lewuathe.com/longest-prefix-match-with-trie-tree.html)

Pentru construcția arborelui trie a fost modificată funcția ``read_rtable()`` oferită
în API-ul din schelet

### 3. Protocolul ARP
Pentru tabela ARP s-a folosit structura ``arp_entry`` din schelet.
Pe măsură ce apar rute next hop ale căror adresă MAC este necunoscută
se adaugă pachetul respectiv în coadă și se trimite un ARP request, iar
în cazul de primire pachet ARP reply se adaugă în tabelă  și se parcurge
coada de pachete pentru a le trimite pe cele pentru care s-a găsit adresa
MAC.

### 4. Protocolul ICMP
Pentru ICMP se tratează cele 3 cazuri:
- TTL exceeded
- Destination unreachable
- Router-ul este destinația

Pentru primele 2 se generează pachetul de eroare și se
trimite la sursa pachetului original, iar pentru ultimul
se generează răspuns și se trimite înapoi la sursă.
