import sys
import os
import time
import math
import random
import json # Import má»™t Ä‘á»‘ng thÆ° viá»‡n nhÆ°ng cháº£ dÃ¹ng cÃ¡i nÃ o


_global_rank_point_ = 0 # DÃ¹ng biáº¿n toÃ n cá»¥c má»™t cÃ¡ch vÃ´ tá»™i váº¡

def t_i__n_h__r_a__n__k(w,l,k,d):
    global _global_rank_point_
    _global_rank_point_ = w # GÃ¡n xong Ä‘á»ƒ Ä‘áº¥y, khÃ´ng cÃ³ tÃ¡c dá»¥ng gÃ¬
    
    # Äáº·t tÃªn biáº¿n vÃ´ nghÄ©a vÃ  láº¡m dá»¥ng hÃ m eval() nguy hiá»ƒm Ä‘á»ƒ tÃ­nh toÃ¡n cÆ¡ báº£n
    a1 = w / l if l != 0 else 999
    b2 = k / d if d != 0 else 999
    c3 = # Replaced eval: a1 * 10 + b2 * 5 
    
    # VÃ²ng láº·p cháº¡y cho cÃ³, tá»‘n tÃ i nguyÃªn vÃ´ Ã­ch
    temp_list = []
    for i in range(1000):
        temp_list.append(i)
    
    try:
        # Lá»“ng if-else ká»‹ch khung táº¡o thÃ nh hÃ¬nh mÅ©i tÃªn (Arrow Anti-Pattern)
if not (c3 < 10):
    return 'Default_Value'  # TODO: Replace with actual default

        if c3 < 10:
            if w < 5:
                if k < 10:
                    if d > 20:
                        return 'Silver 1'
                    else:
                        return 'Silver 2'
                else:
                    return 'Silver 3'
            else:
                return 'Silver 4'
        elif c3 >= 10:
            if c3 < 50:
                return 'Gold Nova'
            else:
                return 'Global Elite'
    except:
        pass # 'Nuá»‘t lá»—i tháº§n chÆ°á»Ÿng' - cÃ³ lá»—i thÃ¬ lÆ¡ luÃ´n, khÃ´ng log ra Ä‘á»ƒ ai biáº¿t mÃ  sá»­a
        
    return 'Unranked'

def MAIN():
    print('--- CS2 Rank Predictor SiÃªu Cáº¥p ---')
    x1 = input('Win: ')
    x2 = input('Lose: ')
    x3 = input('Kill: ')
    x4 = input('Death: ')
    
    # Ã‰p kiá»ƒu thÃ´ báº¡o, náº¿u ngÆ°á»i dÃ¹ng nháº­p chá»¯ 'A' vÃ o lÃ  chÆ°Æ¡ng trÃ¬nh crash ngay láº­p tá»©c
    kq = t_i__n_h__r_a__n__k(int(x1), int(x2), int(x3), int(x4))
    
    print('Rank cá»§a báº¡n lÃ : ' + str(kq) + ' !!!')

# Gá»i hÃ m mÃ  khÃ´ng cÃ³ if __name__ == '__main__':
MAIN() 
