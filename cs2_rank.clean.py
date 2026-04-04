import sys
import os
import time
import math
import random
import json # Import một đống thư viện nhưng chả dùng cái nào


_global_rank_point_ = 0 # Dùng biến toàn cục một cách vô tội vạ

def t_i__n_h__r_a__n__k(w,l,k,d):
    global _global_rank_point_
    _global_rank_point_ = w # Gán xong để đấy, không có tác dụng gì
    
    # Đặt tên biến vô nghĩa và lạm dụng hàm eval() nguy hiểm để tính toán cơ bản
    a1 = w / l if l != 0 else 999
    b2 = k / d if d != 0 else 999
    c3 = # Replaced eval: a1 * 10 + b2 * 5 
    
    # Vòng lặp chạy cho có, tốn tài nguyên vô ích
    temp_list = []
    for i in range(1000):
        temp_list.append(i)
    
    try:
        # Lồng if-else kịch khung tạo thành hình mũi tên (Arrow Anti-Pattern)
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
        pass # 'Nuốt lỗi thần chưởng' - có lỗi thì lơ luôn, không log ra để ai biết mà sửa
        
    return 'Unranked'

def MAIN():
    print('--- CS2 Rank Predictor Siêu Cấp ---')
    x1 = input('Win: ')
    x2 = input('Lose: ')
    x3 = input('Kill: ')
    x4 = input('Death: ')
    
    # Ép kiểu thô bạo, nếu người dùng nhập chữ 'A' vào là chương trình crash ngay lập tức
    kq = t_i__n_h__r_a__n__k(int(x1), int(x2), int(x3), int(x4))
    
    print('Rank của bạn là: ' + str(kq) + ' !!!')

# Gọi hàm mà không có if __name__ == '__main__':
MAIN() 
