bộ theo dõi mạng

zeek
	-> ghi lại những gì xảy ra trên mạng
		ai kết nối với ai
		thời gian nào
		port nào
		gửi bao nhiêu dữ liệu
		domain nào
		
suricata
	-> cố phát hiện chuyện nguy hiểm và phát chuông báo động
	xem xét các traffic giống malware
	exploit signature
	suspicious payload
	known malicious pattern
			
pcap_ring
	-> ghi lại traffic mạng thô ghi đè dữ liệu trong 15p gần nhất
    
Zeek có thể monitor live interface liên tục và tự tạo conn.log, HTTP log, DNS-related logs...

vậy thì vẫn phải có 1 chương trình chạy nền thu thập các thông tin network từ các tool này theo định kỳ thời gian và gửi cho server

