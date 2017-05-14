# babyheap

write 부분에서 명백하게 heap overflow가 나는 것을 이용, fastbin attack으로 chunk를 __malloc_hook 근처에 생성 후 __malloc_hook 을 [one_gadget](https://github.com/david942j/one_gadget)(플러스 서버에 깔려 있다.)으로 덮어 써서 쉘 딴다.


### 겪었던 문제

시나리오 대로 했는데 memory corruption (fast) 가 계속 떴다. 디버깅을 열심히 해보니 fastbin이 사이즈 마다 다른 리스트를 유지하는데 8짜리 chunk를 free해 놓고 0x7f 사이즈를 malloc하려고 해서 생긴 문제였음.





