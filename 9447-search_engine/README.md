# Search Engine

사실 바이너리 분석할 땐 취약점은 못찾았음 ㅠ 문장 split 때문에 릭 날수도 있겠구나 정도는 알아챔.

프로그램 파싱 제대로 되었는지 파이썬 코딩하면서 암거나 넣었는데 double free 나서 이부분 이상하구나.. 하고 그부분 파고 들어감

double free 가 나는 부분은 1번 선택하고 문장 찾아서 지우는 부분. 이 프로그램이 전체적 구조가 어떤 40bytes 짜리 구조체로 단어와 문장 관리하는데 문장 지우려고 free하고 나서 이 구조체에 있는 주소를 안지워서 uaf와 double free bug가 남. 


## round 1 

"A" + " " + "A"*254를 할당하고 delete한 후 "f"를 할당하면 이전 문장이 free된 곳에 문장이 할당 된다. 이때 "f"를 다시 검색하면 해당 단어가 포함된 문장을 프린트 해주기 때문에 small bin을 free했기 때문에 남아있는 main_arena + 88의 주소를 얻을 수 있다.

"f" 처럼 1글자를 할당하는게 중요하다. 왜냐면 단어 검색하는 루틴에서 단어의 길이를 체크하기 때문이다.

## round 2

문장 3개를 alloc 한 후 지우면 해당 문장들이 포함된 힙 청크의 fd에 주소들(fast bin list)이 남는다. 원래는 이 주소들이 c->b->a 이런 순으로 가장 마지막에 free된 애가 head에 있고 연결되어 있지만, 해당 주소를 gdb로 파악한 후 한바이트 search 해서 다시 delete할 수 있다. (double free bug) 그럼 c->b->c->b... 이런 식으로 fastbin list 가 바뀌게 되고 malloc 으로 같은 청크를 두번 할당 받을 수 있게 된다! 

이것을 __malloc_hook 근처에 재할당 해서 그 함수를 one_gadget 으로 덮어버린다.


