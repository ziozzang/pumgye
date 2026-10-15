# 비공개 SAR wire decoder

sar_wire는 서버 binary 내부의 비공개 모듈이며 명시적 default-off listener가 사용한다([서버 계약](KUBERNETES_SAR_SERVER.ko.md)). decoder 자체에는 listener/인증 기능이 없다. public API, caller 인증, listener/cluster 선택, capability, 원천수명/final transport 보장은 추가하지 않는다. pooling/keepalive/H2 방식도 결정하지 않는다. 후속 어댑터는 body 전 고정 API-server 인증/admission, 같은 current View의 mapping+grants 평가, 원래 시간·원천·publication fence를 소유해야 한다.

입력은 공백 포함32768bytes 이하, container 깊이16이하다(root=1). 원본 bytes를 한 번 읽는 visitor가 과도한 container 할당 전 깊이를 검사하며 모든 object에서 escape를 해석한 key 중복을 거부한다. 일반 Value로 먼저 파싱해 중복 key를 잃지 않는다. 잘못된 JSON/UTF8/trailing data/중복/크기·깊이 초과와 잘못된 v1/kind/spec envelope는 입력 내용을 노출하지 않는 BadRequest(후속HTTP400)다.

올바른 envelope의 미지원·unknown security 필드, 잘못된 UID/그룹/extra, 양쪽/없는 attributes와 미지원 scope는 명시적 Deny다. no-opinion이 아니다. Supported도 기존 core Principal/Attributes의 미인증 메타데이터일 뿐 권한이 아니다. metadata의 없음/{}/creationTimestamp:null 및 status의 없음/{}/allowed:false만 inert 기본값으로 허용하고 나머지는 거부한다. 입력 status를 신뢰하거나 응답에 복사하지 않는다. UID 없음과 명시적 null/빈 값은 구분하며 후자는 거부한다.

기존 core 제한을 유지한다: user/UID/그룹/extra1~256bytes/제어문자 없음, 그룹64/extra32key*8값, 중복 거부. 이름·namespace가 있는 resource get/update/patch/delete와 빈/status/scale subresource만 지원한다. selector/wildcard/create/list/watch/cluster-scoped/proxy/exec/connect/escalation은 거부한다. nonresource는 정확한 ASCII 경로/소문자 verb만 허용하며 percent/query/double-slash/dot-segment/정규화는 없다. 가짜 IP/Sum/AAL은 만들지 않는다.

고정 비공개 Allow/Deny JSON은 apiVersion/kind/status와 일관된 allowed/denied, 고정 reason만 담고 입력을 echo하지 않는다. private listener만 native capture/final owner 검사 뒤 Allow를 선택하며 public grant 생성 API는 없다. 약264bytes의 inline Decoded를 유지해 요청별 추가 Box 할당을 피하는 제한적 large-enum lint 예외만 있다. 처리량 달성 주장은 없다.

예약 데이터 fixture는 공개 Kubernetes v1 Go JSON tag에서 도출한 shape이며 실제 API-server 캡처나 Go serializer 실행 증거가 아니다. 실제 v1 서버 호환/transport/current owner gate는 후속 검증이다. 같은 core mapping/grants 연결 및 grant 철회 테스트는 caller 인증/네트워크 fullchain을 증명하지 않는다.
