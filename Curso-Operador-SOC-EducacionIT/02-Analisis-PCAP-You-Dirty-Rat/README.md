# Análisis de tráfico de red: You Dirty Rat

## Información general

- **Actividad:** Análisis de una captura de red
- **Curso:** Operador SOC
- **Herramienta principal:** Wireshark
- **Periodo del análisis:** 03/08/2026 al 14/08/2026
- **Analista:** Franco Zelaya

## Resumen ejecutivo

Se analizó una captura de red correspondiente al equipo `DESKTOP-SKBR25F`, con dirección IP `172.16.1.66`, utilizado por Clark Collier (`ccollier`). La actividad principal comenzó menos de un minuto después del inicio de sesión y mostró accesos consecutivos a GitHub, GitHub Objects y el repositorio Maven. Las comunicaciones con GitHub Objects y Maven generaron transferencias entrantes aproximadas de 833 kB y 8,89 MB, respectivamente. Posteriormente, el host consultó `ip-api.com/json/`, obteniendo información sobre su dirección IP pública, ubicación, proveedor y ASN. No se observó un patrón periódico compatible con beaconing clásico, pero la secuencia puede representar descarga de contenido y reconocimiento del entorno. Debido al cifrado TLS, no fue posible identificar directamente los archivos transferidos ni confirmar ejecución de malware, persistencia o exfiltración. El incidente se clasificó con severidad **High** y se recomendó aislar el endpoint, preservar la evidencia y escalar el caso a SOC Nivel 2 y Respuesta a Incidentes.

## Adquisición e integridad de la evidencia

La captura de red fue obtenida desde Malware-Traffic-Analysis.net para realizar el ejercicio denominado "You Dirty Rat". Antes de iniciar el análisis se verificó el tamaño y la integridad del archivo comprimido y del archivo PCAP.

| Propiedad | Valor |
|---|---|
| Archivo comprimido | `2024-07-30-traffic-analysis-exercise.pcap.zip` |
| Tamaño del ZIP | `10.750.172 bytes` |
| SHA-256 del ZIP | `420530CEFB5F0001E12AACC554CEF14F6273F1E2EC01008567A68F3471E0ED70` |
| Archivo analizado | `2024-07-30-traffic-analysis-exercise.pcap` |
| Fuente | [Malware-Traffic-Analysis.net - You Dirty Rat](https://www.malware-traffic-analysis.net/2024/07/30/index.html) |
| Tamaño del PCAP | `11.526.388 bytes` |
| SHA-256 del PCAP | `C48854C24223CF7B4E9880EA72A21A877E4138E4CE36DF7B7656E5C6C4043F68` |

## Propiedades de la captura

La evidencia contiene tráfico de red encapsulado en Ethernet. La captura abarca aproximadamente 9 minutos y 45 segundos y contiene un total de 11.562 paquetes.

| Propiedad | Valor |
|---|---|
| Primer paquete | `2024-07-29 23:38:48` |
| Último paquete | `2024-07-29 23:48:34` |
| Duración | `585,662 segundos` |
| Paquetes capturados | `11.562` |
| Promedio de paquetes | `19,7 paquetes/s` |
| Tamaño promedio | `981 bytes` |
| Bytes capturados | `11.341.372` |
| Encapsulación | `Ethernet` |
| Evidencia | `capturas/01-propiedades-captura.png` |

La captura fue cargada completamente en Wireshark, sin filtros de visualización aplicados y con el 100 % de los paquetes disponibles.

## Registro del análisis

### 1. Identificación de hosts principales

Mediante `Statistics > Conversations > IPv4`, se ordenaron las conversaciones por cantidad de bytes. La dirección interna `172.16.1.66` concentra las comunicaciones de mayor volumen y aparece conectada con una gran cantidad de direcciones externas, por lo que se la identifica provisionalmente como el host principal involucrado.

La conversación de mayor volumen se produjo entre `172.16.1.66` y `199.232.196.209`, con 6.540 paquetes y aproximadamente 8.894 kB transferidos. La mayor parte de los datos se desplazó desde la dirección externa hacia el host interno, lo que sugiere una descarga o transferencia entrante.

| Prioridad por volumen | IP externa | Paquetes | Bytes aproximados | Observación inicial |
|---:|---|---:|---:|---|
| 1 | `199.232.196.209` | 6.540 | 8.894 kB | Transferencia principalmente entrante |
| 2 | `185.199.110.133` | 653 | 833 kB | Transferencia principalmente entrante |
| 3 | `23.198.7.175` | 189 | 128 kB | Requiere correlación con otros protocolos |

También se observó comunicación entre `172.16.1.66` y `172.16.1.4`. Esta última dirección corresponde al controlador de dominio del escenario, por lo que se considera tráfico interno y no una IP externa.

En esta etapa las direcciones se priorizan por volumen, pero no se clasifican todavía como maliciosas. Su valoración dependerá de la correlación posterior con DNS, HTTP y TLS.

Al aplicar el filtro `ip.addr == 172.16.1.66` y revisar `Statistics > Endpoints > IPv4`, se identificaron 45 endpoints IPv4 relacionados. De ellos, tres pertenecen al segmento interno: el propio host `172.16.1.66`, el controlador de dominio `172.16.1.4` y la dirección de broadcast `172.16.1.255`. Por lo tanto, el equipo investigado se comunicó con **42 direcciones IP externas**.

El host `172.16.1.66` participa en 11.531 de los 11.562 paquetes de la captura, aproximadamente el 99,7 % del total. Asimismo, recibió 8.953 paquetes y transmitió 2.578, evidenciando un volumen predominantemente entrante.

#### Detalles de la víctima

El análisis de las consultas mDNS, LLMNR y DNS permitió identificar el hostname `DESKTOP-SKBR25F`. La dirección MAC de la interfaz fue obtenida desde la cabecera Ethernet y corresponde a `00:1e:64:ec:f3:08`.

Mediante Kerberos y Netlogon se confirmó la cuenta de equipo `DESKTOP-SKBR25F$`. Posteriormente, el análisis del protocolo SAMR permitió identificar la cuenta de usuario asociada.

En el paquete 1070, correspondiente a una respuesta `QueryUserInfo`, se observó el nombre de cuenta `ccollier` y el nombre completo `Clark Collier`. El registro indica un último inicio de sesión el 29 de julio de 2024 a las 23:39:11.

| Propiedad | Valor |
|---|---|
| Dirección IP | `172.16.1.66` |
| Hostname | `DESKTOP-SKBR25F` |
| Dirección MAC | `00:1e:64:ec:f3:08` |
| Dominio | `wiresharkworkshop.online` |
| Cuenta de equipo | `DESKTOP-SKBR25F$` |
| Usuario Windows | `ccollier` |
| Nombre completo | `Clark Collier` |
| Último inicio de sesión | `2024-07-29 23:39:11` |


Evidencia:
- `capturas/02-conversaciones-ipv4-por-bytes.png`
- `capturas/03-endpoints-ipv4-host-principal.png`
- `capturas/14-mac-host-principal.png`
- `capturas/15-usuario-kerberos.png`
- `capturas/16-netlogon-cuenta-equipo.png`
- `capturas/17-usuario-samr.png`

### 2. Jerarquía de protocolos

Mediante `Statistics > Protocol Hierarchy` se examinó la distribución general del tráfico sin aplicar filtros de visualización. La captura está compuesta casi completamente por tráfico IPv4, presente en 11.531 paquetes, equivalentes al 99,73 % del total.

TCP constituye el principal protocolo de transporte, con 11.276 paquetes (97,53 %) y aproximadamente 10,92 MB, equivalentes al 96,27 % de los bytes capturados. UDP presenta una participación considerablemente menor, con 243 paquetes (2,10 %).

Dentro del tráfico TCP, TLS representa 1.402 paquetes (12,13 %), pero concentra aproximadamente 10,41 MB, equivalentes al 91,77 % de todos los bytes de la captura. Esta diferencia indica que la mayor parte del volumen transferido corresponde a sesiones cifradas de tamaño elevado. El resultado es consistente con las transferencias predominantemente entrantes identificadas anteriormente entre `172.16.1.66` y diferentes direcciones externas.

El tráfico HTTP sin cifrar es reducido, con solamente 4 paquetes. No obstante, deberá analizarse porque incluso una cantidad pequeña de solicitudes puede revelar URLs, redirecciones, descargas o comunicaciones relevantes.

DNS representa 171 paquetes (1,48 %) y aproximadamente 15,9 kB. También se identificó tráfico SMB/SMB2, LDAP, Kerberos y DCE/RPC, protocolos compatibles con la comunicación normal de un equipo Windows integrado a un dominio. Su presencia se correlaciona inicialmente con la comunicación observada entre `172.16.1.66` y el controlador de dominio `172.16.1.4`.

En esta instancia, la predominancia de TLS no permite clasificar el tráfico como malicioso por sí sola. Será necesario correlacionar las sesiones cifradas con las consultas DNS, las direcciones IP externas, los valores SNI y su comportamiento temporal.

| Protocolo | Paquetes | Porcentaje de paquetes | Bytes | Porcentaje de bytes |
|---|---:|---:|---:|---:|
| IPv4 | 11.531 | 99,73 % | 230.656* | 2,03 %* |
| TCP | 11.276 | 97,53 % | 10.918.627 | 96,27 % |
| UDP | 243 | 2,10 % | 1.944* | 0,02 %* |
| TLS | 1.402 | 12,13 % | 10.407.852 | 91,77 % |
| DNS | 171 | 1,48 % | 15.894 | 0,14 % |
| HTTP | 4 | 0,03 % | 957 | 0,01 % |
| SMB2 | 297 | 2,57 % | 70.106 | 0,62 % |
| LDAP | 186 | 1,61 % | 121.282 | 1,07 % |
| Kerberos | 56 | 0,48 % | 79.468 | 0,70 % |
| DCE/RPC | 188 | 1,63 % | 52.524 | 0,46 % |

\*En la jerarquía de Wireshark, los valores de bytes de protocolos como IPv4 y UDP representan los bytes atribuidos a esa capa, no necesariamente el tamaño completo de los paquetes que transportan.

**Evidencia:**
- `capturas/04-jerarquia-protocolos.png`



### 3. Análisis DNS

Se filtraron las consultas iniciadas por el host investigado mediante:

`dns.flags.response == 0 && ip.src == 172.16.1.66`

El análisis produjo 97 solicitudes de resolución: 95 mediante DNS, una mediante mDNS y una mediante LLMNR.

Las consultas mDNS, LLMNR y DNS permitieron identificar el nombre del equipo como `DESKTOP-SKBR25F`. Este hostname se encuentra asociado a la dirección `172.16.1.66` y al dominio interno `wiresharkworkshop.online`.

Una parte considerable de las consultas corresponde a servicios internos del dominio Windows y a infraestructura de Microsoft. Entre ellas se encuentran consultas relacionadas con LDAP, Kerberos, WPAD, Office, Bing, MSN y telemetría de Windows.

También se identificaron consultas externas que requieren correlación adicional: `github.com`, `objects.githubusercontent.com`, `repo1.maven.org`, `ip-api.com` y `javadl-esd-secure.oracle.com`. Su presencia no implica por sí sola actividad maliciosa, pero su proximidad temporal podría formar parte de una misma secuencia de navegación o descarga.

La clasificación definitiva dependerá de las respuestas DNS, las direcciones IP resueltas y su correlación con las sesiones HTTP y TLS.

Las respuestas DNS permitieron correlacionar las principales direcciones externas con dominios concretos. La dirección `199.232.196.209`, responsable de la transferencia de mayor volumen, fue resuelta para `repo1.maven.org`. La dirección `185.199.110.133` fue asociada con `objects.githubusercontent.com`, mientras que `23.198.7.175` corresponde a infraestructura utilizada por Bing y Akamai.

Aunque estos dominios pertenecen a servicios legítimos, las comunicaciones con GitHub y Maven deberán ser analizadas en mayor profundidad debido a su proximidad temporal y al volumen de datos transferidos. El uso de infraestructura legítima no descarta la descarga de herramientas o archivos potencialmente dañinos.

También se identificaron 14 respuestas NXDOMAIN. Ocho corresponden a consultas de `wpad.wiresharkworkshop.online`, cuatro a registros LDAP/SRV, una a `autodiscover.wiresharkworkshop.online` y una a `pti.store.microsoft.com`. Este comportamiento resulta compatible inicialmente con mecanismos automáticos de descubrimiento de Windows y no presenta características de generación algorítmica de dominios.

| Dominio | Dirección resuelta | Observación inicial |
|---|---|---|
| `github.com` | `140.82.113.3` | Acceso a GitHub |
| `objects.githubusercontent.com` | `185.199.110.133` y otras | Posible descarga de contenido de GitHub |
| `repo1.maven.org` | `199.232.196.209`, `199.232.192.209` | Repositorio Maven; transferencia de mayor volumen |
| `ip-api.com` | `208.95.112.1` | Consulta de información relacionada con la IP pública |
| `javadl-esd-secure.oracle.com` | `23.194.164.136` | Infraestructura de descarga de Java |
| `www.bing.com` | `23.198.7.175` y otras | Infraestructura de Bing/Akamai |

**Evidencia:**
- `capturas/05-consultas-dns-host-principal.png`
- `capturas/06-respuestas-dns-direcciones-ip.png`


### 4. Análisis HTTP

Se filtró el tráfico HTTP iniciado por el host investigado mediante:

`http.request && tcp && ip.src == 172.16.1.66`

Se identificaron dos solicitudes HTTP. La primera correspondió a una comprobación automática de conectividad de Windows contra `www.msftconnecttest.com/connecttest.txt`, utilizando el User-Agent `Microsoft NCSI`. Esta actividad se considera inicialmente legítima.

La segunda solicitud se produjo contra `ip-api.com` mediante el endpoint `/json/`. El host utilizó un User-Agent correspondiente a Chrome 73 sobre Windows 10 y recibió una respuesta HTTP `200 OK` en formato JSON.

La respuesta incluyó la IP pública `136.49.34.127`, la ubicación aproximada en Austin, Texas, el proveedor Google Fiber y el ASN `AS16591`. La IP obtenida representa la dirección pública del entorno analizado y no debe clasificarse como un indicador malicioso.

Aunque `ip-api.com` es un servicio legítimo, su consulta puede utilizarse como mecanismo de reconocimiento para identificar la dirección pública, ubicación, proveedor y zona horaria del sistema. Por este motivo, la solicitud se incorpora al timeline y deberá correlacionarse con la actividad anterior y posterior.

| Tiempo relativo | Destino | Método | Host y URI | Resultado | Valoración |
|---:|---|---|---|---|---|
| 0,674 s | `23.215.55.140` | GET | `www.msftconnecttest.com/connecttest.txt` | `200 OK` | Comprobación de conectividad de Windows |
| 78,007 s | `208.95.112.1` | GET | `ip-api.com/json/` | `200 OK`, JSON | Posible reconocimiento del entorno |

**Evidencia:**
- `capturas/08-solicitudes-http.png`
- `capturas/09-http-stream-ip-api.png`

### 5. Análisis TLS

Se analizaron los paquetes Client Hello TLS iniciados por el host `172.16.1.66` mediante el filtro:

`tls.handshake.type == 1 && ip.src == 172.16.1.66 && tls.handshake.extensions_server_name`

Se identificaron 77 paquetes Client Hello con información SNI. La mayor parte corresponde a infraestructura de Microsoft, Office, MSN, Bing y servicios relacionados con Windows.

Entre las comunicaciones externas relevantes se identificó una secuencia iniciada aproximadamente 64 segundos después del comienzo de la captura. El host estableció sesiones TLS con `github.com`, posteriormente con `objects.githubusercontent.com` y finalmente con `repo1.maven.org`.

La dirección `185.199.110.133`, asociada con `objects.githubusercontent.com`, coincide con la segunda transferencia de mayor volumen identificada en las conversaciones IPv4. Por otra parte, `199.232.196.209`, asociada con `repo1.maven.org`, corresponde a la transferencia de mayor volumen de toda la captura.

La infraestructura utilizada pertenece a servicios legítimos. Sin embargo, la secuencia temporal y el volumen transferido indican que el equipo obtuvo contenido desde GitHub y Maven. Debido al cifrado TLS, el nombre y contenido de los archivos no pueden determinarse directamente mediante la inspección del tráfico.

Posteriormente se observó una conexión con `javadl-esd-secure.oracle.com`, asociada con infraestructura oficial de distribución de Java. Esta comunicación deberá correlacionarse temporalmente para determinar si forma parte de la misma secuencia de actividad.

| Destino | SNI | Observación |
|---|---|---|
| `140.82.113.3` | `github.com` | Inicio de la secuencia relacionada con GitHub |
| `185.199.110.133` | `objects.githubusercontent.com` | Transferencia entrante de aproximadamente 833 kB |
| `199.232.196.209` | `repo1.maven.org` | Mayor transferencia de la captura, aproximadamente 8,89 MB |
| `23.194.164.136` | `javadl-esd-secure.oracle.com` | Infraestructura oficial de descarga de Java |
| `40.126.29.14` | `login.microsoftonline.com` | Actividad compatible inicialmente con servicios Microsoft |

No se identificaron mediante SNI dominios evidentemente generados, nombres aleatorios o infraestructura directamente atribuible a un servidor de comando y control. La valoración deberá complementarse con el análisis temporal de las conexiones.

**Evidencia:**
- `capturas/10-tls-client-hello-sni.png`

### 6. Análisis de periodicidad y beaconing

Se utilizó `Statistics > I/O Graphs` con un intervalo de un segundo para representar la actividad del host investigado y de los principales destinos externos.

Se analizaron individualmente las comunicaciones con `185.199.110.133` (`objects.githubusercontent.com`), `199.232.196.209` (`repo1.maven.org`) y `208.95.112.1` (`ip-api.com`).

La comunicación con `objects.githubusercontent.com` produjo un pico concentrado aproximadamente 65 segundos después del comienzo de la captura. Inmediatamente después, la conexión con `repo1.maven.org` generó el mayor pico de toda la evidencia, asociado con la transferencia entrante de aproximadamente 8,89 MB.

La consulta a `ip-api.com` fue breve y se produjo aproximadamente en el segundo 78. No se observaron conexiones periódicas o de bajo volumen repetidas regularmente hacia estos destinos.

El patrón analizado resulta más compatible con una secuencia puntual de acceso, descarga y reconocimiento que con un comportamiento de beaconing clásico. Esta conclusión se limita a los destinos examinados y al periodo cubierto por la captura.

El Flow Graph permitió reconstruir la secuencia principal entre los segundos 63,96 y 78,05. El host consultó inicialmente `github.com`, estableció una sesión TLS y posteriormente se comunicó con `objects.githubusercontent.com`. A continuación, realizó múltiples consultas y conexiones TLS con `repo1.maven.org`.

Después de estas transferencias, el equipo consultó `ip-api.com` y realizó una solicitud HTTP `GET /json/`, recibiendo una respuesta satisfactoria en formato JSON. La proximidad temporal respalda la hipótesis de una secuencia relacionada de acceso a repositorios, descarga de contenido y reconocimiento de la dirección pública del entorno.


**Evidencia:**
- `capturas/11-io-graph-comunicaciones-relevantes.png`
- `capturas/12-flow-graph-secuencia-principal.png`

### 7. Evidencia exportada

Mediante `File > Export Objects > HTTP` se identificaron y exportaron dos objetos transmitidos sin cifrado.

El primero, `connecttest.txt`, corresponde a la comprobación automática de conectividad de Windows. El segundo, guardado como `ip-api-response.json`, contiene la respuesta proporcionada por `ip-api.com` con información sobre la dirección pública y ubicación aproximada del entorno analizado.

Después de la exportación se calculó el hash SHA-256 de cada objeto para preservar y documentar su integridad.

| Archivo | Tamaño | SHA-256 | Valoración |
|---|---:|---|---|
| `connecttest.txt` | 22 bytes | `5E9A7996FE94D7BE10595D7133748760BF8348198B71B7A50FD8AFFAA980AC61` | Comprobación legítima de conectividad |
| `ip-api-response.json` | 294 bytes | `47729774D301B648E888DEE3B5E215D63ADABB069700E1D81671FCBDFB80E4BB` | Evidencia de consulta de información sobre la IP pública |

Los archivos fueron conservados sin modificar dentro de la carpeta de evidencia. Los hashes documentados corresponden a evidencia extraída y no deben interpretarse automáticamente como indicadores maliciosos.

No fue posible exportar mediante HTTP los objetos transferidos desde GitHub y Maven debido a que esas comunicaciones se encuentran cifradas mediante TLS.

**Evidencia:**
- `capturas/13-objetos-http-disponibles.png`
- `evidencia/connecttest.txt`
- `evidencia/ip-api-response.json`

### 8. Indicadores de compromiso y observables

| Tipo | Valor | Evidencia | Interpretación |
|---|---|---|---|
| IP externa | `140.82.113.3` | DNS y TLS SNI | Dirección asociada con `github.com`; infraestructura compartida |
| Dominio | `github.com` | DNS y TLS SNI | Inicio de la secuencia de acceso a GitHub |
| IP externa | `185.199.110.133` | DNS, TLS y Conversations | Asociada con `objects.githubusercontent.com`; transferencia entrante aproximada de 833 kB |
| Dominio | `objects.githubusercontent.com` | DNS y TLS SNI | Posible descarga de contenido alojado en GitHub |
| IP externa | `199.232.196.209` | DNS, TLS y Conversations | Asociada con Maven; mayor transferencia de la captura, aproximadamente 8,89 MB |
| Dominio | `repo1.maven.org` | DNS y TLS SNI | Descarga de contenido desde el repositorio Maven |
| IP externa | `208.95.112.1` | DNS y HTTP | Dirección resuelta para `ip-api.com` |
| Dominio | `ip-api.com` | DNS y HTTP | Servicio utilizado para consultar información de la IP pública |
| URL/URI | `http://ip-api.com/json/` | HTTP, paquete 9111 | Consulta de IP pública, ubicación, proveedor y ASN |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36` | HTTP stream 84 | Cliente utilizado en la consulta a IP-API |
| SNI | `javadl-esd-secure.oracle.com` | TLS Client Hello | Acceso posterior a infraestructura de descarga de Java |

Las direcciones de GitHub, Fastly, Maven, Oracle y Microsoft corresponden a infraestructura compartida. Por lo tanto, no se recomienda bloquearlas globalmente basándose únicamente en esta captura.

Los elementos deben utilizarse principalmente para búsqueda histórica y correlación temporal. El observable de mayor interés contextual es la secuencia `github.com` → `objects.githubusercontent.com` → `repo1.maven.org` → `ip-api.com/json/`.

### 9. Timeline del incidente

La secuencia temporal fue reconstruida correlacionando registros SAMR, consultas DNS, sesiones TLS, tráfico HTTP y estadísticas de conversaciones. Los horarios corresponden a la zona horaria local configurada en la captura.

| Fecha y hora | Evento | Interpretación |
|---|---|---|
| `2024-07-29 23:38:48` | Inicio de la captura de red | Comienza el periodo de observación |
| `2024-07-29 23:39:11.839` | Último inicio de sesión registrado para `ccollier` | Se identifica al usuario activo como Clark Collier |
| `2024-07-29 23:39:52.925` | Consultas DNS para `github.com` y `repo1.maven.org` | Comienza la secuencia de acceso a repositorios externos |
| `2024-07-29 23:39:53.167` | Client Hello TLS hacia `github.com` (`140.82.113.3`) | El host establece una sesión cifrada con GitHub |
| `2024-07-29 23:39:53.734–23:39:53.828` | Resolución DNS y Client Hello hacia `objects.githubusercontent.com` (`185.199.110.133`) | Se inicia una transferencia entrante aproximada de 833 kB desde GitHub Objects |
| `2024-07-29 23:39:57.008–23:39:57.030` | Tres Client Hello hacia `repo1.maven.org` (`199.232.196.209`) | Se establecen sesiones asociadas con la mayor transferencia de la captura, aproximadamente 8,89 MB |
| `2024-07-29 23:40:06.968` | Solicitud HTTP `GET /json/` hacia `ip-api.com` (`208.95.112.1`) | Se obtiene la IP pública, ubicación, proveedor y ASN del entorno |
| `2024-07-29 23:44:29.516` | Client Hello hacia `javadl-esd-secure.oracle.com` (`23.194.164.136`) | Acceso posterior a infraestructura oficial de descarga de Java |

La secuencia principal ocurre pocos segundos después del inicio de sesión del usuario. El host accede casi simultáneamente a GitHub y Maven, recibe transferencias de gran volumen y posteriormente consulta información sobre su IP pública mediante `ip-api.com`.

El patrón observado es compatible con una actividad encadenada de acceso a repositorios, descarga de contenido y reconocimiento del entorno. Sin embargo, debido al cifrado TLS, la captura no permite determinar directamente los nombres ni el contenido de los archivos transferidos.

La comunicación posterior con la infraestructura de Oracle podría indicar la obtención o actualización de componentes Java. Su relación exacta con la actividad anterior no puede confirmarse exclusivamente mediante la evidencia de red disponible.

**Evidencia:**
- `capturas/12-flow-graph-secuencia-principal.png`
- `capturas/17-usuario-samr.png`
- `capturas/18-timeline-eventos-principales.png`

### 10. Evaluación y respuesta SOC

#### Evaluación de severidad

El incidente se clasifica con severidad **High**.

La clasificación se fundamenta en la identificación de una secuencia temporal de acceso a GitHub, descarga de contenido desde GitHub Objects, transferencia de aproximadamente 8,89 MB desde Maven y posterior consulta a `ip-api.com` para obtener información sobre la IP pública y ubicación del entorno.

El host involucrado fue identificado como `DESKTOP-SKBR25F`, con dirección `172.16.1.66`, y el usuario asociado como `ccollier` (Clark Collier).

La actividad requiere una investigación inmediata del endpoint. Sin embargo, no se asigna severidad Critical porque la captura no permite confirmar directamente la ejecución de malware, persistencia, movimiento lateral, exfiltración de información o comunicación con un servidor de comando y control.

| Criterio | Evaluación |
|---|---|
| Host y usuario identificados | Sí |
| Transferencias externas de gran volumen | Sí |
| Reconocimiento mediante IP-API | Sí |
| Payload identificado | No, contenido cifrado mediante TLS |
| Ejecución de malware confirmada | No |
| Persistencia confirmada | No |
| Beaconing o C2 confirmado | No |
| Exfiltración confirmada | No |
| Severidad | **High** |
| Confianza analítica | **Media** |

#### Escalamiento

El caso debe ser escalado desde SOC Nivel 1 hacia:

1. **SOC Nivel 2**, para ampliar la investigación y correlacionar la actividad con otras fuentes.
2. **Equipo de Respuesta a Incidentes o DFIR**, para adquirir y analizar evidencia del endpoint.
3. **Equipo de soporte/administración de endpoints**, para aislar el equipo y obtener logs, procesos y archivos.
4. **Equipo de identidad o Active Directory**, si se detectan señales de compromiso de la cuenta `ccollier`.

#### Acciones inmediatas de contención

| Prioridad | Acción | Objetivo |
|---:|---|---|
| 1 | Aislar `DESKTOP-SKBR25F` de la red mediante EDR, NAC o segmentación controlada | Evitar comunicaciones adicionales sin apagar el equipo |
| 2 | Preservar la captura PCAP y los logs disponibles, documentando hashes y cadena de custodia | Mantener la integridad de la evidencia |
| 3 | Obtener un triage del endpoint: procesos, conexiones, usuarios conectados, archivos recientes, tareas programadas, servicios y claves de inicio automático | Buscar ejecución y persistencia |
| 4 | Revisar la carpeta Descargas, historial del navegador, caché, archivos temporales y actividad de Java | Identificar el contenido obtenido desde GitHub, Maven u Oracle |
| 5 | Capturar memoria RAM si el procedimiento y las herramientas disponibles lo permiten | Recuperar procesos, conexiones y artefactos volátiles |
| 6 | Buscar en EDR, SIEM, proxy, DNS y firewall otros equipos con la misma secuencia de dominios y horarios | Determinar el alcance del incidente |

#### Acciones posteriores de erradicación y recuperación

| Prioridad | Acción | Objetivo |
|---:|---|---|
| 1 | Analizar los archivos recuperados mediante hashes, firmas, antivirus, sandbox y reglas YARA | Determinar si contienen código malicioso |
| 2 | Validar con el usuario y su responsable si el acceso a GitHub, Maven y Java estaba justificado | Diferenciar actividad autorizada de una ejecución no reconocida |
| 3 | Restablecer la contraseña de `ccollier` y revocar sesiones si aparecen indicios de compromiso de credenciales | Reducir el riesgo de reutilización de la cuenta |
| 4 | Actualizar navegador, Java y sistema operativo según las políticas corporativas | Corregir software obsoleto y reducir superficie de ataque |
| 5 | Eliminar artefactos maliciosos y mecanismos de persistencia que sean confirmados durante el análisis | Erradicar la amenaza |
| 6 | Restaurar o reinstalar el endpoint desde una imagen confiable si no puede garantizarse su integridad | Recuperar el activo de forma segura |
| 7 | Mantener monitoreo reforzado sobre el host, usuario y observables relacionados | Detectar recurrencia o actividad residual |
| 8 | Crear reglas de detección basadas en la combinación temporal de GitHub Objects, Maven e IP-API | Detectar secuencias similares sin bloquear infraestructura legítima |

#### Consideraciones sobre bloqueo

No se recomienda bloquear globalmente `github.com`, `objects.githubusercontent.com`, `repo1.maven.org`, Fastly, Oracle o sus direcciones IP, ya que corresponden a infraestructura legítima y compartida.

Las medidas preventivas deberían basarse en correlación contextual: equipo no autorizado, volumen de descarga, horarios, procesos iniciadores, reputación del archivo, hashes y consulta posterior a servicios de reconocimiento como `ip-api.com`.

#### Estado del caso

El caso debe permanecer **abierto y escalado** hasta completar el análisis del endpoint y determinar qué archivos fueron descargados, qué proceso inició las conexiones y si existió ejecución, persistencia o afectación adicional.
