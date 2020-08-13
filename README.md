# BCAST_IDS: Detección de Malware en Redes LAN

## Abstract
La intrusión y propagación de Malware en redes de comunicaciones de área local (LAN) supone un serio riesgo que atenta contra la integridad, confidencialidad y disponibilidad de cualquier entorno TI. El desarrollo de **Sistemas de Detección de Intrusiones de Red utilizando Machine Learning (ML)** y aplicaciones de técnicas y estudios en extracción de patrones en los datos (Data Mining), es un enfoque novedoso para hacer frente a este tipo de amenazas. Estas soluciones pueden identificar y aplicar medidas paliativas frente a la detección de tráfico malicioso y, por tanto, ofrecer una protección de red adicional. **BCAST_IDS** es un proyecto de Seguridad elaborado por el departamento de Comunicaciones de Gestión Tributaria Territorial (GTT), que obtiene los datos actividad de los dispositivos activos y conectados a cualquier red LAN (o Wifi) y, mediante la aplicación de un algoritmo de Machine Learning, es capaz de avisar cuando detecta un comportamiento inusual en la red.

## Introducción
Un Sistema de Detección de Intrusiones, conocido también por el término anglosajón *Network Intrusion Detection System* o NIDS, es una herramienta software (o hardware) utilizada para monitorizar tráfico de red y encontrar posibles señales de ataques o actividades sospechosas. De hecho, están constantemente analizando y visualizando patrones de comportamiento en un entorno de red monitorizado. Si el sistema detecta un patrón que coincide con una firma o alguna política, genera una alerta de seguridad. 

## *BCAST_IDS*: Machine Learning aplicado a un NIDS
![alt text](https://user-images.githubusercontent.com/69505347/89898449-0b2f5f80-dbe1-11ea-9158-b689bfaf4e41.png)
Uno de los mecanismos de propagación que utiliza el Malware para infectar a otros equipos localizados en la misma red es el tráfico de difusión. Estas intrusiones de red pueden considerarse como anomalías. Por ello, *BCAST_IDS* emplea el algoritmo de ML **Isolation Forest**, que se encarga, precisamente, de encontrar conjuntos de datos anormales, esto es, actividad de red maliciosa.

El sistema consiste en tres fases:
- **Preprocesamiento**: recogida y estructuración de los datos que utilizará el algoritmo de ML para aprender y crear un modelo. En esta fase, también se han identificado las columnas (features) del dataset:

  ```
  - MAC: dirección MAC.
  - num_MAC: cantidad de veces que ha aparecido una dirección MAC en la captura de red en curso.
  - UCAST: cantidad de tráfico UNICAST que ha generado una dirección MAC en la captura de red en curso.
  - MCAS: cantidad de tráfico MULTICAST que ha generado una dirección MAC en la captura de red en curso.
  - BCAST: cantidad de tráfico BROADCAST que ha generado una dirección MAC en la captura de red en curso.
  - ARPrq: cantidad de tráfico ARP REQUEST que ha generado una dirección MAC en la captura de red en curso.
  - ARPpb: cantidad de tráfico ARP PROBE que ha generado una dirección MAC en la captura de red en curso.
  - ARPan: cantidad de tráfico ARP Announcement que ha generado una dirección MAC en la captura de red en curso.
  - ARPgr: cantidad de tráfico ARP Gratitude que ha generado una dirección MAC en la captura de red en curso.
  - IPF: cantidad de direcciones IP que sí que existen y que han sido preguntadas por una dirección MAC de la captura de red en curso mediante solicitudes ARP request (sin duplicados).
  - IP_ICMP: cantidad de tráfico ICMP  que ha generado una dirección MAC en la captura de red en curso.
  - IP_UDP: cantidad de tráfico UDP que ha generado una dirección MAC en la captura de red en curso.
  - IP_TCP: cantidad de tráfico TCP que ha generado una dirección MAC en la captura de red en curso.
  - IP_RESTO: cantidad de otro tipo de tráfico IP que ha generado una dirección MAC en la captura de red en curso.
  - IPv6: cantidad de tráfico IP versión 6 que ha generado una dirección MAC en la captura de red en curso. 
  - ETH_RESTO: cantidad de otro tipo de tráfico no categorizado previamente, que ha generado una dirección MAC en la captura de red en curso. 
  - ARP_noIP: cantidad de direcciones IP que sí que existen y que han sido preguntadas por una dirección MAC de la captura de red en curso (sin duplicados) mediante solicitudes ARP request.
  - SALIDA: actividad de MAC categorizada para entrenar con un algoritmo supervisado. Dos posibles valores: 0 (no hay ataque) 1 (ataque).
  ```
- **Entrenamiento**: el algoritmo de Machine Learning Isolation Forest obtiene patrones de los datos y genera el modelo correspondiente.
- **Detección**: una vez que el modelo ha sido creado, los datos de tráfico monitorizados serán empleados como entrada al sistema para su posterior comparación con el modelo generado. Si el patrón de la observación coincide con alguna anomalía, se generará una alarma.
