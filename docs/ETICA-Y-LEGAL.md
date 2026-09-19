# Uso responsable, ética y marco legal

`zipaes` es una herramienta de **recuperación de datos**. Esta página explica qué hace, qué
no hace, y bajo qué condiciones corresponde usarla.

---

## Qué hace y qué no hace

**Hace:**

- leer el formato de los archivos ZIP con cifrado AES, que muchas herramientas no soportan;
- verificar de forma concluyente si una contraseña es la correcta;
- emitir el hash que necesitan hashcat y John the Ripper;
- probar candidatos que **vos aportás** (diccionario, lista dirigida, mutaciones);
- descifrar y extraer el contenido una vez conocida la contraseña.

**No hace:**

- no explota ninguna vulnerabilidad;
- no debilita ni elude el cifrado: AES-256 sigue siendo AES-256;
- no recupera la contraseña por arte de magia: sólo prueba candidatos, como cualquier
  herramienta de cracking;
- no accede a ningún sistema remoto;
- no incluye diccionarios ni material de terceros.

Es, funcionalmente, lo mismo que `hashcat` o `John the Ripper` con un parser de formato
delante. Esas herramientas son estándar en auditoría, peritaje y administración de sistemas.

---

## Cuándo corresponde usarla

**Sí:**

- un archivo tuyo, cuya contraseña perdiste;
- un archivo de tu organización, con autorización de quien puede darla;
- un peritaje o una auditoría, con mandato escrito;
- una sucesión, un traspaso o una recuperación de emergencia, con autorización verificable;
- docencia e investigación sobre formatos de archivo.

**No:**

- archivos de otras personas sin su autorización expresa;
- archivos encontrados, comprados o descargados de un tercero;
- cualquier situación donde el titular del archivo no haya consentido el acceso;
- para acceder a información que no te corresponde conocer, aunque técnicamente puedas.

---

## Nota sobre el marco legal

Las normas varían por país, y este documento no es asesoramiento jurídico. Como referencia
general, en buena parte de las jurisdicciones:

- acceder a datos ajenos sin autorización suele estar tipificado, con independencia del
  medio técnico empleado;
- el hecho de que la contraseña se recupere o no es irrelevante: lo que se valora es el
  acceso no autorizado;
- los equipos de una empresa suelen tener políticas internas que **no** equivalen a
  autorización legal para un tercero;
- en un contexto pericial o de sucesión conviene dejar constancia escrita de la
  autorización antes de empezar, y conservar esa constancia.

Si tu caso involucra datos de terceros, equipos corporativos, sistemas de salud, información
financiera o datos personales, consultá con un abogado antes de ejecutar nada.

---

## Recomendaciones prácticas

1. **Dejá rastro.** Si el caso es serio, documentá la autorización, la fecha, el archivo y
   quién la otorgó, antes de correr el primer comando.
2. **Trabajá sobre copias.** No modifiques el original.
3. **Mantené el alcance.** Recuperá lo que la autorización cubre, y nada más.
4. **Cuidá el resultado.** Un archivo descifrado contiene lo que contenía: tratalo con la
   confidencialidad que corresponde.
5. **Si dudás, preguntá.** Ante una duda razonable sobre la titularidad, no ejecutes.

---

## Descargo

El software se distribuye bajo licencia MIT, **sin garantía de ningún tipo**. Los autores y
colaboradores no se responsabilizan del uso que se le dé ni de las consecuencias legales,
económicas o de cualquier otra índole derivadas de su utilización. La responsabilidad de
determinar si el uso es legítimo es exclusivamente de quien lo ejecuta.

Si encontrás un problema de seguridad en la herramienta, abrí un *issue* describiendo el
escenario y cómo reproducirlo. No la uses contra archivos sobre los que no tengas derechos
para demostrar el problema: alcanza con una descripción.