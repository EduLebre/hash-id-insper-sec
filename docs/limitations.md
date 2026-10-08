# Limitações conhecidas

O identificador trabalha com pistas do formato da entrada, como prefixo,
comprimento e caracteres usados. Por isso, o resultado é uma estimativa e não
uma confirmação do algoritmo original.

- Hashes diferentes podem ter o mesmo formato. Uma sequência de 32 caracteres
  hexadecimais, por exemplo, pode ser MD5, NTLM ou MD4.
- Um hash truncado pode ser confundido com outro algoritmo de saída menor.
- Entradas em Base32, Base58 ou Base64 podem gerar falsos positivos, pois a
  ferramenta analisa apenas a forma do texto.
- A dificuldade de quebra é aproximada. Ela também depende da senha, dos
  parâmetros do algoritmo e do hardware usado.

A ferramenta não valida senhas nem executa tentativas de quebra. Ela apenas
sugere candidatos e, quando possível, o modo correspondente do Hashcat.
