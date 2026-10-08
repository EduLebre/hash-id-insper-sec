# Demo — Hash_ID

## Visão geral

O Hash_ID é uma ferramenta de terminal que sugere o algoritmo de uma string a
partir de características visíveis, como prefixo, comprimento e conjunto de
caracteres. Ela não quebra hashes: apenas apresenta candidatos e explica o motivo
de cada identificação.

## O que foi implementado

- Identificação individual e em lote
- Saída em tabela e JSON
- Leitura por argumento, arquivo ou `stdin`
- Modos do Hashcat para algoritmos conhecidos
- Estimativa de dificuldade de quebra
- Reconhecimento de formatos que não são hashes

## Casos para demonstrar

```powershell
hashid 5f4dcc3b5aa765d61d8327deb882cf99
hashid '$2b$12$EixZaYVK1fsbw1ZfbX3OXe'
hashid '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA'
hashid 'https://insper.edu.br/'
hashid --json 5f4dcc3b5aa765d61d8327deb882cf99
```

Para demonstrar a entrada em lote, use um arquivo `hashes.txt` com uma entrada
por linha:

```powershell
hashid --file .\hashes.txt
Get-Content .\hashes.txt | hashid
```

## Decisões técnicas

As regras mais específicas são verificadas primeiro. Um prefixo como `$2b$`
identifica bcrypt com mais segurança do que apenas o comprimento da string. Para
entradas repetidas em lote, os resultados são guardados em cache durante aquela
execução.

A confiança indica a certeza da identificação. A dificuldade indica o custo
aproximado de testar senhas para aquele algoritmo. São informações diferentes.

## Validação

A validação local terminou com 66 testes passando, Ruff e Mypy sem erros e
Pylint com nota 10/10.

```powershell
just test
just lint
```

## Limitações

Algoritmos diferentes podem produzir saídas com o mesmo formato. Por isso, a
ferramenta retorna candidatos e não afirma que toda identificação é definitiva.
Mais detalhes estão em [docs/limitations.md](docs/limitations.md).

## Vídeo

O vídeo de demonstração será enviado em formato `.mp4` pelo formulário de
entrega.

