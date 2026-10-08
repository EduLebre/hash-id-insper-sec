# Hash_ID

![Mode](https://img.shields.io/badge/Mode-Individual-402)
![Difficulty](https://img.shields.io/badge/Difficulty-N1_Iniciante-brightgreen)
![Stack](https://img.shields.io/badge/Stack-Python-3776AB)

> Identifique o algoritmo por trás de uma string de hash por seu prefixo, comprimento e conjunto de caracteres — o primeiro passo em qualquer fluxo de trabalho de quebra de senhas.

_Esta é uma visão geral rápida — teoria de segurança, arquitetura e tutoriais completos estão em [/learn](./learn/00-Introdução.md)._

> [!NOTE]
> Esta ferramenta foi desenvolvida para alguém que nunca escreveu Python antes. O código-fonte é amplamente comentado como material de apoio ao aprendizado, a pasta `learn/` explica cada conceito do zero, e toda a ferramenta consiste em um único arquivo legível.

## 🎯 Objetivo

Construir uma ferramenta de linha de comando que identifica o algoritmo de hash de uma string com base em padrões observáveis (prefixo, comprimento, conjunto de caracteres), retornando candidatos classificados com níveis de confiança.

## 🧠 Aprendizados

- O que são hashes e por que não são criptografia reversível
- Como identificar algoritmos por formato, comprimento e prefixo
- Os três sinais de identificação: prefixo, comprimento, conjunto de caracteres
- Fundamentos de Python: funções puras, tipagem, testes, CLI
- Como estruturar um pipeline de decisão em camadas

## 📘 Caso tenha dificuldades com a base do projeto

> [!NOTE]
> Este projeto ensina Python do zero nos módulos `learn/`. Se você empacar na base, estes recursos rápidos ajudam a recuperar o fluxo.

- [Curso em Vídeo — Python para Iniciantes](https://www.cursoemvideo.com/course/curso-python-3/) — vídeo-aula passo a passo
- [Python Tutorial for Beginners — freeCodeCamp.org](https://www.youtube.com/watch?v=rfscVS0vtbw) — introdução prática a Python
- [Hash algorithms — Computerphile](https://youtu.be/b4b8ktEV4Bg?si=4KDOBMfntwpbWxkw) — entenda hashes em 10 minutos

## 🛠️ Funcionalidades

- Identificação por prefixo, comprimento e conjunto de caracteres
- Lista de candidatos com confiança e motivo da identificação
- Saída em tabela ou JSON
- Leitura de um hash, de um arquivo ou do `stdin`
- Cache durante o processamento de entradas repetidas em lote
- Sugestão do modo correspondente do Hashcat
- Estimativa de dificuldade de quebra
- Reconhecimento de URL, JWT, Base32, Base58, Base64 e hexadecimal com `0x`

## ✅ Estado atual

- [x] 66 testes automatizados passando
- [x] Ruff e Mypy sem erros
- [x] Pylint com nota 10/10
- [x] Execução individual, por arquivo e por `stdin`
- [x] Códigos de saída adequados para uso em scripts

## 🧪 Validação

```bash
just test       # executa o pytest
just lint       # ruff + mypy --strict + pylint
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
# MD5 | modo 0 | trivial | confiança medium
```

Teste com os [hashes de demonstração](#hashes-de-demonstração) abaixo.

## 🎬 Demo

O roteiro, os casos escolhidos e os resultados estão em [DEMO.md](DEMO.md).

## 🚀 Instalação e execução

Na raiz do projeto, instale as dependências:

```bash
uv sync --all-extras
uv run hashid 5f4dcc3b5aa765d61d8327deb882cf99
```

Se o ambiente virtual já estiver ativado, use diretamente `hashid`.

> [!TIP]
> Este projeto utiliza o [`just`](https://github.com/casey/just) como executor de comandos. Digite `just` para ver todos os comandos disponíveis.

## Hashes de Demonstração

| Entrada                                                                       | Resultado        | Hashcat | Dificuldade |
| ----------------------------------------------------------------------------- | ---------------- | ------- | ----------- |
| `5f4dcc3b5aa765d61d8327deb882cf99`                                            | MD5              | 0       | trivial     |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`            | SHA-256          | 1400    | trivial     |
| `$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK`              | bcrypt           | 3200    | hard        |
| `$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG` | Argon2id         | —       | very_hard   |
| `$apr1$JlOdSlVe$ipa1mTAv3LFRBHHzqaIaH/`                                       | Apache MD5-crypt | 1600    | moderate    |
| `https://insper.edu.br/`                                                      | URL, não é hash  | —       | —           |

> [!IMPORTANT]
> Sempre envolva hashes que começam com `$` em **aspas simples**. Sem as aspas, seu shell tentará expandir `$2`, `$P$`, `$1$` etc. como variáveis de shell.

## Ferramentas

```bash
just            # lista os comandos disponíveis
just test       # executa o pytest
just lint       # ruff + mypy --strict + pylint
just format     # yapf
just run -- <h> # identifica um hash

hashid --json <hash>        # saída estruturada
hashid --file hashes.txt    # uma entrada por linha
```

No PowerShell, também é possível usar o `stdin`:

```powershell
Get-Content .\hashes.txt | hashid
```

## Requisitos

- **Python 3.13+**
- [`uv`](https://github.com/astral-sh/uv) — gerenciador moderno de pacotes para Python.
- [`just`](https://github.com/casey/just) — usado nos comandos de validação.

Nenhum compilador, biblioteca de sistema ou acesso à rede é necessário.

## 📚 Material de apoio

| Módulo                                          | Tópico                                                             |
| ----------------------------------------------- | ------------------------------------------------------------------ |
| [00 - Introdução](learn/00-Introdução.md)       | Início rápido, pré-requisitos, problemas comuns                    |
| [01 - Conceitos](learn/01-Conceitos.md)         | O que são hashes, violações reais, os três sinais de identificação |
| [02 - Arquitetura](learn/02-Arquitetura.md)     | Arquitetura em três camadas, pipeline de decisão em seis etapas    |
| [03 - Implementação](learn/03-Implementação.md) | Explicação linha por linha — cada recurso do Python explicado      |
| [04 - Desafios](learn/04-Desafios.md)           | Cinco níveis de ideias para extensão                               |

## 🔗 Referências externas

- [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) — catálogo de formatos de hash reais
- [Name That Hash](https://nth.skerritt.blog/) — ferramenta online de identificação de hashes
- [Crypto 101](https://www.crypto101.io/) — introdução a criptografia aplicada

## Limitações conhecidas

A identificação é baseada no formato da entrada e pode retornar mais de um
candidato. Veja as [limitações conhecidas](docs/limitations.md) para entender os
casos em que não é possível determinar o algoritmo com certeza.

## 🧭 Próximos passos

A evolução natural deste projeto é o `Hash_Cracker`, que recebe um formato já
identificado e testa possíveis senhas com ataques de dicionário ou força bruta.

> [!NOTE]
> **Não é obrigatório** avançar para o próximo projeto imediatamente. Você pode fazer múltiplos projetos primários em paralelo, respeitando as janelas de entrega do calendário.

---

@CarterPerez-dev | Copyright (C) 2026 Murilo Miacci
