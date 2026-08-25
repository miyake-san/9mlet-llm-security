# Guia de Contribuição

Obrigado por contribuir com o `9mlet-llm-security`. Este repositório tem finalidade acadêmica e busca manter materiais claros, reprodutíveis e tecnicamente rigorosos para a disciplina **Segurança, Conformidade e Guardrails para LLMs**.

> Voltar para o [README principal](../README.md).

## Como Reportar Issues

Abra uma issue em https://github.com/miyake-san/9mlet-llm-security/issues quando encontrar problemas ou oportunidades de melhoria. Antes de criar uma nova issue, verifique se já existe uma discussão semelhante.

Ao reportar um problema, inclua:

- Aula, pasta ou arquivo afetado.
- Passos para reproduzir o comportamento observado.
- Resultado esperado e resultado obtido.
- Versões relevantes de Python, Docker, sistema operacional e ferramentas externas.
- Logs, mensagens de erro ou evidências, removendo qualquer dado sensível.

Para sugestões de conteúdo, descreva o objetivo pedagógico, a relação com segurança de LLMs e como a mudança se integra ao fio condutor do **Banco Aurora** e do **Aurora Assist**.

## Fluxo de Pull Requests

1. Crie uma branch a partir da branch principal:

   ```bash
   git checkout -b feat/descricao-curta
   ```

2. Faça mudanças pequenas, coesas e revisáveis. Evite misturar refatoração, documentação e novas funcionalidades no mesmo PR quando não houver dependência direta.

3. Use commits convencionais sempre que possível:

   ```text
   feat: adiciona laboratório de prompt injection indireta
   fix: corrige anonimização de CPF nos exemplos
   docs: atualiza roteiro da aula 04
   test: cobre política de bloqueio para PII
   chore: atualiza dependências de desenvolvimento
   ```

4. Antes de abrir o PR, rode os testes e validações aplicáveis à aula modificada.

5. No PR, descreva:
   - Motivação da mudança.
   - Arquivos e aulas afetados.
   - Evidência de validação executada.
   - Riscos, limitações ou trabalhos futuros.

6. Aguarde revisão. Comentários de revisão devem ser tratados com commits adicionais, preservando rastreabilidade da discussão.

## Padrões de Código

Para código Python, adote os seguintes padrões:

- **PEP 8** como base de estilo.
- **Type hints** em funções públicas, modelos de dados e interfaces entre componentes.
- **Docstrings no estilo Google** para módulos, classes e funções não triviais.
- **Ruff** para linting e formatação, quando configurado no projeto ou na aula.
- **Pydantic** para contratos de dados, validação de configurações, schemas de entrada/saída e objetos de política.
- Separação explícita entre código de laboratório, fixtures de teste e dados sintéticos.
- Nunca inclua segredos, chaves de API, tokens, credenciais ou dados pessoais reais no repositório.

Exemplo de docstring esperada:

```python
def mask_account_number(value: str) -> str:
    """Mascara um número de conta bancária para exibição segura.

    Args:
        value: Número de conta em formato textual.

    Returns:
        Número mascarado, preservando apenas os últimos dígitos.
    """
```

## Como Rodar Testes e Validações

Sincronize o ambiente na raiz do repositório com o [`uv`](https://docs.astral.sh/uv/). O comando
cria o `.venv` e instala as dependências de `pyproject.toml`, incluindo o grupo `dev`:

```bash
uv sync
```

O comando é idêntico em Linux, macOS e Windows. **Não é necessário ativar o ambiente
manualmente** — use `uv run <comando>` para executar ferramentas dentro dele. Para adicionar uma
nova dependência, use `uv add <pacote>` (ou `uv add --dev <pacote>` para ferramentas de
desenvolvimento), o que atualiza `pyproject.toml` e `uv.lock` automaticamente.

Rode os testes com `uv run pytest`:

```bash
uv run pytest
```

Quando a aula ou o projeto definir tarefas com Taskipy, use:

```bash
task --list
task test
task lint
```

Para cenários de avaliação com `promptfoo`, instale a ferramenta e execute na pasta que contém a configuração:

```bash
npm install -g promptfoo
promptfoo eval
```

Se apenas uma aula foi alterada, prefira validações direcionadas à pasta modificada. Use validações completas quando a mudança afetar dependências compartilhadas, contratos de dados, políticas globais ou documentação central.

## Como Adicionar uma Nova Aula

Novas aulas devem seguir o padrão de organização existente:

```text
NN_nome_snake_case/
├── README.md
├── notebooks/
├── src/
├── tests/
├── data/              # apenas dados sintéticos ou públicos permitidos
└── promptfoo/         # quando houver avaliações automatizadas de prompts
```

Requisitos mínimos:

- Nome da pasta no formato `NN_nome_snake_case/`, preservando ordenação numérica.
- `README.md` da aula com objetivos, contexto, pré-requisitos, execução e critérios de avaliação.
- Notebooks ou scripts reprodutíveis, com células e saídas revisáveis.
- Testes automatizados em `tests/` para funções, políticas e guardrails relevantes.
- Dados sintéticos documentados; dados reais ou pessoais não devem ser adicionados.
- Relação explícita com o arco narrativo do **Banco Aurora** e do **Aurora Assist**.
- Atualização do [README principal](../README.md) e de documentos arquiteturais quando a nova aula alterar fluxo, componentes ou decisões relevantes.

## Segurança e Privacidade

- Não publique segredos, credenciais, tokens, `.env` reais ou dados pessoais.
- Use exemplos sintéticos para PII, transações, clientes, logs e prompts.
- Documente riscos residuais quando um laboratório reproduzir comportamento inseguro para fins didáticos.
- Evite instruções que incentivem uso indevido fora do ambiente acadêmico controlado.

## Código de Conduta

Espera-se colaboração respeitosa, inclusiva e orientada a aprendizado. Discussões devem focar evidências técnicas, clareza pedagógica e melhoria do material.

Não são aceitos assédio, discriminação, exposição de dados pessoais, linguagem ofensiva ou uso do repositório para fins maliciosos. Contribuições que violem segurança, privacidade ou ética acadêmica poderão ser recusadas.
