# Controle de Rede — Roteador Vivo

Fiz esse projeto porque queria ter controle de verdade sobre quem acessa minha internet em casa. Cansei de depender do app da operadora pra isso, então fui direto na API do roteador e montei meu próprio painel.

Com ele consigo ver todos os dispositivos conectados e bloquear/liberar o acesso de qualquer um com um clique — sem mexer no painel do roteador.

---

## Como funciona

O script acessa o painel admin do roteador Vivo (interface Sophia) via HTTP, faz login com MD5 igual o próprio site faz, e usa as rotas CGI internas pra:

- Listar dispositivos conectados (2.4GHz e 5GHz)
- Criar regras de firewall pra bloquear um IP específico
- Deletar essas regras pra liberar o acesso

Tem um cache em background que atualiza a cada 30 segundos, então a interface responde na hora sem travar esperando o roteador (a página de estatísticas dele demora ~10s pra carregar).

---

## Pré-requisitos

- Python 3.10+
- Estar na mesma rede do roteador (192.168.15.x)

Instala as dependências:

```bash
pip install flask requests
```

---

## Configuração

Abre o `controle_rede.py` e edita as primeiras linhas com as credenciais do seu roteador:

```python
ROUTER_IP = "192.168.15.1"
USERNAME  = "admin"
PASSWORD  = "sua_senha_aqui"
```

---

## Rodando

```bash
python controle_rede.py
```

O navegador abre automaticamente em `http://localhost:5000`.

A primeira carga leva uns 15s enquanto o cache é construído. Depois disso tudo responde na hora.

**Pra parar:** `Ctrl+C` no terminal.

> Se der erro de "porta em uso", é porque tem uma instância antiga rodando. Fecha o terminal onde ela estava ou mata o processo.

---

## O que aparece no painel

- Lista de todos os dispositivos conectados (nome, IP, MAC, tempo online)
- Badge verde = online / vermelho = bloqueado
- Botão pra bloquear ou liberar cada dispositivo
- Atualização automática a cada 35 segundos

---

## Como o bloqueio funciona

Quando clico em "Bloquear internet" num dispositivo, o script cria uma regra de firewall no roteador com o prefixo `BLOQUEAR_` no nome, apontando pro IP daquele dispositivo. Quando libero, deleta essa regra.

O painel só gerencia as regras que ele mesmo criou — não mexe em nenhuma outra configuração do roteador.

> **Dica:** Se o dispositivo que você quer controlar pegar IPs diferentes cada vez que conecta, configura uma reserva de DHCP no roteador pra fixar o IP dele pelo MAC address. Fica em Configurações > Rede Local.

---

## Estrutura

```
controle_rede.py   — servidor Flask + lógica de acesso ao roteador + frontend embutido
```

Tudo num arquivo só pra ficar simples de rodar e de carregar em outro computador se precisar.

---

## Adaptando pra outro roteador

O código foi feito pro roteador Vivo com interface Sophia (ZTE), mas dá pra adaptar pra qualquer roteador que tenha painel web.

O que você precisa descobrir no seu roteador:

**1. Como é o login**
Abre o DevTools do navegador (F12 → aba Network), faz o login no painel do roteador e vê qual requisição é feita — qual endpoint, quais campos, se a senha vai em texto puro ou com hash.

**2. Onde ficam os dispositivos conectados**
Procura uma página de "Dispositivos conectados", "DHCP clients" ou similar. No DevTools, vê se ela carrega via AJAX (fetch/XHR) — nesse caso tem um endpoint específico com os dados. Inspeciona o HTML pra entender a estrutura das tabelas.

**3. Como criar regras de firewall**
Vai em Firewall ou Controle de Acesso no painel, adiciona uma regra manualmente enquanto captura no DevTools — aí você vê exatamente quais campos são enviados no POST.

Com isso em mãos, você edita as funções `_login`, `_fetch_devices`, `_fetch_blocked`, `block_device` e `unblock_device` no `controle_rede.py` pra bater com o seu roteador.

Se o roteador tiver uma API REST com JSON fica ainda mais simples — é só trocar os parsers de HTML por `response.json()`.

---

## Observações técnicas

O roteador Vivo (interface Sophia / ZTE) tem um comportamento chato: a sessão expira logo após carregar a página de estatísticas, que é justamente a mais pesada. A solução foi usar sessões HTTP separadas pra cada tipo de requisição, fazendo login antes de cada uma.

A autenticação usa `MD5(senha:sessionId)` — o mesmo algoritmo que o JavaScript do painel web do roteador usa.
