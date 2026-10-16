## 1\. Kontrakt I/O

Wejście:

```
   payload = {
    "domain": str,            # np. "mbank.pl"
    "amount": float,          # kwota transakcji
    "history_avg_amount": float # średnia kwota użytkownika
}
```

Wyjście:

```
result = {
    "verdict": str,           # "ALLOW", "BLOCK" lub "DEEP_CHECK"
    "reason_code": str | None,# np. "KNOWN_BENIGN", "BLACKLISTED_PHISH", None
    "bypass_pipeline": bool   # True jeśli kończymy ocenę, False jeśli idzie dalej
}
```

## 3\. Przepływ logiczny (Mermaid)
```
flowchart TD
    A["Wejście: Domena + Kwota"] --> B{"Domena na Białej Liście?"}
    B -- Tak --> C{"Kwota <= 1.5 * Średnia?"}
    C -- Tak --> D["ALLOW: KNOWN_BENIGN<br/>bypass=True"]
    C -- Nie --> G["DEEP_CHECK: UNUSUAL_AMOUNT<br/>bypass=False"]
    B -- Nie --> E{"Domena na Czarnej Liście?"}
    E -- Tak --> F["BLOCK: BLACKLISTED_PHISH<br/>bypass=True"]
    E -- Nie --> H["DEEP_CHECK: UNKNOWN_DOMAIN<br/>bypass=False"]

    classDef allow fill:#f0fdf4,stroke:#4ade80
    classDef block fill:#fef2f2,stroke:#f87171
    classDef check fill:#fff7ed,stroke:#fb923c
    class D allow
    class F block
    class G,H check
```

## 4\. Algorytm i logistyka danych

1.  Odszukanie w White List: Sprawdzenie domeny w pamięci podręcznej (zbiór trusted_banks.set – polskie banki, BLIK, PayU).
2.  Warunek bezpiecznego pominięcia: Jeśli domena jest zaufana, a kwota nie przekracza odchylenia od normy konta (np. $\le 1.5 \times \text{średnia}$), natychmiast zwróć ALLOW (oszczędność cykli procesora na LinuxONE)
3.  Odszukanie w Black List: Sprawdzenie hasha domeny w zbiorze phishtank.csv. Trafienie oznacza natychmiastowy BLOCK bez odpytywania dalszych modeli
4.  Fallback: Każdy inny przypadek zwraca DEEP_CHECK i przekazuje sterowanie do domain_analyzer oraz transaction_analyzer