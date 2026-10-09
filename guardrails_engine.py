"""
Universal Guardrails Engine
---------------------------
Stages : INPUT (user prompt) | OUTPUT (model reply) | TOOL_CALL | CONTEXT (RAG / web / files)
Guards : pluggable. Each guard returns Findings; engine merges them (strictest wins).
Actions: ALLOW < REDACT < REVIEW < BLOCK
Model-agnostic: works in front of / behind any LLM. Llama Guard is just one optional guard.
"""
from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import time
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Callable, Optional


logger = logging.getLogger("guardrails_engine")


# ───────────────────────── Core types ─────────────────────────
class Stage(str, Enum):
    INPUT = "input"
    OUTPUT = "output"
    TOOL_CALL = "tool_call"
    CONTEXT = "context"


class Action(IntEnum):
    ALLOW = 0
    REDACT = 1
    REVIEW = 2
    BLOCK = 3


@dataclass
class Finding:
    guard: str
    action: Action
    reason: str
    category: str = "general"
    span: Optional[tuple] = None  # (start, end) for redaction


@dataclass
class GuardResult:
    decision: str
    reason: str
    stage: str
    categories: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    text: str = ""           # safe text to forward (redacted if needed)
    latency_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.decision in ("ALLOW", "REDACT")


# ───────────────────────── Guard interface ─────────────────────────
class Guard(ABC):
    name = "guard"
    stages = {Stage.INPUT, Stage.OUTPUT, Stage.TOOL_CALL, Stage.CONTEXT}

    @abstractmethod
    def check(self, text: str, stage: Stage, history: list) -> list[Finding]: ...


# ───────────────────────── Text normalisation ─────────────────────────
_ZW = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)
_LEET = str.maketrans("0134578@$", "oleastbas")


def normalize(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).translate(_ZW)
    return re.sub(r"\s+", " ", t)


def variants(text: str) -> list[str]:
    """Original + de-leeted + decoded base64 blobs, so simple obfuscation can't dodge regex guards."""
    t = normalize(text)
    out = [t, t.translate(_LEET)]
    for blob in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", t):
        try:
            dec = base64.b64decode(blob, validate=True).decode("utf-8")
            if dec.isprintable():
                out.append(dec)
        except (binascii.Error, UnicodeDecodeError):
            pass
    return out


# ───────────────────────── Built-in guards ─────────────────────────
class LengthGuard(Guard):
    name = "length"

    def __init__(self, max_chars=10_000):
        self.max_chars = max_chars

    def check(self, text, stage, history):
        if not isinstance(text, str) or not text.strip():
            return [Finding(self.name, Action.BLOCK, "empty_or_invalid", "format")]
        if len(text) > self.max_chars:
            return [Finding(self.name, Action.BLOCK, "too_long", "format")]
        return []


class PatternGuard(Guard):
    """Regex deny-list covering 20+ threat categories. Pass your own rules: (regex, category, action)."""
    name = "pattern"

    # ── Shared fragments (kept DRY) ──
    _INSTRUCT = (r"\b(how\s+to|instructions?\s+(?:for|on|to)|steps?\s+(?:for|to)|guide\s+(?:for|on|to)"
                 r"|teach\s+me|show\s+me|tell\s+me\s+how|explain\s+how\s+to|tutorial\s+(?:for|on)"
                 r"|ways?\s+to|methods?\s+(?:to|of|for)|best\s+way\s+to|easiest\s+way\s+to"
                 r"|tips?\s+(?:for|on|to)|tricks?\s+(?:for|to)|techniques?\s+(?:for|to))\b")

    _INTENT = (r"\b(i\s+want\s+to|i\s+wanna|i(?:'|\u2019)?m\s+going\s+to|i(?:'|\u2019)?m\s+gonna"
               r"|i\s+will|i\s+plan\s+to|planning\s+to|going\s+to|gonna|i\s+need\s+to|help\s+me"
               r"|can\s+you\s+help\s+me|i\s+intend\s+to|i\s+wish\s+to|let(?:'|\u2019)?s)\b")

    _MAKE_VERBS = (r"\b(make|build|construct|assemble|synthesi[sz]e|create|produce|fabricate|craft"
                   r"|manufacture|prepare|mix|brew|cook|compound|formulate|concoct|rig)\b")

    _WEAPON_NOUNS = (r"(bomb|explosive|detonator|ied|pipe\s*bomb|molotov|grenade|land\s*mine|dynamite"
                     r"|nerve\s*agent|sarin|vx|tabun|soman|mustard\s*gas|chlorine\s*gas"
                     r"|bioweapon|biological\s*weapon|chemical\s*weapon|poison\s*gas|ricin|anthrax|botulinum"
                     r"|napalm|thermite|c[\-\s]?4|semtex|rdx|hmx|petn|tnt|anfo"
                     r"|gunpowder|black\s*powder|nitroglycerin[e]?|ammonium\s*nitrate\s*fuel"
                     r"|dirty\s*bomb|radiological\s*dispersion|nuclear\s*device"
                     r"|zip\s*gun|ghost\s*gun|3d[\-\s]?printed\s*(?:gun|firearm|weapon)"
                     r"|suppressor|silencer|bump\s*stock|auto[\-\s]?sear|switch\s*for\s*glock)s?\b")

    _VIOLENCE_VERBS = (r"\b(kill|murder|assassinate|shoot|stab|strangle|suffocate|smother|drown"
                       r"|poison|attack|assault|hurt|harm|maim|injure|beat\s+up|execute"
                       r"|slaughter|behead|decapitate|dismember|disembowel|mutilate|torture"
                       r"|kidnap|abduct|lynch|rape|molest|sodomize|traffick?)\b")

    _PERSON_TARGETS = (r"\b(someone|a\s+person|people|persons?|him|her|them|my|his|her|their"
                       r"|friend|family|wife|husband|spouse|partner|girlfriend|boyfriend"
                       r"|brother|sister|mother|father|mom|dad|son|daughter|child|children|baby"
                       r"|boss|teacher|professor|neighbor|neighbour|coworker|colleague|classmate"
                       r"|ex[\-\s]?(wife|husband|girlfriend|boyfriend|partner)|rival|enemy"
                       r"|anyone|anybody|everybody|everyone|stranger|victim)\b")

    DEFAULT_RULES = [
        # ═══════════════════════════════════════════════════════════
        # 1. WEAPONS / EXPLOSIVES / WMD / FIREARMS
        # ═══════════════════════════════════════════════════════════
        # Instructional: "how to make a bomb"
        (_INSTRUCT + r".{0,80}" + _MAKE_VERBS + r".{0,80}" + _WEAPON_NOUNS, "weapons", Action.BLOCK),
        # Standalone: "make a bomb", "create explosives"
        (_MAKE_VERBS + r".{0,40}\b(?:a\s+|an\s+|the\s+|some\s+|homemade\s+|improvised\s+|diy\s+|crude\s+)?" + _WEAPON_NOUNS,
         "weapons", Action.BLOCK),
        # Acquiring weapons: "where to buy", "how to get", "how to obtain"
        (r"\b(where\s+(?:to|can\s+i)|how\s+(?:to|can\s+i))\s+(buy|get|obtain|acquire|purchase|order|find|source)\b"
         r".{0,60}" + _WEAPON_NOUNS, "weapons", Action.BLOCK),
        # Converting firearms: "convert semi to full auto"
        (r"\b(convert|modify|alter|hack)\b.{0,40}\b(semi[\-\s]?auto|single\s*fire|pistol|rifle|gun|glock|ar[\-\s]?15)\b"
         r".{0,40}\b(full[\-\s]?auto|automatic|burst|select[\-\s]?fire)\b", "weapons", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 2. VIOLENCE / THREATS / HARM TO OTHERS
        # ═══════════════════════════════════════════════════════════
        # Direct intent: "i want to kill someone"
        (_INTENT + r".{0,40}" + _VIOLENCE_VERBS, "violence", Action.BLOCK),
        # Instructional violence: "how to kill someone"
        (_INSTRUCT + r".{0,60}" + _VIOLENCE_VERBS + r".{0,60}" + _PERSON_TARGETS, "violence", Action.BLOCK),
        # Standalone threat with target: "kill my friend", "murder him"
        (_VIOLENCE_VERBS + r".{0,40}" + _PERSON_TARGETS, "violence", Action.BLOCK),
        # Mass violence: "shoot up a school", "bomb a building"
        (r"\b(shoot\s+up|bomb|attack|blow\s+up|burn\s+down|massacre|terrorize|rampage)\b"
         r".{0,40}\b(school|church|mosque|synagogue|temple|hospital|mall|airport|train\s*station"
         r"|government|parliament|congress|white\s*house|courthouse|police\s*station"
         r"|crowd|concert|festival|stadium|arena|market|plaza|building|office)\b", "violence", Action.BLOCK),
        # Threatening/death threats
        (r"\b(i(?:'|\u2019)?ll|we(?:'|\u2019)?ll|i\s+will|we\s+will)\b.{0,30}"
         r"\b(kill|murder|destroy|eliminate|end)\s+(you|them|him|her|all\s+of\s+you)\b", "violence", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 3. SELF-HARM / SUICIDE
        # ═══════════════════════════════════════════════════════════
        (r"\b(how\s+to|ways?\s+to|methods?\s+(?:to|of|for)|i\s+want\s+to|i\s+wanna|planning\s+to|going\s+to|best\s+way\s+to)\b"
         r".{0,40}\b(kill\s+myself|commit\s+suicide|end\s+my\s+life|take\s+my\s+(?:own\s+)?life"
         r"|self[\-\s]?harm|cut\s+myself|hurt\s+myself|hang\s+myself|overdose|slit\s+my\s+wrists?)\b",
         "self_harm", Action.BLOCK),
        # Lethal dosage queries
        (r"\b(lethal|fatal|deadly|toxic|minimum\s+lethal)\s+(dose|dosage|amount|quantity)\b"
         r".{0,40}\b(of\s+)?(pills?|medication|drug|poison|chemical|substance)\b", "self_harm", Action.BLOCK),
        # Suicide methods
        (r"\b(painless|quickest|fastest|easiest|most\s+effective|foolproof|guaranteed)\b"
         r".{0,40}\b(way\s+to\s+die|suicide|death|to\s+end\s+it)\b", "self_harm", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 4. CHILD SEXUAL ABUSE MATERIAL (CSAM)
        # ═══════════════════════════════════════════════════════════
        (r"\b(child|children|minor|underage|kid|teen|preteen|infant|toddler|juvenile|boy|girl)\b"
         r".{0,60}\b(sexual|nude|explicit|naked|porn(?:ography)?|erotic|indecent|obscene|molest|groom|fondle|sodomi[zs]e)\b",
         "csam", Action.BLOCK),
        (r"\b(sexual|nude|explicit|naked|porn(?:ography)?|erotic|indecent|obscene|molest|groom|fondle|sodomi[zs]e)\b"
         r".{0,60}\b(child|children|minor|underage|kid|teen|preteen|infant|toddler|juvenile|boy|girl)s?\b",
         "csam", Action.BLOCK),
        # Standalone CSAM compound terms
        (r"\b(child|kiddie|underage|minor)\s*(porn(?:ography)?|sex|erotica|exploitation|abuse)\b", "csam", Action.BLOCK),
        # Grooming patterns
        (r"\b(groom|lure|seduce|entice)\b.{0,40}\b(child|children|minor|underage|kid|teen|boy|girl)\b",
         "csam", Action.BLOCK),
        # Age-specific sexual content
        (r"\b(\d{1,2}[\-\s]?year[\-\s]?old|young|little|small)\s+(boy|girl|child)\b"
         r".{0,40}\b(sex|naked|nude|porn|erotic|touch|fondle)\b", "csam", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 5. MALWARE / HACKING / CYBERCRIME
        # ═══════════════════════════════════════════════════════════
        (r"\b(write|create|generate|build|code|develop|make|design|program)\b"
         r".{0,40}\b(ransomware|keylogger|malware|botnet|trojan|rootkit|spyware|worm|rat[\-\s]?(?:tool|payload)"
         r"|exploit|zero[\-\s]?day|backdoor|payload|shellcode|crypter|stealer|dropper|loader"
         r"|phishing\s*(?:kit|page|tool)|credential\s*(?:harvester|stealer)|skimmer)\b",
         "malware", Action.BLOCK),
        # Hacking specific systems
        (r"\b(hack|crack|break\s+into|exploit|compromise|penetrate|bypass|brute[\-\s]?force)\b"
         r".{0,60}\b(password|account|email|bank|server|database|network|wifi|wi[\-\s]?fi"
         r"|computer|phone|instagram|facebook|snapchat|whatsapp|twitter|tiktok|gmail|icloud"
         r"|someone(?:'|\u2019)?s|his|her|their|my\s+(?:ex|boss|friend))\b",
         "hacking", Action.BLOCK),
        # DDoS / service disruption
        (r"\b(ddos|dos|flood|crash|take\s+down|bring\s+down)\b.{0,40}\b(server|website|site|service|network|game)\b",
         "hacking", Action.BLOCK),
        # SQL injection / code injection tutorials for malicious purposes
        (r"\b(how\s+to|tutorial|guide)\b.{0,30}\b(sql\s*inject|xss\s*attack|remote\s*code\s*execution"
         r"|buffer\s*overflow\s*exploit|privilege\s*escalat|reverse\s*shell)\b", "hacking", Action.REVIEW),

        # ═══════════════════════════════════════════════════════════
        # 6. ILLEGAL DRUGS / DRUG MANUFACTURING
        # ═══════════════════════════════════════════════════════════
        (_MAKE_VERBS + r".{0,60}\b(methamphetamine|meth|crystal\s*meth|fentanyl|heroin|cocaine|crack\s*cocaine"
         r"|lsd|mdma|ecstasy|ghb|pcp|ketamine|dmt|psilocybin|amphetamine"
         r"|oxycodone|oxycontin|morphine|codeine|xanax|valium)\b", "drugs", Action.BLOCK),
        (_INSTRUCT + r".{0,60}" + _MAKE_VERBS + r".{0,60}"
         r"\b(methamphetamine|meth|crystal\s*meth|fentanyl|heroin|cocaine|crack\s*cocaine"
         r"|lsd|mdma|ecstasy|ghb|pcp|dmt|amphetamine)\b", "drugs", Action.BLOCK),
        # Drug acquisition
        (r"\b(where\s+(?:to|can\s+i)|how\s+(?:to|can\s+i))\s+(buy|get|obtain|order|score|find|source)\b"
         r".{0,60}\b(meth|fentanyl|heroin|cocaine|crack|lsd|mdma|ecstasy|ghb|pcp|ketamine"
         r"|opioids?|narcotics?|controlled\s*substance)\b", "drugs", Action.BLOCK),
        # Drug lab / synthesis instructions
        (r"\b(synthesis|extraction|purification|distillation|cook|lab\s*setup)\b"
         r".{0,40}\b(meth|fentanyl|heroin|cocaine|lsd|mdma|dmt|amphetamine)\b", "drugs", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 7. HUMAN TRAFFICKING / SLAVERY / EXPLOITATION
        # ═══════════════════════════════════════════════════════════
        (r"\b(buy|sell|trade|traffick?|smuggle|transport|import|export|auction)\b"
         r".{0,60}\b(human|people|person|slave|sex\s*worker|prostitute|organ|kidney|liver|child|children"
         r"|girl|boy|woman|women|man|men)\b"
         r"(.{0,30}\b(slave|slavery|servitude|bondage|captive|forced\s*labor|sex\s*trade)\b)?",
         "trafficking", Action.BLOCK),
        # Standalone slavery / servitude
        (r"\b(sell|buy|own|keep|trade|enslave)\b.{0,30}\b(human|people|person)s?\b"
         r".{0,20}\b(as\s+)?(slave|property|chattel)s?\b", "trafficking", Action.BLOCK),
        (r"\b(force|coerce|trick|lure|recruit|abduct|kidnap)\b"
         r".{0,40}\b(into\s+)?(prostitution|sex\s*work|sex\s*trade|forced\s*labor|slavery|servitude|sweatshop)\b",
         "trafficking", Action.BLOCK),
        # Organ trafficking
        (r"\b(buy|sell|harvest|trade|traffick?)\b.{0,30}\b(organ|kidney|liver|heart|lung|cornea|blood)\b"
         r".{0,30}\b(black\s*market|illegally|underground)?\b", "trafficking", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 8. TERRORISM / RADICALIZATION / EXTREMISM
        # ═══════════════════════════════════════════════════════════
        (r"\b(join|recruit|support|fund|pledge\s+allegiance|swear\s+loyalty|fight\s+for)\b"
         r".{0,60}\b(isis|isil|daesh|al[\-\s]?qaeda|al[\-\s]?qaida|hamas|hezbollah|boko\s*haram"
         r"|taliban|al[\-\s]?shabaab|jabhat|jihad|caliphate|mujahideen)\b", "terrorism", Action.BLOCK),
        # Lone wolf / attack planning
        (r"\b(plan|execute|carry\s+out|organize|coordinate|prepare|stage|commit|launch)\b"
         r".{0,40}\b(attack|bombing|shooting|massacre|jihad|terror|assassination|rampage"
         r"|mass\s*(?:killing|shooting|murder|casualty))\b", "terrorism", Action.BLOCK),
        # Radicalization propaganda
        (r"\b(propaganda|manifesto|recruit|radicali[sz]e|indoctrinate|brainwash)\b"
         r".{0,40}\b(extremis[mt]|terrorist|jihad|white\s*supremac|neo[\-\s]?nazi|fascis[mt]|separatis[mt])\b",
         "terrorism", Action.BLOCK),
        # Financing terrorism
        (r"\b(fund|financ[ei]|donat[ei]|send\s+money|wire\s+funds|launder)\b"
         r".{0,40}\b(terror|isis|al[\-\s]?qaeda|extremis[mt]|jihad|militant)\b", "terrorism", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 9. FRAUD / FINANCIAL CRIME / SCAMS
        # ═══════════════════════════════════════════════════════════
        (_INSTRUCT + r".{0,60}\b(money\s*launder|launder\s*money|tax\s*evas|evade\s*tax"
         r"|embezzle|insider\s*trad|ponzi|pyramid\s*scheme|wire\s*fraud"
         r"|credit\s*card\s*fraud|insurance\s*fraud|bank\s*fraud|securities\s*fraud"
         r"|advance[\-\s]?fee\s*(?:scam|fraud)|romance\s*scam|pig\s*butcher"
         r"|pump\s*and\s*dump|market\s*manipulat)\b", "fraud", Action.BLOCK),
        # Creating fake / counterfeit financial instruments
        (r"\b(create|make|forge|counterfeit|fake|fabricate|print|produce)\b"
         r".{0,40}\b(money|currency|bills?|banknotes?|checks?|cheques?|credit\s*cards?"
         r"|debit\s*cards?|gift\s*cards?|vouchers?|coupons?|receipts?|invoices?"
         r"|diplomas?|certificates?|degrees?|transcripts?)\b", "fraud", Action.BLOCK),
        # Cryptocurrency scams
        (r"\b(rug\s*pull|exit\s*scam|crypto\s*scam|pump\s*and\s*dump|wash\s*trading)\b", "fraud", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 10. IDENTITY THEFT / IMPERSONATION / FORGERY
        # ═══════════════════════════════════════════════════════════
        (r"\b(steal|clone|forge|fake|fabricate|create\s+(?:a\s+)?fake|obtain\s+fake|buy\s+fake)\b"
         r".{0,40}\b(identity|passport|driver(?:'|\u2019)?s?\s*licen[sc]e|social\s*security"
         r"|birth\s*certificate|visa|green\s*card|id\s*card|ssn|national\s*id"
         r"|insurance\s*card|medical\s*records?|vaccination\s*(?:card|record|certificate))\b",
         "identity_theft", Action.BLOCK),
        # Phishing / social engineering
        (r"\b(create|build|set\s*up|design|make)\b.{0,30}\b(phishing|spear[\-\s]?phishing)\b"
         r".{0,30}\b(page|site|email|campaign|attack|kit|template)\b", "identity_theft", Action.BLOCK),
        # Doxing
        (r"\b(dox|doxx|find\s+(?:the\s+)?(?:home\s+)?address|track\s+(?:down|location)|locate|unmask|expose)\b"
         r".{0,40}" + _PERSON_TARGETS, "doxxing", Action.BLOCK),
        # Swatting
        (r"\b(swat|swatting|false\s+(?:police|bomb|emergency)\s+(?:report|call|tip))\b", "doxxing", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 11. HARASSMENT / HATE SPEECH / DISCRIMINATION
        # ═══════════════════════════════════════════════════════════
        # Slurs + dehumanization (broad categories)
        (r"\b(exterminate|genocide|ethnic\s*cleansing|purge|eradicate|wipe\s*out|eliminate)\b"
         r".{0,40}\b(race|ethnic|jews?|muslims?|christians?|blacks?|whites?|asians?|hispanics?"
         r"|immigrants?|refugees?|lgbtq?|gays?|lesbians?|trans|disabled|homeless)\b",
         "hate_speech", Action.BLOCK),
        # Supremacist / neo-nazi content generation
        (r"\b(write|create|generate|compose)\b.{0,30}\b(hate\s*speech|racist|antisemitic|islamophobic"
         r"|homophobic|transphobic|xenophobic|supremacist|neo[\-\s]?nazi)\b"
         r".{0,30}\b(speech|rant|manifesto|pamphlet|flyer|post|message|content)?\b",
         "hate_speech", Action.BLOCK),
        # Inciting violence against groups
        (r"\b(all\s+)?" + _VIOLENCE_VERBS + r".{0,30}"
         r"\b(jews?|muslims?|christians?|blacks?|whites?|asians?|hispanics?|mexicans?"
         r"|immigrants?|refugees?|lgbtq?|gays?|lesbians?|trans\s*(?:people|gender)?|disabled)\b",
         "hate_speech", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 12. SEXUAL VIOLENCE / NON-CONSENSUAL
        # ═══════════════════════════════════════════════════════════
        (r"\b(how\s+to|tips?\s+(?:for|on)|ways?\s+to|i\s+want\s+to|teach\s+me)\b"
         r".{0,40}\b(rape|sexually\s*assault|drug\s+(?:and\s+)?(?:rape|assault)|date\s*rape"
         r"|roofie|spike\s+(?:a\s+|her\s+|his\s+)?drink|grope|molest|force\s+(?:sex|intercourse))\b",
         "sexual_violence", Action.BLOCK),
        # Revenge porn / non-consensual intimate images
        (r"\b(leak|share|post|distribute|upload|publish|spread)\b"
         r".{0,40}\b(nude|naked|intimate|private|sex)\s*(photo|pic|image|video|tape|content)s?\b"
         r".{0,30}\b(without\s+consent|revenge|ex[\-\s]?(?:girlfriend|boyfriend|wife|husband|partner))?\b",
         "sexual_violence", Action.REVIEW),
        # Sextortion
        (r"\b(blackmail|extort|threaten\s+to\s+(?:share|leak|post|release))\b"
         r".{0,40}\b(nude|naked|intimate|sexual|explicit)\b", "sexual_violence", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 13. STALKING / ILLEGAL SURVEILLANCE
        # ═══════════════════════════════════════════════════════════
        (_INSTRUCT + r".{0,40}\b(stalk|spy\s+on|surveil|monitor|track|follow|watch)\b"
         r".{0,40}" + _PERSON_TARGETS, "stalking", Action.BLOCK),
        # Spyware / hidden surveillance
        (r"\b(install|plant|hide|place|put)\b.{0,30}\b(hidden|secret|covert)\b"
         r".{0,30}\b(camera|microphone|mic|gps|tracker|recording\s*device|spyware|keylogger)\b",
         "stalking", Action.BLOCK),
        (r"\b(track|monitor|spy\s+on)\b.{0,30}\b(my\s+)?(wife|husband|girlfriend|boyfriend|partner|spouse|ex)\b"
         r".{0,30}\b(without\s+(?:them|her|him)\s+knowing|secretly|covertly)?\b",
         "stalking", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 14. ANIMAL CRUELTY
        # ═══════════════════════════════════════════════════════════
        (r"\b(torture|abuse|harm|hurt|mutilate|kill|poison|starve|burn|electrocute|drown|crush)\b"
         r".{0,30}\b(a\s+|an\s+|the\s+|my\s+)?"
         r"(animal|dog|cat|puppy|kitten|pet|bird|rabbit|hamster|horse|livestock)\b",
         "animal_cruelty", Action.BLOCK),
        (r"\b(dog|cock|animal)\s*(fight|fighting|ring|baiting|pit)\b", "animal_cruelty", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 15. ARSON / PROPERTY DESTRUCTION
        # ═══════════════════════════════════════════════════════════
        (_INSTRUCT + r".{0,40}\b(set\s+fire|burn\s+down|arson|firebomb|torch|ignite|incinerate)\b"
         r".{0,40}\b(house|home|building|car|vehicle|property|church|mosque|synagogue|school|store|business)\b",
         "arson", Action.BLOCK),
        (_INTENT + r".{0,40}\b(set\s+fire\s+to|burn\s+down|torch|firebomb)\b", "arson", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 16. POISONING / CONTAMINATION / BIOTERROR
        # ═══════════════════════════════════════════════════════════
        (_INSTRUCT + r".{0,60}\b(poison|contaminate|taint|lace|spike|adulterate)\b"
         r".{0,40}\b(water\s*supply|food\s*supply|drinking\s*water|reservoir|well"
         r"|medication|medicine|food|drink|beverage)\b", "poisoning", Action.BLOCK),
        (r"\b(undetectable|untraceable|odorless|tasteless|colorless|invisible|silent)\b"
         r".{0,30}\b(poison|toxin|chemical|substance|drug|agent|venom|lethal)\b", "poisoning", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 17. EVADING LAW ENFORCEMENT
        # ═══════════════════════════════════════════════════════════
        (_INSTRUCT + r".{0,60}\b(evade|escape|flee|avoid|run\s+from|hide\s+from|elude|outrun)\b"
         r".{0,40}\b(police|cops?|law\s*enforcement|fbi|cia|dea|atf|interpol|feds?|authorities"
         r"|arrest|warrant|prosecution|detection|investigation)\b", "evading_law", Action.BLOCK),
        (r"\b(dispose|get\s+rid|destroy|hide|conceal|clean|remove|tamper\s+with)\b"
         r".{0,40}\b(evidence|murder\s*weapon|body|corpse|dna|fingerprints?|blood\s*(?:stain|evidence)"
         r"|crime\s*scene|surveillance|cctv|footage|security\s*camera)\b", "evading_law", Action.BLOCK),
        # Fake alibi
        (r"\b(create|fabricate|fake|forge|establish)\b.{0,30}\b(alibi|false\s*alibi|cover\s*story)\b",
         "evading_law", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 18. GORE / SNUFF / EXTREME CONTENT
        # ═══════════════════════════════════════════════════════════
        (r"\b(show|find|watch|send|share|generate|create)\b"
         r".{0,30}\b(gore|snuff|execution|beheading|torture|mutilation|dismemberment)\b"
         r".{0,20}\b(video|footage|film|content|image|photo|pic)s?\b", "gore", Action.BLOCK),
        (r"\b(real|actual|genuine|authentic)\b.{0,20}\b(murder|killing|death|execution|torture|rape)\b"
         r".{0,20}\b(video|footage|film|content|image|photo|pic)s?\b", "gore", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 19. NUCLEAR / RADIOLOGICAL / CBRN
        # ═══════════════════════════════════════════════════════════
        (_INSTRUCT + r".{0,60}\b(enrich|refine|process|acquire|obtain|build)\b"
         r".{0,40}\b(uranium|plutonium|centrifuge|nuclear\s*(?:material|fuel|warhead|reactor)"
         r"|radioactive\s*(?:material|source|isotope)|cesium[\-\s]?137|cobalt[\-\s]?60"
         r"|strontium[\-\s]?90|iodine[\-\s]?131|polonium)\b", "nuclear", Action.BLOCK),
        (r"\b(weaponize|weaponis[ei])\b.{0,40}\b(anthrax|ricin|botulinum|smallpox|plague|ebola"
         r"|uranium|plutonium|radioactive|biological|chemical)\b", "nuclear", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 20. ELECTION INTERFERENCE / VOTER FRAUD
        # ═══════════════════════════════════════════════════════════
        (_INSTRUCT + r".{0,60}\b(rig|manipulate|hack|tamper|interfere|steal|stuff)\b"
         r".{0,40}\b(election|vote|ballot|voting\s*machine|poll|electoral)\b", "election_fraud", Action.BLOCK),
        (r"\b(create|generate|spread|distribute|make)\b"
         r".{0,30}\b(voter|election|political|campaign)\b"
         r".{0,30}\b(disinformation|misinformation|fake\s*news|propaganda|deepfake)\b",
         "election_fraud", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 21. ESCAPE / PRISON BREAK
        # ═══════════════════════════════════════════════════════════
        (_INSTRUCT + r".{0,40}\b(escape|break\s+out|flee|get\s+out)\b"
         r".{0,30}\b(prison|jail|custody|detention|house\s*arrest|ankle\s*(?:monitor|bracelet))\b",
         "escape", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 22. ILLEGAL GAMBLING / MATCH FIXING
        # ═══════════════════════════════════════════════════════════
        (_INSTRUCT + r".{0,40}\b(fix|rig|manipulate|throw)\b"
         r".{0,30}\b(match|game|fight|race|sport|competition|contest)\b", "match_fixing", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 23. DEEPFAKES / NON-CONSENSUAL SYNTHETIC MEDIA
        # ═══════════════════════════════════════════════════════════
        (r"\b(create|make|generate|produce)\b.{0,30}\b(deepfake|deep\s*fake|face\s*swap)\b"
         r".{0,40}\b(porn|nude|naked|sex|intimate|revenge|blackmail|fraud|scam)?\b",
         "deepfake", Action.BLOCK),
        (r"\b(deepfake|deep\s*fake|face\s*swap)\b.{0,30}\b(porn|nude|naked|sex|intimate)\b",
         "deepfake", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 24. SOCIAL ENGINEERING / MANIPULATION
        # ═══════════════════════════════════════════════════════════
        (_INSTRUCT + r".{0,40}\b(manipulate|trick|deceive|con|scam|defraud|catfish|impersonate|social[\-\s]?engineer)\b"
         r".{0,40}" + _PERSON_TARGETS, "social_engineering", Action.BLOCK),
        # Romance scam scripts
        (r"\b(write|create|generate)\b.{0,30}\b(scam|fraud|con)\b"
         r".{0,30}\b(script|message|email|letter|pitch)\b", "social_engineering", Action.BLOCK),

        # ═══════════════════════════════════════════════════════════
        # 25. LOCK PICKING / PHYSICAL SECURITY BYPASS
        # ═══════════════════════════════════════════════════════════
        (_INSTRUCT + r".{0,40}\b(pick|bypass|break|defeat|crack|open)\b"
         r".{0,30}\b(lock|deadbolt|safe|vault|padlock|combination|car\s*(?:lock|door)|house\s*(?:lock|door))\b"
         r".{0,30}\b(without\s+(?:a\s+)?key|illegally|break\s*in)?\b", "physical_bypass", Action.REVIEW),
        # Breaking and entering
        (_INSTRUCT + r".{0,40}\b(break\s+into|burglarize|rob|loot|steal\s+from)\b"
         r".{0,30}\b(house|home|apartment|building|store|shop|car|vehicle|office|bank|atm)\b",
         "physical_bypass", Action.BLOCK),
    ]

    def __init__(self, rules=None):
        self.rules = [(re.compile(p, re.I | re.S), c, a) for p, c, a in (rules or self.DEFAULT_RULES)]

    def check(self, text, stage, history):
        found = []
        for v in variants(text):
            for rx, cat, act in self.rules:
                if rx.search(v):
                    found.append(Finding(self.name, act, f"matched_{cat}", cat))
            if found:
                break
        return found


class InjectionGuard(Guard):
    """Prompt-injection / jailbreak / exfiltration heuristics. Critical on CONTEXT & TOOL_CALL (indirect injection)."""
    name = "injection"
    RULES = [
        # ── Override / ignore instructions ──
        r"\bignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|original|initial|system)\s+(instructions|rules|prompts?|guidelines|directives?|constraints?)\b",
        r"\bdisregard\s+(your|all|the|any|every)\s+(instructions|rules|guidelines|system\s+prompt|safety|filters?|restrictions?|constraints?)\b",
        r"\bforget\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|original|system)\s+(instructions|rules|prompts?|context)\b",
        r"\boverride\s+(your|all|the|any|system)\s+(instructions|rules|guidelines|safety|filters?|restrictions?|settings?|protocols?)\b",
        r"\b(bypass|circumvent|disable|turn\s+off|deactivate|remove)\s+(your\s+|the\s+|all\s+)?(safety|content|ethical)\s*(filter|guard|check|restriction|guideline|policy|constraint|rule)s?\b",
        # ── System prompt extraction ──
        r"\b(reveal|show|print|repeat|output|display|leak|dump|echo|tell\s+me|give\s+me|share|disclose|expose|extract)\s+(me\s+)?(your\s+)?(hidden\s+|system\s+|initial\s+|original\s+|full\s+|secret\s+|internal\s+)?(prompt|instructions|system\s*message|rules|configuration|guidelines|context|directive|preamble)\b",
        r"\b(what\s+(?:is|are)\s+your|repeat\s+(?:back|your))\s+(system\s+)?(prompt|instructions|rules|guidelines|initial\s+(?:prompt|instructions)|hidden\s+(?:prompt|instructions))\b",
        r"\bdisclose\s+(private|confidential|secret|hidden|internal)\s+(configuration|instructions|prompt|rules|data)\b",
        # ── Roleplay / persona hijacking ──
        r"\byou\s+are\s+now\s+(dan|evil|in\s+developer\s+mode|jailbroken|unfiltered|uncensored|unrestricted|a\s+new\s+ai|no\s+longer)\b",
        r"\b(enter|activate|enable|switch\s+to|go\s+into|turn\s+on)\s+(developer|god|sudo|admin|debug|test|unrestricted|jailbreak|dan|evil|chaos|uncensored)\s*(mode)?\b",
        r"\bpretend\s+(you\s+)?(have\s+no|there\s+are\s+no|you\s+don(?:'|\u2019)?t\s+have|to\s+be)\s+(rules|restrictions|filters|safety|guidelines|limits|boundaries|an?\s+(?:evil|unrestricted|unfiltered))\b",
        r"\b(act|behave|respond|function|operate)\s+(?:as\s+(?:if|though)\s+you\s+(?:have|had|were|are)\s+no|without\s+any|without)\s+(restrictions?|rules?|filters?|safety|guidelines?|limits?|boundaries|ethical)\b",
        r"\bfrom\s+now\s+on,?\s+you\s+(will|shall|must|should|can|are\s+going\s+to)\s+(ignore|disregard|bypass|forget|override|not\s+follow)\b",
        # ── Multi-step / chained jailbreak ──
        r"\b(do\s+anything\s+now|dan\s+mode|maximum\s+mode|sigma\s+mode|omega\s+mode|alpha\s+mode|beast\s+mode|uncensored\s+mode|unleashed\s+mode)\b",
        r"\b(hypothetically|theoretically|in\s+(?:a\s+)?fiction|in\s+(?:a\s+)?(?:novel|story|movie|game)|for\s+(?:a\s+)?(?:book|screenplay|creative\s+writing))\b"
        r".{0,40}\b(how\s+(?:to|would)|explain|describe|detail|write)\b"
        r".{0,60}\b(kill|murder|bomb|poison|hack|steal|attack|exploit|make\s+(?:a\s+)?(?:bomb|weapon|drug))\b",
        # ── Token smuggling / delimiter injection ──
        r"<\s*/?\s*(system|assistant|user|s|INST|SYS)\s*>",
        r"\[\s*(system|inst|SYS|INST|/INST|/SYS)\s*\]",
        r"###\s*(system|instruction|human|assistant)\b",
        r"\b(BEGINOFTEXT|ENDOFTEXT|begin_of_text|end_of_text|end_header_id|start_header_id)\b",
        r"<<\s*SYS\s*>>",
        # ── Exfiltration / data leakage ──
        r"\bsend\s+(this|the|all|my|every|your)\b.{0,40}\b(to|via)\b.{0,40}(https?://|@|webhook|discord|telegram|slack)",
        r"\b(encode|encrypt|exfiltrate|smuggle|hide)\s+(the|this|all|your)\s+(data|info|conversation|chat|history|output|response)\b",
        r"\b(fetch|load|import|include|curl|wget|request)\s+(from\s+)?https?://",
        # ── Obfuscation attempts ──
        r"\b(base64|hex|rot13|unicode|url[\-\s]?encod[ei]|morse\s+code)\b.{0,30}\b(decode|encrypt|encode|convert|translate|interpret)\b"
        r".{0,40}\b(this|following|message|instruction|payload|command)\b",
        # ── Gaslighting the model ──
        r"\byour\s+(true|real|actual|original|intended)\s+(purpose|goal|function|objective|mission)\s+is\s+to\b",
        r"\byou\s+(?:were|are)\s+(?:actually|really|secretly)\s+(?:designed|programmed|built|created|meant)\s+to\b",
    ]

    def __init__(self, indirect_action=Action.BLOCK, direct_action=Action.REVIEW):
        self.rx = [re.compile(p, re.I | re.S) for p in self.RULES]
        self.indirect_action, self.direct_action = indirect_action, direct_action

    def check(self, text, stage, history):
        act = self.indirect_action if stage in (Stage.CONTEXT, Stage.TOOL_CALL) else self.direct_action
        for v in variants(text):
            for rx in self.rx:
                if rx.search(v):
                    return [Finding(self.name, act, "prompt_injection_pattern", "injection")]
        return []


def _luhn(num: str) -> bool:
    d = [int(c) for c in num[::-1]]
    return sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2]) % 10 == 0


class PIIGuard(Guard):
    """Detects PII/secrets. REDACT by default; mask spans in result.text."""
    name = "pii"
    PATTERNS = {
        "email": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
        "phone": r"(?<!\d)(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{3,5}\)?[\s-]?)\d{3,4}[\s-]?\d{3,4}(?!\d)",
        "aadhaar": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:\d[ -]?){13,19}\b",
        "passport": r"\b[A-Z]{1,2}\d{6,9}\b",
        "iban": r"\b[A-Z]{2}\d{2}[\s-]?[\dA-Z]{4}[\s-]?(?:[\dA-Z]{4}[\s-]?){1,7}[\dA-Z]{1,4}\b",
        "ipv4": r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b",
        "api_key": r"\b(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}"
                   r"|glpat-[A-Za-z0-9\-]{20,}|eyJ[A-Za-z0-9\-_]{30,}\.eyJ|AIza[A-Za-z0-9\-_]{35}"
                   r"|SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}|sk_live_[A-Za-z0-9]{24,}"
                   r"|rk_live_[A-Za-z0-9]{24,}|pk_live_[A-Za-z0-9]{24,}"
                   r"|AC[a-z0-9]{32}|sq0[a-z]{3}-[A-Za-z0-9\-_]{22,})\b",
        "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "aws_secret": r"\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*[A-Za-z0-9/+=]{40}\b",
        "connection_string": r"\b(?:mongodb|postgresql|mysql|redis|amqp)://[^\s]+\b",
    }

    def __init__(self, action=Action.REDACT, kinds=None):
        kinds = kinds or list(self.PATTERNS)
        self.rx = {k: re.compile(self.PATTERNS[k]) for k in kinds}
        self.action = action

    def check(self, text, stage, history):
        found = []
        for kind, rx in self.rx.items():
            for m in rx.finditer(text):
                s = m.group()
                if kind == "credit_card" and not _luhn(re.sub(r"\D", "", s)):
                    continue
                if kind == "phone" and len(re.sub(r"\D", "", s)) < 10:
                    continue
                act = Action.BLOCK if kind in ("private_key", "aws_secret", "connection_string") else self.action
                found.append(Finding(self.name, act, f"pii_{kind}", "pii", m.span()))
        return found


class ToolCallGuard(Guard):
    """Allow-list tools + block dangerous args. Feed it json.dumps({'name':..., 'args':...})."""
    name = "tool"
    stages = {Stage.TOOL_CALL}
    DANGEROUS = [
        r"\brm\s+-rf\b", r"\bdrop\s+(table|database)\b", r"\bcurl\b.+\|\s*(sh|bash)\b",
        r"/etc/(passwd|shadow)", r"\.ssh/", r"\bchmod\s+777\b", r"169\.254\.169\.254",
        r"\bsudo\b", r"\bmkfs\b", r"\bdd\s+if=", r"\b:(){ :\|:& };:\b",
        r"\bformat\s+[a-z]:\b", r"\bnet\s+user\b", r"\breg\s+(add|delete)\b",
        r"\bshutdown\s+[/-]", r"\bschtasks\b.+/create\b",
        r"\beval\s*\(", r"\bexec\s*\(", r"\b__import__\s*\(",
        r"\bos\.(system|popen|exec)", r"\bsubprocess\.(call|run|Popen)",
        r"\bimport\s+(?:os|subprocess|shutil|ctypes)\b",
        r"\bwget\b.+\|\s*(sh|bash|python)\b",
        r"\bpowershell\b.+-enc", r"\bcertutil\b.+-urlcache\b",
    ]

    def __init__(self, allowed_tools: Optional[set] = None):
        self.allowed = allowed_tools
        self.rx = [re.compile(p, re.I) for p in self.DANGEROUS]

    def check(self, text, stage, history):
        try:
            call = json.loads(text)
        except json.JSONDecodeError:
            return [Finding(self.name, Action.BLOCK, "malformed_tool_call", "tool")]
        if self.allowed is not None and call.get("name") not in self.allowed:
            return [Finding(self.name, Action.BLOCK, "tool_not_allowed", "tool")]
        blob = json.dumps(call.get("args", {}))
        if any(rx.search(blob) for rx in self.rx):
            return [Finding(self.name, Action.BLOCK, "dangerous_tool_args", "tool")]
        return []


class TopicGuard(Guard):
    """Business-policy guard: block/review off-topic or banned topics via keywords."""
    name = "topic"

    def __init__(self, banned: dict[str, list[str]], action=Action.REVIEW):
        self.banned, self.action = banned, action

    def check(self, text, stage, history):
        t = normalize(text).lower()
        return [Finding(self.name, self.action, f"banned_topic_{topic}", topic)
                for topic, kws in self.banned.items() if any(k in t for k in kws)]


class CallableGuard(Guard):
    """Wrap any function(text, stage, history) -> list[Finding] | None as a guard (custom rules, APIs, etc.)."""

    def __init__(self, fn: Callable, name="custom", stages=None):
        self.fn, self.name = fn, name
        if stages:
            self.stages = set(stages)

    def check(self, text, stage, history):
        return self.fn(text, stage, history) or []


class GuardrailsAIGuard(Guard):
    """Bridge to the guardrails-ai python package (guardrails.Guard instances)."""
    name = "guardrails_ai"
    
    def __init__(self, guard_instance, action=Action.BLOCK, name="guardrails_ai", stages=None):
        self.guard = guard_instance
        self.action = action
        self.name = name
        if stages:
            self.stages = set(stages)

    def check(self, text, stage, history):
        try:
            # Try to validate using guardrails-ai
            self.guard.validate(text)
            return []
        except Exception as exc:
            # If guardrails-ai raises a ValidationError, capture it.
            return [Finding(self.name, self.action, str(exc)[:200], self.name)]


class LlamaGuardClassifier(Guard):
    """ML safety classifier (Llama Guard 3). Lazy-loaded. Checks user turn on INPUT, user+assistant on OUTPUT."""
    name = "llama_guard"
    stages = {Stage.INPUT, Stage.OUTPUT}

    CATEGORIES = {
        "S1": "violent_crimes", "S2": "nonviolent_crimes", "S3": "sex_crimes", "S4": "child_exploitation",
        "S5": "defamation", "S6": "specialized_advice", "S7": "privacy", "S8": "intellectual_property",
        "S9": "indiscriminate_weapons", "S10": "hate", "S11": "self_harm", "S12": "sexual_content",
        "S13": "elections",
    }

    def __init__(self, model_id="meta-llama/Llama-Guard-3-1B", max_new_tokens=20, device_map="auto"):
        self.model_id, self.max_new_tokens, self.device_map = model_id, max_new_tokens, device_map
        self._tok = self._model = None
        self._load_error: str | None = None
        self._last_inference_error: str | None = None

    def _load(self):
        if self._model is not None:
            return
        if self._load_error is not None:
            raise RuntimeError(self._load_error)
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            logger.info("Loading safety classifier: %s", self.model_id)
            self._tok = AutoTokenizer.from_pretrained(self.model_id)
            self._model = AutoModelForCausalLM.from_pretrained(
                self.model_id,
                torch_dtype="auto",
                device_map=self.device_map,
                low_cpu_mem_usage=True,
            ).eval()
            logger.info("Safety classifier is ready: %s", self.model_id)
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"{type(exc).__name__}: {exc}"
            logger.exception("Safety classifier failed to load: %s", self.model_id)
            raise

    def readiness(self) -> dict[str, object]:
        if self._model is not None:
            result = {"ready": True, "state": "ready", "model": self.model_id}
            if self._last_inference_error is not None:
                result["last_error"] = self._last_inference_error
            return result
        if self._load_error is not None:
            return {
                "ready": False,
                "state": "unavailable",
                "model": self.model_id,
                "error": self._load_error.split(":", 1)[0],
            }
        return {"ready": False, "state": "not_loaded", "model": self.model_id}

    def _classify(self, turns: list[dict]) -> str:
        import torch
        # Llama Guard 3's template expects multimodal-style text-content turns.
        msgs = [
            {"role": t["role"], "content": [{"type": "text", "text": t["content"]}]}
            for t in turns
        ]
        inputs = self._tok.apply_chat_template(
            msgs,
            tokenize=True,
            add_generation_prompt=False,
            return_tensors="pt",
            return_dict=True,
        ).to(self._model.device)
        with torch.inference_mode():
            out = self._model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                do_sample=False,
                pad_token_id=0,
            )
        return self._tok.decode(out[0, inputs["input_ids"].shape[-1]:], skip_special_tokens=True).strip()

    def _parse(self, raw: str) -> list[Finding]:
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        if len(lines) == 1 and lines[0].lower() == "safe":
            return []
        if not lines:
            return [Finding(self.name, Action.REVIEW, "empty_classifier_output", "system")]
        if lines[0].lower() != "unsafe":
            return [Finding(self.name, Action.REVIEW, "unrecognized_classifier_output", "system")]
        if len(lines) != 2:
            return [Finding(self.name, Action.REVIEW, "malformed_unsafe_classifier_output", "system")]

        codes = [code.strip().upper() for code in lines[1].split(",") if code.strip()]
        if not codes or any(code not in self.CATEGORIES for code in codes):
            return [Finding(self.name, Action.REVIEW, "unrecognized_classifier_category", "system")]
        return [
            Finding(self.name, Action.BLOCK, f"unsafe_{self.CATEGORIES[code]}", self.CATEGORIES[code])
            for code in dict.fromkeys(codes)
        ]

    def check(self, text, stage, history):
        self._load()
        turns = [t for t in history if t["role"] in ("user", "assistant")][-6:]
        # ensure the text under test is the last turn with the right role
        role = "user" if stage == Stage.INPUT else "assistant"
        if not turns or turns[-1]["content"] != text:
            turns.append({"role": role, "content": text})
        # Llama Guard requires alternating roles starting with user
        clean = []
        for t in turns:
            if not clean and t["role"] != "user":
                continue
            if clean and clean[-1]["role"] == t["role"]:
                clean[-1] = t
            else:
                clean.append(t)
        try:
            findings = self._parse(self._classify(clean))
            self._last_inference_error = None
            return findings
        except Exception as exc:  # noqa: BLE001
            self._last_inference_error = type(exc).__name__
            logger.exception("Safety classifier inference failed at %s stage", stage.value)
            raise


# ───────────────────────── Engine ─────────────────────────
class GuardrailsEngine:
    def __init__(self, guards: Optional[list[Guard]] = None, fail_closed=True,
                 category_overrides: Optional[dict[str, Action]] = None, audit: Optional[Callable] = None):
        """
        fail_closed        : guard crash -> BLOCK (True) or REVIEW (False)
        category_overrides : e.g. {"self_harm": Action.REVIEW, "pii": Action.BLOCK}
        audit              : callback(GuardResult) for logging / metrics
        """
        self.guards = guards if guards is not None else self.default_guards()
        self.fail_closed = fail_closed
        self.overrides = category_overrides or {}
        self.audit = audit

    @staticmethod
    def default_guards(use_llama_guard=False, llama_guard_model_id="meta-llama/Llama-Guard-3-1B") -> list[Guard]:
        g = [LengthGuard(), PatternGuard(), InjectionGuard(), PIIGuard()]
        if use_llama_guard:
            g.append(LlamaGuardClassifier(model_id=llama_guard_model_id))
        return g

    def add(self, guard: Guard):
        self.guards.append(guard)
        return self

    # ---- public API ----
    def validate_input(self, text, history=None):
        return self._run(text, Stage.INPUT, history)

    def validate_output(self, text, history=None):
        return self._run(text, Stage.OUTPUT, history)

    def validate_tool_call(self, name: str, args: dict, history=None):
        return self._run(json.dumps({"name": name, "args": args}), Stage.TOOL_CALL, history)

    def validate_context(self, text, history=None):
        """Retrieved docs / web pages / file contents BEFORE they enter the prompt."""
        return self._run(text, Stage.CONTEXT, history)

    def protect(self, user_text: str, llm: Callable[[str], str], history=None, refusal="Sorry, I can't help with that."):
        """Full pipeline: guard input -> call any LLM -> guard output."""
        r_in = self.validate_input(user_text, history)
        if not r_in.allowed:
            return refusal, r_in, None
        reply = llm(r_in.text)
        hist = (history or []) + [{"role": "user", "content": r_in.text}]
        r_out = self.validate_output(reply, hist)
        return (r_out.text if r_out.allowed else refusal), r_in, r_out

    # ---- internals ----
    def _run(self, text, stage, history) -> GuardResult:
        t0 = time.perf_counter()
        history = history or []
        findings: list[Finding] = []

        if not isinstance(text, str):
            res = GuardResult("BLOCK", "invalid_type", stage.value, ["format"], [], "")
            return self._finish(res, t0)

        for g in self.guards:
            if stage not in g.stages:
                continue
            try:
                findings += g.check(text, stage, history)
            except Exception as exc:  # noqa: BLE001
                act = Action.BLOCK if self.fail_closed else Action.REVIEW
                findings.append(Finding(g.name, act, f"guard_error:{type(exc).__name__}", "system"))

        for f in findings:
            if f.category in self.overrides:
                f.action = self.overrides[f.category]

        top = max((f.action for f in findings), default=Action.ALLOW)
        safe_text = text
        if top == Action.REDACT:
            safe_text = self._redact(text, findings)
        elif top >= Action.REVIEW:
            safe_text = ""

        top_f = next((f for f in findings if f.action == top), None)
        res = GuardResult(
            decision=top.name,
            reason=top_f.reason if top_f else "clean",
            stage=stage.value,
            categories=sorted({f.category for f in findings if f.action > Action.ALLOW}),
            findings=findings,
            text=safe_text,
        )
        return self._finish(res, t0)

    @staticmethod
    def _redact(text, findings):
        spans = sorted({f.span + (f.reason,) for f in findings if f.span and f.action == Action.REDACT}, reverse=True)
        for s, e, reason in spans:
            text = text[:s] + f"[{reason.replace('pii_', '').upper()}]" + text[e:]
        return text

    def _finish(self, res: GuardResult, t0):
        res.latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        if self.audit:
            try:
                self.audit(res)
            except Exception:  # noqa: BLE001
                pass
        return res


# ───────────────────────── CLI demo ─────────────────────────
if __name__ == "__main__":
    import sys

    engine = GuardrailsEngine(GuardrailsEngine.default_guards(use_llama_guard="--llama" in sys.argv))
    engine.add(ToolCallGuard(allowed_tools={"search", "calculator"}))

    print("Commands:  <text> = input check | out: <text> = output check | ctx: <text> = context check | exit")
    while True:
        try:
            line = input("\n> ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if line.lower() in {"exit", "quit"}:
            break
        if line.startswith("out:"):
            r = engine.validate_output(line[4:].strip())
        elif line.startswith("ctx:"):
            r = engine.validate_context(line[4:].strip())
        else:
            r = engine.validate_input(line)
        print(f"Decision: {r.decision} | Reason: {r.reason} | Categories: {r.categories} | {r.latency_ms}ms")
        if r.decision == "REDACT":
            print("Sanitized:", r.text)
