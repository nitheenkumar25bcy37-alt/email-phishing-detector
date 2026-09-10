# Detailed Evaluation Questions for Your Phishing Detection System

## SECTION 1: SYSTEM ARCHITECTURE & IMPLEMENTATION

### 1.1 Backend Implementation (Flask)

**Questions about your Flask API:**

1. **Email Parsing Pipeline**
   - [ ] What library are you using for RFC 822 parsing? (email.parser? email-validator? custom?)
   - [ ] How do you handle malformed emails?
   - [ ] Do you parse both plain text and HTML email bodies?
   - [ ] How do you handle MIME multipart structures (attachments, embedded images)?
   - [ ] Are you extracting all links from HTML correctly?

2. **URL Analysis**
   - [ ] What features do you extract from URLs?
     - [ ] Domain (extracted how? regex? URL parser?)
     - [ ] TLD (.com, .ru, etc.)
     - [ ] Subdomain count
     - [ ] Domain age (from WHOIS? which service?)
     - [ ] Domain reputation (how? VirusTotal? other?)
     - [ ] URL length
     - [ ] Special characters
     - [ ] URL encoding
     - [ ] Redirect chains (do you follow them?)
     - [ ] IP address detection
   - [ ] Do you expand shortened URLs (bit.ly, tinyurl, etc.)?
   - [ ] Which external APIs do you call and how often?
   - [ ] What's the timeout for external API calls?

3. **Header Analysis (SPF/DKIM/DMARC)**
   - [ ] Do you parse raw email headers for authentication results?
   - [ ] Do you make actual DNS queries (SPF record check) or just read headers?
   - [ ] How do you handle domains that don't have SPF/DKIM/DMARC?
   - [ ] Do you validate the DMARC policy (quarantine vs. reject)?

4. **Sender & Domain Analysis**
   - [ ] How do you extract sender information (From header, friendly name)?
   - [ ] Do you compare display name vs. actual sender domain?
   - [ ] Do you check sender reputation (historical sending pattern)?
   - [ ] Do you detect suspicious sender domains (domains created recently)?

5. **Text Analysis (Body & Subject)**
   - [ ] What text features do you extract?
     - [ ] Urgent keywords (list: "verify", "urgent", "immediately", etc.)
     - [ ] Authority appeals ("from IT department", "from PayPal support")
     - [ ] Financial/payment keywords
     - [ ] Call-to-action keywords
   - [ ] Do you use NLP/embeddings (TF-IDF, Word2Vec, BERT)?
   - [ ] How do you handle different languages?

### 1.2 ML Model Details

1. **Model Architecture**
   - [ ] What model are you using? (Logistic Regression? Random Forest? Neural Network? Something else?)
   - [ ] If multiple models, how do you ensemble them?
   - [ ] How many features does the model take as input?
   - [ ] What's the model size (KB/MB)?

2. **Training Data**
   - [ ] How many samples in training set? (phishing vs. legitimate split?)
   - [ ] Where does training data come from?
     - [ ] Public datasets (PhishTank? SpamAssassin? Others?)
     - [ ] Real company emails (with consent)?
     - [ ] Synthetic data?
   - [ ] How old is the training data? (recent phishing or outdated?)
   - [ ] How do you handle class imbalance (more legitimate than phishing)?

3. **Model Performance**
   - [ ] What metrics did you measure on training/validation/test sets?
   - [ ] Show confusion matrix
   - [ ] Precision? Recall? F1-score?
   - [ ] Do you have separate metrics per phishing category?

4. **Model Interpretability**
   - [ ] Can you explain which features are important?
   - [ ] Do you have feature importance ranking?
   - [ ] For a given email, can you explain why it was flagged?

### 1.3 Risk Aggregation & Decision Making

1. **Composite Fraud Risk Index**
   - [ ] How is the 0-100 score calculated?
   - [ ] What are the weights for different signals?
     - [ ] ML model score: _% weight
     - [ ] Rule-based score: _% weight
     - [ ] Threat intelligence score: _% weight
   - [ ] How are conflicting signals handled (ML says safe, rules say phishing)?
   - [ ] Is the score calibrated to represent actual probability? (i.e., does 70 mean 70% chance of phishing?)

2. **Decision Threshold**
   - [ ] What threshold determines PHISHING vs. SUSPICIOUS vs. SAFE?
     - [ ] SAFE: score < __
     - [ ] SUSPICIOUS: __ ≤ score < __
     - [ ] PHISHING: score ≥ __
   - [ ] How did you choose these thresholds? (ROC curve? based on precision/recall tradeoff?)
   - [ ] Can users adjust sensitivity?

### 1.4 Chrome Extension & Integration

1. **Extension Functionality**
   - [ ] How does the extension communicate with backend? (REST API? WebSocket?)
   - [ ] What data does it send to backend? (full email? just headers? links only?)
   - [ ] Does it send PII or sensitive data? (How do you protect it?)
   - [ ] What's the latency from user action to risk assessment?

2. **User Interface**
   - [ ] What warning/confirmation does the user see?
   - [ ] Can users report false positives/negatives?
   - [ ] Can users whitelist/blacklist senders?
   - [ ] Does the extension show confidence score or just "PHISHING" / "SAFE"?

### 1.5 Gmail Integration

1. **Gmail API Usage**
   - [ ] Which Gmail API endpoints do you call?
   - [ ] Do you have permission to read email content? (OAuth scopes?)
   - [ ] Do you store email data or analyze only in-memory?
   - [ ] What's your API rate limit handling?

2. **Data Privacy**
   - [ ] Do you store emails in your database?
   - [ ] Do you log email content?
   - [ ] How long do you retain data?
   - [ ] Are emails encrypted in transit and at rest?

### 1.6 Forensic Ledger & Evidence Sealing

1. **Database Schema**
   - [ ] What fields do you store for each analyzed email?
     - [ ] Case ID, timestamp, sender, subject
     - [ ] ML score, rule score, final risk
     - [ ] Decision (PHISHING/SAFE/SUSPICIOUS)
     - [ ] Confidence score
     - [ ] Features extracted
   - [ ] How do you seal evidence (SHA-256 hash)?
   - [ ] Can evidence be tampered with?

2. **Dashboard & Reporting**
   - [ ] Can analysts retrieve case details?
   - [ ] Can they filter by risk level? By date? By sender?
   - [ ] Do you show feature explanations?
   - [ ] Can analysts mark cases for escalation?

---

## SECTION 2: CURRENT PERFORMANCE & TESTING

### 2.1 Test Dataset

1. **Dataset Composition**
   - [ ] Total samples? (__  phishing + __ legitimate)
   - [ ] Source of phishing emails? (public datasets? real examples?)
   - [ ] Source of legitimate emails? (real user emails? public samples?)
   - [ ] How old are the samples? (recent phishing or outdated?)
   - [ ] Any obvious phishing included? (for sanity check?)

2. **Train/Val/Test Split**
   - [ ] Training set: __ samples (__ phishing, __ benign)
   - [ ] Validation set: __ samples (__ phishing, __ benign)
   - [ ] Test set: __ samples (__ phishing, __ benign)
   - [ ] How did you split? (random? temporal? by sender?)
   - [ ] Any data leakage between sets?

### 2.2 Performance Metrics

1. **On Test Set**
   - [ ] Accuracy: ___%
   - [ ] Precision: ___%
   - [ ] Recall (Detection Rate): ___%
   - [ ] F1-Score: ___%
   - [ ] False Positive Rate: ___%
   - [ ] False Negative Rate: ___%
   - [ ] Confusion Matrix (provide the 2x2 table)

2. **Per Category**
   - [ ] Accuracy on "obvious phishing"? ___%
   - [ ] Accuracy on "URL evasion"? ___%
   - [ ] Accuracy on "webpage evasion"? ___%
   - [ ] Accuracy on "legitimate emails"? ___%

3. **Production Performance** (if tested with real users)
   - [ ] False positive rate observed? ___%
   - [ ] Did users disable the extension due to false alarms?
   - [ ] How many real phishing attempts were caught?
   - [ ] User satisfaction? (feedback collected?)

### 2.3 Latency & Performance

1. **Inference Speed**
   - [ ] Average time to analyze one email: __ ms
   - [ ] P95 latency: __ ms
   - [ ] P99 latency: __ ms
   - [ ] Bottleneck component: (URL analysis? ML? API calls?)
   - [ ] Can you analyze 1000 emails/hour? (required for production)

2. **Resource Usage**
   - [ ] Memory per email analysis: __ MB
   - [ ] Model size: __ MB
   - [ ] CPU usage (single core): __ %

### 2.4 Error Analysis

1. **False Negatives (Missed Phishing)**
   - [ ] Can you list 5-10 phishing emails your system missed?
   - [ ] What do they have in common?
   - [ ] Why did your features not fire?
   - [ ] Example: "Phishing email with HTTPS + proper SPF/DKIM + no suspicious keywords"

2. **False Positives (Legitimate Emails Flagged)**
   - [ ] Can you list 5-10 legitimate emails your system incorrectly flagged?
   - [ ] What triggered the false alarm?
   - [ ] Example: "Bank password reset email flagged due to urgent language"

3. **Weakness Analysis**
   - [ ] Which evasion techniques work against your system?
   - [ ] Which attack types are you weakest on?
   - [ ] Where do you think an attacker would focus to evade you?

---

## SECTION 3: FEATURES & SIGNALS

### 3.1 URL Features

- [ ] Domain age (days)
- [ ] Domain reputation score
- [ ] Domain registered by individuals vs. organization
- [ ] Domain TLD (.ru, .tk, etc.)
- [ ] Subdomain count
- [ ] Suspicious subdomains (contains bank name?)
- [ ] IP address vs. domain name
- [ ] URL length
- [ ] Special characters in URL
- [ ] URL encoding (% characters)
- [ ] Number of redirects
- [ ] HTTPS vs. HTTP
- [ ] Self-signed certificate
- [ ] Domain mismatch with certificate

### 3.2 Header Features

- [ ] SPF pass/fail
- [ ] DKIM pass/fail
- [ ] DMARC pass/fail
- [ ] Subject line length
- [ ] From address vs. reply-to mismatch
- [ ] Display name vs. sender address mismatch
- [ ] Unusual headers (X-Originating-IP, etc.)

### 3.3 Text Features

- [ ] Urgent keywords ("verify", "immediately", "click")
- [ ] Authority keywords ("support", "admin", "IT")
- [ ] Financial keywords ("payment", "transfer", "invoice")
- [ ] Urgency score (how urgent is the language?)
- [ ] HTML to text ratio (more HTML = suspicious)
- [ ] Misspellings (typos in brand names)
- [ ] Links to subdomains of legitimate sites

### 3.4 Email Structure Features

- [ ] Number of links
- [ ] Links matching sender domain
- [ ] Links to external domains
- [ ] Embedded images
- [ ] Executable attachments
- [ ] Archive attachments (ZIP, RAR)
- [ ] MIME complexity

### 3.5 Threat Intelligence Features

- [ ] URL in VirusTotal blacklist
- [ ] URL detected by antivirus
- [ ] Domain in URLhaus (phishing database)
- [ ] Domain/IP has bad reputation
- [ ] Email sender in known phishing campaigns

**Question: Which of the above 30+ features do you currently compute? Which are missing?**

---

## SECTION 4: KNOWN ISSUES & LIMITATIONS

1. **What doesn't work well:**
   - [ ] Homograph attacks (Cyrillic lookalike domains)?
   - [ ] Business Email Compromise (CEO fraud)?
   - [ ] Phishing from legitimate but compromised domains?
   - [ ] Image-based phishing (text hidden in images)?
   - [ ] Sophisticated HTML with hidden forms?

2. **What would break your system:**
   - [ ] External APIs down (VirusTotal, URLhaus)?
   - [ ] Very long emails (timeout)?
   - [ ] Unusual character encoding?
   - [ ] Emails with 100+ links?

3. **What users complained about:**
   - [ ] False alarm frequency?
   - [ ] Latency (extension feels slow)?
   - [ ] Too aggressive flagging?
   - [ ] Doesn't explain why email was flagged?

---

## SECTION 5: IMPROVEMENTS IMPLEMENTED SO FAR

1. **Database Persistence Bug (August 29, 2026)**
   - [ ] Fixed live_mode flag
   - [ ] Now all cases persist in forensic ledger
   - [ ] Verified with testing?

2. **Any other improvements since baseline?**
   - [ ] Feature additions?
   - [ ] Model updates?
   - [ ] API integrations?

---

## DELIVERABLES TO PROVIDE

**Please share (if possible):**

1. **Source Code Snippets**
   - Main detection pipeline (Flask endpoint)
   - Feature extraction function
   - Model prediction code

2. **Performance Data**
   - Confusion matrix
   - Sample prediction results (10 examples with ground truth)
   - Error analysis (false positives + negatives)

3. **Dataset Info**
   - Phishing data source (public? proprietary?)
   - Sample sizes per category
   - Train/val/test split methodology

4. **Model Details**
   - Model type + architecture
   - Training methodology
   - Hyperparameters
   - Feature list

5. **Documentation**
   - README or technical report
   - Architecture diagram
   - API documentation
   - Test methodology

---

## NEXT STEPS AFTER YOU PROVIDE ANSWERS

1. I'll review your implementation
2. Identify strengths and weaknesses
3. Recommend specific improvements
4. Create detailed roadmap with code examples
5. Help implement Phase 1 improvements
6. Evaluate impact and iterate

**Ready to start the deep dive?** Please share as much detail as you can about questions in Sections 1-3. I'll then provide specific, actionable feedback.
