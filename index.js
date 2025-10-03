    const secondsPerQuestion = 60;
    const questionsToShow = 3;

    const questionsData = [
      {
        q: "What is the definition of a Phishing attack?",
        choices: [
          "An attack using fake messages to steal sensitive information",
          "A program that protects networks from viruses",
          "A type of firewall",
          "A method to encrypt data"
        ],
        correct: 0
      },
      {
        q: "What is the difference between Encryption and Authentication?",
        choices: [
          "Encryption protects data, Authentication verifies identity",
          "They are the same thing",
          "Encryption is for devices, Authentication is for networks",
          "Authentication protects data, Encryption verifies identity"
        ],
        correct: 0
      },
      {
        q: "What does VPN stand for and what is its use?",
        choices: [
          "Virtual Private Network - secures internet connection",
          "Virus Protection Network - antivirus software",
          "Variable Programming Node - a type of database",
          "Virtual Processing Node - internet router device"
        ],
        correct: 0
      },
      {
        q: "What is a Firewall and how does it work?",
        choices: [
          "A system that monitors and controls network traffic",
          "A photo editing software",
          "A type of virus",
          "A data storage device"
        ],
        correct: 0
      },
      {
        q: "What is the difference between HTTP and HTTPS?",
        choices: [
          "HTTPS is encrypted and secure, HTTP is not encrypted",
          "HTTP is faster than HTTPS",
          "There is no difference between them",
          "HTTP is for governments only"
        ],
        correct: 0
      },
      {
        q: "What are Brute-force attacks?",
        choices: [
          "Attempting to guess passwords by trying all possibilities",
          "Physical attacks on hardware devices",
          "A type of virus",
          "A method to encrypt data"
        ],
        correct: 0
      },
      {
        q: "What does 'zero-day vulnerability' mean?",
        choices: [
          "A security flaw unknown to the vendor with no patch available",
          "A vulnerability that has been fixed",
          "An old attack method",
          "A type of malware"
        ],
        correct: 0
      },
      {
        q: "How does regular software updating help in cybersecurity?",
        choices: [
          "Closes security vulnerabilities and improves protection",
          "Makes devices slower",
          "Does not affect security",
          "Only increases battery consumption"
        ],
        correct: 0
      },
      {
        q: "What is a Ransomware attack?",
        choices: [
          "Malicious software that encrypts data and demands ransom",
          "A free protection program",
          "A type of firewall",
          "A backup method"
        ],
        correct: 0
      },
      {
        q: "What are Insider threats?",
        choices: [
          "Threats from employees or people inside the organization",
          "Viruses from the internet",
          "Attacks from other countries",
          "Malware in emails"
        ],
        correct: 0
      },
      {
        q: "What are best practices for choosing strong passwords?",
        choices: [
          "Use long passwords with mixed characters, numbers, and symbols",
          "Use your birthdate",
          "Use simple words like 'password'",
          "Use the same password everywhere"
        ],
        correct: 0
      },
      {
        q: "What is Multi-Factor Authentication (MFA) and why is it important?",
        choices: [
          "Additional security layer requiring multiple verification methods",
          "A password manager",
          "A type of encryption",
          "A firewall feature"
        ],
        correct: 0
      },
      {
        q: "How can Malware enter a system?",
        choices: [
          "Through email attachments, downloads, and infected websites",
          "Only through physical USB drives",
          "Only through phone calls",
          "Malware cannot enter systems"
        ],
        correct: 0
      },
      {
        q: "What is the difference between Virus, Malware and Worm?",
        choices: [
          "Malware is general term, Virus needs host file, Worm spreads independently",
          "They are all exactly the same",
          "Virus is harmless, Malware and Worm are dangerous",
          "Worm is a type of hardware, others are software"
        ],
        correct: 0
      },
      {
        q: "What is an SQL Injection attack?",
        choices: [
          "Inserting malicious SQL code to manipulate databases",
          "A method to speed up databases",
          "A legitimate database query",
          "A type of firewall"
        ],
        correct: 0
      },
      {
        q: "What is Cross-Site Scripting (XSS)?",
        choices: [
          "Injecting malicious scripts into trusted websites",
          "A legitimate web development technique",
          "A type of antivirus software",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "Why is data backup important for security?",
        choices: [
          "Protects against data loss from attacks or failures",
          "It is not important for security",
          "Only for increasing storage space",
          "Only businesses need backups"
        ],
        correct: 0
      },
      {
        q: "What is the principle of Least Privilege?",
        choices: [
          "Users should have minimum access rights needed for their tasks",
          "Everyone should have administrator access",
          "All users should have equal access",
          "Privilege has no relation to security"
        ],
        correct: 0
      },
      {
        q: "What is Social Engineering?",
        choices: [
          "Manipulating people to divulge confidential information",
          "A software development method",
          "A type of network protocol",
          "A hardware maintenance technique"
        ],
        correct: 0
      },
      {
        q: "What are Vulnerability scanners?",
        choices: [
          "Tools that identify security weaknesses in systems",
          "Programs that create vulnerabilities",
          "Types of viruses",
          "Network routers"
        ],
        correct: 0
      },
      {
        q: "What are DOS and DDoS attacks?",
        choices: [
          "Attacks that overwhelm systems with traffic to make them unavailable",
          "Methods to speed up internet connection",
          "Types of encryption",
          "Legitimate network testing tools"
        ],
        correct: 0
      },
      {
        q: "How can a home Wi-Fi network be secured?",
        choices: [
          "Use strong password, WPA3 encryption, change default settings",
          "Keep the default password",
          "Share password with everyone",
          "Disable all security features"
        ],
        correct: 0
      },
      {
        q: "What is the difference between Threat and Vulnerability?",
        choices: [
          "Threat is potential danger, Vulnerability is a weakness",
          "They mean exactly the same thing",
          "Threat is a weakness, Vulnerability is danger",
          "Neither relates to security"
        ],
        correct: 0
      },
      {
        q: "What is a Security Policy?",
        choices: [
          "Documented rules and procedures for protecting information assets",
          "A type of antivirus software",
          "A network protocol",
          "A hardware device"
        ],
        correct: 0
      },
      {
        q: "What is an Endpoint in security?",
        choices: [
          "End-user devices like computers, phones, tablets connected to network",
          "The end of an internet cable",
          "A type of firewall",
          "A database server"
        ],
        correct: 0
      },
      {
        q: "Why are OS updates important?",
        choices: [
          "They patch security vulnerabilities and add new protections",
          "They only change the appearance",
          "Updates are not important",
          "They only add new features"
        ],
        correct: 0
      },
      {
        q: "What is the concept of Defense in depth?",
        choices: [
          "Multiple layers of security controls throughout an IT system",
          "Using only one strong security measure",
          "A type of encryption",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is the difference between IDS and IPS?",
        choices: [
          "IDS detects threats, IPS detects and prevents them",
          "They are identical systems",
          "IDS prevents, IPS only detects",
          "Neither relates to security"
        ],
        correct: 0
      },
      {
        q: "What are the risks of using public Wi-Fi?",
        choices: [
          "Data interception, man-in-the-middle attacks, malware distribution",
          "There are no risks",
          "Only slower speeds",
          "Only limited bandwidth"
        ],
        correct: 0
      },
      {
        q: "What is a Man-in-the-Middle (MITM) attack?",
        choices: [
          "Intercepting communication between two parties without their knowledge",
          "A legitimate network management technique",
          "A type of firewall",
          "A method of encryption"
        ],
        correct: 0
      },
      {
        q: "What is the difference between symmetric and asymmetric encryption?",
        choices: [
          "Symmetric uses one key, asymmetric uses public and private keys",
          "There is no difference",
          "Symmetric uses two keys, asymmetric uses one",
          "Symmetric is always faster"
        ],
        correct: 0
      },
      {
        q: "What is PKI and why is it used?",
        choices: [
          "Public Key Infrastructure - manages digital certificates and encryption",
          "A type of virus",
          "A network protocol",
          "A database system"
        ],
        correct: 0
      },
      {
        q: "What are SSL/TLS certificates?",
        choices: [
          "Digital certificates that encrypt data between browsers and servers",
          "Physical security badges",
          "Types of passwords",
          "Network cables"
        ],
        correct: 0
      },
      {
        q: "What are dictionary attacks?",
        choices: [
          "Password cracking using common words and phrases",
          "Attacks on dictionary websites",
          "A type of encryption",
          "A legitimate authentication method"
        ],
        correct: 0
      },
      {
        q: "What is a honeypot and why is it used?",
        choices: [
          "A decoy system to detect and study attackers",
          "A type of malware",
          "A network router",
          "A password manager"
        ],
        correct: 0
      },
      {
        q: "What are Supply Chain attacks?",
        choices: [
          "Compromising trusted vendors or software to reach targets",
          "Attacks on shipping companies",
          "A type of phishing",
          "Physical theft of products"
        ],
        correct: 0
      },
      {
        q: "Why is log monitoring important?",
        choices: [
          "Detects suspicious activities and security incidents",
          "Only for storage management",
          "Not important for security",
          "Only for performance tuning"
        ],
        correct: 0
      },
      {
        q: "What does patch management mean?",
        choices: [
          "Process of identifying, testing, and applying software updates",
          "Repairing physical hardware",
          "A type of malware",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is best practice when receiving a suspicious email?",
        choices: [
          "Do not click links, verify sender, report to IT",
          "Click all links to check them",
          "Forward to all contacts",
          "Reply immediately"
        ],
        correct: 0
      },
      {
        q: "What is a credential stuffing attack?",
        choices: [
          "Using stolen credentials from one breach to access other accounts",
          "Creating strong passwords",
          "A legitimate login method",
          "A type of encryption"
        ],
        correct: 0
      },
      {
        q: "What is separation of duties?",
        choices: [
          "Dividing critical tasks among multiple people to prevent fraud",
          "Working in separate offices",
          "Using different computers",
          "A type of encryption"
        ],
        correct: 0
      },
      {
        q: "How does Full Disk Encryption help?",
        choices: [
          "Protects all data on device if stolen or lost",
          "Makes device faster",
          "Only encrypts emails",
          "Not useful for security"
        ],
        correct: 0
      },
      {
        q: "What is Spyware?",
        choices: [
          "Malware that secretly monitors and collects user information",
          "A legitimate monitoring tool",
          "A type of firewall",
          "An antivirus program"
        ],
        correct: 0
      },
      {
        q: "What is the importance of Penetration Testing?",
        choices: [
          "Identifies vulnerabilities by simulating real attacks",
          "It damages systems permanently",
          "Only for entertainment",
          "Not useful for security"
        ],
        correct: 0
      },
      {
        q: "What is a security baseline?",
        choices: [
          "Minimum security standards for systems and networks",
          "The worst possible security",
          "A type of malware",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is form-jacking?",
        choices: [
          "Injecting malicious code to steal form data like credit cards",
          "A legitimate form validation",
          "A type of firewall",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What are methods to prevent XSS attacks?",
        choices: [
          "Input validation, output encoding, Content Security Policy",
          "Disable all JavaScript",
          "Use only HTTP",
          "XSS cannot be prevented"
        ],
        correct: 0
      },
      {
        q: "What is the concept of red team and blue team?",
        choices: [
          "Red team attacks, blue team defends in security exercises",
          "Different departments in a company",
          "Types of network cables",
          "Color coding for passwords"
        ],
        correct: 0
      },
      {
        q: "What is Single Sign-On (SSO)?",
        choices: [
          "One authentication for accessing multiple applications",
          "Using only one password ever",
          "A type of malware",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is PII (Personally Identifiable Information)?",
        choices: [
          "Data that can identify a specific individual",
          "Public information only",
          "A type of encryption",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What are pros and cons of saving passwords in browsers?",
        choices: [
          "Pro: convenient, Con: less secure if device is compromised",
          "Only pros, no cons",
          "Only cons, no pros",
          "Browsers cannot save passwords"
        ],
        correct: 0
      },
      {
        q: "What does tokenization mean in data protection?",
        choices: [
          "Replacing sensitive data with non-sensitive tokens",
          "Creating digital coins",
          "A type of encryption key",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What are waterhole attacks?",
        choices: [
          "Compromising websites frequently visited by target group",
          "Attacks on water infrastructure",
          "A type of phishing email",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is pharming and how does it differ from phishing?",
        choices: [
          "Pharming redirects to fake sites via DNS, phishing uses fake messages",
          "They are exactly the same",
          "Pharming only targets farmers",
          "Phishing redirects, pharming sends emails"
        ],
        correct: 0
      },
      {
        q: "What is a security incident?",
        choices: [
          "An event that threatens confidentiality, integrity, or availability",
          "Any computer error",
          "A scheduled maintenance",
          "A software update"
        ],
        correct: 0
      },
      {
        q: "What is the role of a Password Manager?",
        choices: [
          "Securely stores and generates strong passwords",
          "Shares passwords with everyone",
          "Weakens password security",
          "Only stores usernames"
        ],
        correct: 0
      },
      {
        q: "What are the risks of sharing sensitive info on social media?",
        choices: [
          "Identity theft, social engineering, privacy loss",
          "No risks at all",
          "Only losing followers",
          "Only slower internet"
        ],
        correct: 0
      },
      {
        q: "What is bluejacking and bluesnarfing?",
        choices: [
          "Bluejacking sends messages, bluesnarfing steals data via Bluetooth",
          "Both are legitimate Bluetooth features",
          "Types of Wi-Fi attacks",
          "Methods to improve Bluetooth range"
        ],
        correct: 0
      },
      {
        q: "What does bricking mean in devices?",
        choices: [
          "Rendering a device completely unusable",
          "Making a device stronger",
          "A legitimate update process",
          "A type of encryption"
        ],
        correct: 0
      },
      {
        q: "What is a rootkit?",
        choices: [
          "Malware that provides privileged access while hiding its presence",
          "A legitimate system tool",
          "A type of antivirus",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is a logic bomb?",
        choices: [
          "Malicious code triggered by specific conditions or time",
          "A legitimate debugging tool",
          "A type of firewall",
          "A network device"
        ],
        correct: 0
      },
      {
        q: "What is the difference between authentication and authorization?",
        choices: [
          "Authentication verifies identity, authorization determines access rights",
          "They are the same thing",
          "Authentication grants access, authorization verifies identity",
          "Neither relates to security"
        ],
        correct: 0
      },
      {
        q: "What are methods to secure laptops?",
        choices: [
          "Strong passwords, encryption, cable locks, disable auto-login",
          "Leave unlocked for convenience",
          "Share with everyone",
          "Never update software"
        ],
        correct: 0
      },
      {
        q: "What is certificate pinning?",
        choices: [
          "Associating a host with their expected certificate or public key",
          "Physical attachment of certificates",
          "A type of password",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is application sandboxing?",
        choices: [
          "Isolating applications to limit their access and damage potential",
          "Testing apps at the beach",
          "A type of malware",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What are BYOD policies and how do they affect security?",
        choices: [
          "Bring Your Own Device policies manage personal devices accessing company resources",
          "Buy Your Own Drinks policies",
          "A type of encryption",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is secure coding and why is it important?",
        choices: [
          "Writing software with security considerations to prevent vulnerabilities",
          "Encrypting all code files",
          "Using passwords in code",
          "A type of malware"
        ],
        correct: 0
      },
      {
        q: "What are clickjacking attacks?",
        choices: [
          "Tricking users into clicking hidden malicious elements",
          "A legitimate UI design technique",
          "A type of mouse",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "How can APIs be secured?",
        choices: [
          "Authentication, rate limiting, input validation, encryption",
          "APIs cannot be secured",
          "Make them public to everyone",
          "Remove all security features"
        ],
        correct: 0
      },
      {
        q: "What does data leakage mean?",
        choices: [
          "Unauthorized transmission of data from within an organization",
          "Normal data transfer",
          "A type of encryption",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is spoofing?",
        choices: [
          "Impersonating another device or user to gain access",
          "A legitimate network test",
          "A type of firewall",
          "A method of encryption"
        ],
        correct: 0
      },
      {
        q: "What is the difference between white hat, black hat, and grey hat hackers?",
        choices: [
          "White hat: ethical, black hat: malicious, grey hat: in between",
          "They all wear different colored hats",
          "All are equally malicious",
          "No difference at all"
        ],
        correct: 0
      },
      {
        q: "What is threat modeling?",
        choices: [
          "Identifying and assessing potential threats to prioritize defenses",
          "Creating 3D models of threats",
          "A type of malware",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is SIEM and what does it do?",
        choices: [
          "Security Information and Event Management - collects and analyzes security data",
          "A type of firewall",
          "A network router",
          "An email protocol"
        ],
        correct: 0
      },
      {
        q: "What is DLP (Data Loss Prevention)?",
        choices: [
          "Technologies to prevent unauthorized data transmission",
          "A type of backup software",
          "A network protocol",
          "A type of malware"
        ],
        correct: 0
      },
      {
        q: "What are best practices for securing web servers?",
        choices: [
          "Regular updates, strong authentication, disable unnecessary services, SSL/TLS",
          "Leave default settings",
          "Disable all security",
          "Never update software"
        ],
        correct: 0
      },
      {
        q: "What is a botnet?",
        choices: [
          "Network of infected computers controlled remotely for malicious purposes",
          "A legitimate server network",
          "A type of firewall",
          "An antivirus program"
        ],
        correct: 0
      },
      {
        q: "What does rate limiting mean and why is it used?",
        choices: [
          "Restricting number of requests to prevent abuse and DoS attacks",
          "Slowing down internet speed",
          "A type of encryption",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is CAPTCHA and how does it help?",
        choices: [
          "Challenge to distinguish humans from bots",
          "A type of password",
          "A network protocol",
          "A type of malware"
        ],
        correct: 0
      },
      {
        q: "What is privilege escalation?",
        choices: [
          "Gaining higher access rights than initially granted",
          "A legitimate promotion process",
          "A type of encryption",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is ARP spoofing?",
        choices: [
          "Sending fake ARP messages to intercept network traffic",
          "A legitimate network configuration",
          "A type of firewall",
          "A method of encryption"
        ],
        correct: 0
      },
      {
        q: "What is hashing and how is it different from encryption?",
        choices: [
          "Hashing is one-way, encryption is reversible",
          "They are exactly the same",
          "Hashing is reversible, encryption is one-way",
          "Neither is used in security"
        ],
        correct: 0
      },
      {
        q: "What is salt in password storage?",
        choices: [
          "Random data added to passwords before hashing",
          "A type of seasoning for servers",
          "A network protocol",
          "A type of encryption key"
        ],
        correct: 0
      },
      {
        q: "What are the risks of using pirated software?",
        choices: [
          "Malware infection, no updates, legal issues, no support",
          "No risks at all",
          "Only legal issues",
          "Only lack of support"
        ],
        correct: 0
      },
      {
        q: "What is session hijacking?",
        choices: [
          "Stealing user's session token to impersonate them",
          "A legitimate session management",
          "A type of firewall",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is CSP (Content Security Policy)?",
        choices: [
          "HTTP header that helps prevent XSS and injection attacks",
          "A type of antivirus",
          "A network protocol",
          "A physical security policy"
        ],
        correct: 0
      },
      {
        q: "What are patch management tools?",
        choices: [
          "Software that automates finding and applying updates",
          "Tools to create patches",
          "Types of malware",
          "Network routers"
        ],
        correct: 0
      },
      {
        q: "What is ethical hacking?",
        choices: [
          "Authorized testing to find vulnerabilities before attackers do",
          "Hacking for fun",
          "Illegal hacking activities",
          "A type of malware"
        ],
        correct: 0
      },
      {
        q: "What is the difference between live monitoring and disaster recovery planning?",
        choices: [
          "Live monitoring detects threats in real-time, DRP prepares for major incidents",
          "They are the same thing",
          "DRP monitors, live monitoring plans",
          "Neither relates to security"
        ],
        correct: 0
      },
      {
        q: "What are methods to secure databases?",
        choices: [
          "Encryption, access controls, regular backups, SQL injection prevention",
          "Leave databases public",
          "Use default passwords",
          "Never update database software"
        ],
        correct: 0
      },
      {
        q: "What is security awareness training?",
        choices: [
          "Educating users about security threats and best practices",
          "A type of antivirus software",
          "A network protocol",
          "A type of firewall"
        ],
        correct: 0
      },
      {
        q: "What is digital forensics?",
        choices: [
          "Investigating and analyzing digital evidence from cyber incidents",
          "A type of encryption",
          "A network protocol",
          "A photo editing technique"
        ],
        correct: 0
      },
      {
        q: "What is MITRE ATT&CK and why do professionals use it?",
        choices: [
          "Framework documenting adversary tactics and techniques for threat analysis",
          "A type of malware",
          "A network protocol",
          "An antivirus program"
        ],
        correct: 0
      },
      {
        q: "What does attack surface mean?",
        choices: [
          "All possible points where an attacker can enter or extract data",
          "Physical surface of devices",
          "A type of malware",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What is SIEM correlation?",
        choices: [
          "Analyzing relationships between security events to identify threats",
          "A type of encryption",
          "A network protocol",
          "A hardware device"
        ],
        correct: 0
      },
      {
        q: "What are the OWASP Top 10 guidelines?",
        choices: [
          "List of most critical web application security risks",
          "Top 10 antivirus programs",
          "Top 10 network protocols",
          "Top 10 programming languages"
        ],
        correct: 0
      },
      {
        q: "What is threat intelligence?",
        choices: [
          "Information about current and emerging threats to inform defenses",
          "A type of artificial intelligence",
          "A network protocol",
          "A type of malware"
        ],
        correct: 0
      },
      {
        q: "What are components of a Disaster Recovery Plan (DRP)?",
        choices: [
          "Backup procedures, recovery strategies, emergency contacts, testing plans",
          "Only backup procedures",
          "Only emergency contacts",
          "DRP has no components"
        ],
        correct: 0
      },
      {
        q: "What is the Zero Trust security model?",
        choices: [
          "Never trust, always verify - no automatic trust based on location",
          "Trust everyone inside the network",
          "A type of encryption",
          "A network protocol"
        ],
        correct: 0
      },
      {
        q: "What are benefits of Role-Based Access Control (RBAC)?",
        choices: [
          "Simplifies permissions management and enforces least privilege",
          "Gives everyone full access",
          "Makes security more complex",
          "Has no benefits"
        ],
        correct: 0
      },
      {
        q: "What are the risks related to IoT?",
        choices: [
          "Weak security, data privacy issues, large attack surface, botnet recruitment",
          "No risks at all",
          "Only high power consumption",
          "Only connectivity issues"
        ],
        correct: 0
      },
      {
        q: "What is multi-tenant cloud risk?",
        choices: [
          "Multiple customers sharing resources may lead to data leakage or breaches",
          "No risks in cloud computing",
          "Only cost-related risks",
          "Only performance issues"
        ],
        correct: 0
      }
    ];

    const board = document.getElementById('board');
    const startBtn = document.getElementById('startBtn');
    const newBtn = document.getElementById('newBtn');
    const resetBtn = document.getElementById('resetBtn');
    const scoreBoard = document.getElementById('scoreBoard');
    const scoreText = document.getElementById('scoreText');

    let activeTimers = [];
    let correctAnswers = 0;
    let totalQuestions = 0;

    function pickRandomIndices(n) {
      const idx = new Set();
      while (idx.size < n && idx.size < questionsData.length) {
        idx.add(Math.floor(Math.random() * questionsData.length));
      }
      return Array.from(idx);
    }

    function clearBoard() {
      activeTimers.forEach(t => clearInterval(t.interval));
      activeTimers = [];
      board.innerHTML = '';
      correctAnswers = 0;
      totalQuestions = 0;
      scoreBoard.style.display = 'none';
    }

    function updateScore() {
      scoreText.textContent = correctAnswers + '/' + totalQuestions;
      scoreBoard.style.display = 'block';
    }

    function startQuiz() {
      clearBoard();
      const picks = pickRandomIndices(questionsToShow);
      picks.forEach(i => renderQuestionCard(questionsData[i]));
    }

    function renderQuestionCard(data) {
      const card = document.createElement('div');
      card.className = 'card';

      const q = document.createElement('div');
      q.className = 'question';
      q.textContent = data.q;

      const choicesDiv = document.createElement('div');
      choicesDiv.className = 'choices';

      let answered = false;

      data.choices.forEach((choice, idx) => {
        const choiceEl = document.createElement('div');
        choiceEl.className = 'choice';
        choiceEl.textContent = choice;

        choiceEl.addEventListener('click', () => {
          if (answered) return;

          answered = true;
          totalQuestions++;

          const allChoices = choicesDiv.querySelectorAll('.choice');
          allChoices.forEach(c => c.classList.add('disabled'));

          if (idx === data.correct) {
            choiceEl.classList.add('correct');
            resultBadge.textContent = '✓ Correct Answer';
            resultBadge.className = 'result-badge correct';
            correctAnswers++;
          } else {
            choiceEl.classList.add('wrong');
            allChoices[data.correct].classList.add('correct');
            resultBadge.textContent = '✗ Wrong Answer';
            resultBadge.className = 'result-badge wrong';
          }

          updateScore();
        });

        choicesDiv.appendChild(choiceEl);
      });

      const timerBar = document.createElement('div');
      timerBar.className = 'timer-bar';

      const resultBadge = document.createElement('div');
      resultBadge.className = 'result-badge';
      resultBadge.style.visibility = 'hidden';

      const timerEl = document.createElement('div');
      timerEl.className = 'timer';
      timerEl.textContent = formatTime(secondsPerQuestion);

      timerBar.appendChild(resultBadge);
      timerBar.appendChild(timerEl);

      card.appendChild(q);
      card.appendChild(choicesDiv);
      card.appendChild(timerBar);

      board.appendChild(card);

      let remaining = secondsPerQuestion;
      const interval = setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) {
          timerEl.textContent = 'Time Over';
          clearInterval(interval);

          if (!answered) {
            totalQuestions++;
            const allChoices = choicesDiv.querySelectorAll('.choice');
            allChoices.forEach(c => c.classList.add('disabled'));
            allChoices[data.correct].classList.add('correct');
            resultBadge.textContent = '⏱ Time Over';
            resultBadge.className = 'result-badge wrong';
            resultBadge.style.visibility = 'visible';
            updateScore();
          }

          setTimeout(() => {
            card.classList.add('fade-out');
            setTimeout(() => {
              if (card.parentNode) card.parentNode.removeChild(card);
            }, 600);
          }, 2000);
        } else {
          timerEl.textContent = formatTime(remaining);
          if (!answered) {
            resultBadge.style.visibility = 'hidden';
          } else {
            resultBadge.style.visibility = 'visible';
          }
        }
      }, 1000);

      activeTimers.push({ interval });
    }

    function formatTime(sec) {
      const s = Math.max(0, Math.floor(sec));
      return (s < 10 ? '0' + s : s) + 's';
    }

    startBtn.addEventListener('click', startQuiz);
    newBtn.addEventListener('click', startQuiz);
    resetBtn.addEventListener('click', clearBoard);
    document.addEventListener('keydown', e => { if (e.key === 'Enter') startQuiz(); });
  