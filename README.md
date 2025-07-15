# code-sentinel
# 🔍 Code Sentinel – GenAI-Powered Code Review Agent

**Code Sentinel** is an intelligent, agentic system designed to analyze entire code repositories.  
It performs multi-level repo review by generating logical flowcharts, scanning for security and functionality issues, and suggesting auto-remediations — powered by GenAI.

---

## 🚀 Features

- 📂 **Repo Tree Generator** – Parses and structures nested code folders, intelligently ignoring noise
- 📈 **Flowchart Generator** – Visualizes logical code flow to help reviewers understand architecture
- 🛡️ **Code Analyzer** – Performs multiple checks (security, code smells, function audit)
- 🔧 **Auto Remediator** – Suggests and applies fixes using LLM-based recommendations

---

## 📽️ Demo Video

▶️ Watch Demo Video- https://drive.google.com/file/d/1JKumV9hcOd-1TsRi7INEAqWJmrLdz1W1/view?usp=sharing
*(Note: This is a rough cut demo — a polished version with narration/UI is coming soon)*

---

## 🛠 Tech Stack

- **Python**
- **LangChain** (Agent framework)
- **  Gemini** (or Gemini if integrated)
- **Graphviz / Mermaid** for visual flow
- **PDF generation**, File parsers

---

##  Folder Structure

```bash
src/
├── auto_remediator/
├── flowchart_generator/
├── repo_tree_generator/
├── review_caller/
├── api_config.py
main.py
requirements.txt


Perfect, Ankit — here’s the **remaining part of the `README.md` in Markdown format**, ready for direct copy-paste.

Just add this **below your “Folder Structure” section**.

---

````markdown
---

**How to Run**

```bash
# Step 1: Install dependencies
pip install -r requirements.txt

# Step 2: Run the main pipeline
python main.py
````

Make sure to configure your OpenAI API key inside `src/api_config.py` or your `.env`.

---

##  Sample Outputs (coming soon)

* `outputs/flowchart.svg` – Logic flowchart of the code
* `outputs/analysis_report.pdf` – Code issue summary
* `test-project/` – Sample repo for testing

---

 **Future Improvements**


* Integrate **GitHub webhook** for real-time analysis
* Add **Slack or email notifications** for reviewer summary
* Convert to **microservice or SaaS agent**
* Fine-tune **auto-remediation logic** using more complex datasets

---

## 👤 Author

**Ankit Sharma**
🛠️ AI Engineer | GenAI Tool Builder | Intelligent Developer Tools
🔗 LinkedIn- www.linkedin.com/in/ankit-sharma-dev2226



 *If you're a startup, team lead, or hiring manager exploring agentic AI tooling — I’d love to connect or collaborate.*
  Open to freelance, contract, or full-time GenAI engineering roles.



