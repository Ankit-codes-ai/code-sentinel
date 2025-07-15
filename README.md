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

▶️ [Watch Demo Video](https://[Your Google Drive Video Link])  
*(Note: This is a rough cut demo — a polished version with narration/UI is coming soon)*

---

## 🛠️ Tech Stack

- **Python**
- **LangChain** (Agent framework)
- **  Gemini** (or Gemini if integrated)
- **Graphviz / Mermaid** for visual flow
- **PDF generation**, File parsers

---

## 📁 Folder Structure

```bash
src/
├── auto_remediator/
├── flowchart_generator/
├── repo_tree_generator/
├── review_caller/
├── api_config.py
main.py
requirements.txt


