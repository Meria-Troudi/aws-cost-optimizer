<div align="center">

# 🚀 AWS Cost Optimizer

**An AWS FinOps platform for analyzing cloud costs and identifying optimization opportunities.**

Analyze AWS billing data, resource configurations, and CloudWatch metrics to identify potential cost inefficiencies and generate evidence-based recommendations.

</div>

## ✨ Features

* 💰 **AWS cost analysis and cost-driver identification**
* 🔎 **Targeted resource investigation**
* 📊 **Resource, configuration, and CloudWatch analysis**
* 🔗 **Cost and resource reconciliation**
* 🧠 **Evidence-based findings and recommendations**
* 💵 **Cost-saving opportunity identification**
* 📈 **Cost dashboard and scan results**
* 🤖 **AI-assisted recommendation explanations**

## 🧰 Tech Stack

* **Backend:** Python 3.12+ · FastAPI · SQLAlchemy · Boto3
* **Frontend:** TypeScript · React · Vite
* **Database:** SQLite
* **AI:** Ollama *(optional)*

## 🛠️ Prerequisites

* **Python 3.12+**
* **Node.js 20+**
* **AWS credentials** 
* **AWS API permissions** for the services being analyzed:
  * Cost Explorer
  * EC2
  * RDS
  * EKS
  * Elastic Load Balancing
  * DynamoDB
  * WAF
  * QuickSight
  * S3
  * CloudWatch
  * CloudTrail
* **Ollama**  for AI-generated recommendation explanations

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the backend

From the repository root:

```bash
python -m uvicorn backend.main:app --reload --port 8000
```

### 3. Start the frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The frontend will be available at:

**http://localhost:5173**

## 🧭 Design Principles

* **Evidence first** — Recommendations are based on collected and validated AWS data.
* **Accurate cost attribution** — Billing amounts are attributed only when the available evidence supports the attribution.
* **Evidence-based savings** — Savings are estimated only when supported by sufficient cost and resource data.
* **Resource-level findings** — Findings remain linked to individual resources or scopes for traceability.
* **Targeted investigation** — Resource-level data is collected based on identified cost drivers rather than through unrestricted account-wide collection.
* **Evidence-gated recommendations** — Recommendations are generated only when their required evidence is available.
