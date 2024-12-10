from langchain_groq import ChatGroq
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import FAISS
from langchain.chains import RetrievalQA
from langchain.text_splitter import CharacterTextSplitter
from fpdf import FPDF
import json
from utils.logger import appLogger

class SecurityAnalyzer:
    """
    Analyzes security scan data using RAG and generates detailed security reports with actionable insights.
    """
    
    def __init__(self, model_id="llama3-70b-8192", groq_api_key=None):
        if not groq_api_key:
            raise ValueError("Groq API key is required.")

        self.model = ChatGroq(model=model_id, temperature=0.5, api_key=groq_api_key)
        self.embeddings = HuggingFaceEmbeddings()
        appLogger.info("🔥 Groq model initialized successfully! Ready to roll. 💻")

    def generate_report(self, scan_results: dict, pdf_path="security_report.pdf", json_path="security_report.json"):
        try:
            appLogger.debug("🔍 Splitting scan results into manageable chunks...")
            chunks = self._process_scan_results(scan_results)

            appLogger.debug("📚 Creating FAISS index for document retrieval...")
            vector_store = FAISS.from_documents(chunks, self.embeddings)

            retriever = vector_store.as_retriever()
            chain = RetrievalQA.from_chain_type(self.model, retriever=retriever)

            report = self._generate_report_prompt()

            appLogger.info("🤖 Running the analysis with retrieval chain...")
            result = chain.run(report)

            self._generate_pdf_report(result, pdf_path)
            self._generate_json_report(result, json_path)

            appLogger.info("✅ Report generation complete! Files saved successfully. 🛡️")
            return "Report generation complete. PDF and JSON reports have been saved."

        except Exception as e:
            appLogger.error(f"🚨 Error during report generation: {e}")
            return f"Error during report generation: {e}"

    def _process_scan_results(self, scan_results):
        scan_text = ""
        for alert_type, alerts in scan_results.items():
            scan_text += f"{alert_type.upper()}:\n"
            for alert in alerts:
                scan_text += f"- {alert['alert']} (Risk: {alert['risk']}) at URL: {alert['url']}\n"
                scan_text += f"  Description: {alert.get('description', 'N/A')}\n"
                scan_text += f"  Solution: {alert.get('solution', 'N/A')}\n\n"

        text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
        appLogger.debug("📖 Splitting text into chunks for processing...")
        return text_splitter.create_documents([scan_text])

    def _generate_report_prompt(self):
        return (
            "You are an AI cybersecurity expert analyzing a series of security scan results from OWASP ZAP. "
            "Your task is to generate a detailed, comprehensive security report based on the provided data. "
            "The report should include actionable insights, detailed recommendations, and a plan of action "
            "to address identified vulnerabilities and improve system security. The report should be structured as follows:\n\n"
            "1. **Executive Summary**: Provide an overview of the most critical findings and risks.\n"
            "2. **Vulnerability Analysis**: List and explain the most severe vulnerabilities identified, their potential impact, and how they can be mitigated.\n"
            "3. **Recommendations**: Provide specific, actionable recommendations to address each identified vulnerability.\n"
            "4. **Plan of Action**: Create a step-by-step plan for remediating security issues, prioritizing actions based on severity.\n"
            "5. **Conclusion**: Summarize the overall security posture and key areas for improvement.\n\n"
            "Ensure the report is clear, structured, and actionable, with the intent of guiding a system administrator in securing the system."
        )

    def _generate_pdf_report(self, analysis, file_path="security_report.pdf"):
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", style='B', size=16)
            pdf.cell(200, 10, txt="Security Vulnerability Report", ln=True, align='C')
            pdf.ln(10)
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt=analysis)
            pdf.output(file_path)
            appLogger.info(f"📄 PDF report generated: {file_path}")
        except Exception as e:
            appLogger.error(f"⚠️ Error generating PDF report: {e}")

    def _generate_json_report(self, analysis, file_path="security_report.json"):
        try:
            report_data = {"analysis": analysis}
            with open(file_path, 'w') as json_file:
                json.dump(report_data, json_file, indent=4)
            appLogger.info(f"📂 JSON report generated: {file_path}")
        except Exception as e:
            appLogger.error(f"⚠️ Error generating JSON report: {e}")