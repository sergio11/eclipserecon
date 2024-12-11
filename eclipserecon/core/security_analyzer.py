from langchain_groq import ChatGroq
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.chains import RetrievalQA
from langchain.text_splitter import CharacterTextSplitter
from fpdf import FPDF
import json
import os
from dotenv import load_dotenv
from eclipserecon.utils.logger import appLogger

class SecurityAnalyzer:
    """
    SecurityAnalyzer is a class designed to analyze security scan results using Retrieval-Augmented Generation (RAG) 
    and generate detailed security reports with actionable insights. This class integrates with Groq's Chat API for 
    advanced analysis and leverages FAISS for efficient document retrieval.

    Attributes:
        model (ChatGroq): A Groq language model instance for generating insights and analyses.
        embeddings (HuggingFaceEmbeddings): Embedding model used for text representation.
    """
    
    def __init__(self):
        """
        Initializes the SecurityAnalyzer class by loading the Groq API key and model ID from environment variables 
        and configuring the necessary components (Groq model and HuggingFace embeddings) for security analysis.

        This method ensures that both the Groq API key and model ID are available in the environment variables.
        If not, an error will be raised.

        Raises:
            ValueError: If the Groq API key or model ID is not found in the environment variables.
        """
        load_dotenv()

        groq_api_key = os.getenv("GROQ_API_KEY")
        model_id = os.getenv("MODEL_ID")

        if not groq_api_key or not model_id:
            raise ValueError("GROQ API key and Model ID are required. Ensure they are defined in the .env file.")

        self.model = ChatGroq(model=model_id, temperature=1, api_key=groq_api_key)
        self.embeddings = HuggingFaceEmbeddings()
        appLogger.info("🔥 Groq model initialized successfully! Ready to roll. 💻")

    def generate_report(self, scan_results: dict, pdf_path="security_report.pdf", json_path="security_report.json"):
        """
        Generates a detailed security report based on the scan results. The report includes actionable insights, 
        vulnerability analysis, and recommendations for improving security.

        The method processes the scan results, generates a retrieval-based chain using the Groq model for 
        analysis, and creates both a PDF and a JSON report.

        Args:
            scan_results (dict): A dictionary containing the scan results, where each key represents a type of alert 
                                  and each value is a list of alerts for that type.
            pdf_path (str, optional): Path where the generated PDF report will be saved. Defaults to "security_report.pdf".
            json_path (str, optional): Path where the generated JSON report will be saved. Defaults to "security_report.json".

        Returns:
            str: A message indicating whether the report generation was successful or if an error occurred.
        """
        try:
            appLogger.debug("🔍 Splitting scan results into manageable chunks...")
            chunks = self._process_scan_results(scan_results)

            appLogger.debug("📚 Creating FAISS index for document retrieval...")
            vector_store = FAISS.from_documents(chunks, self.embeddings)

            retriever = vector_store.as_retriever()
            chain = RetrievalQA.from_chain_type(self.model, retriever=retriever)

            report = self._generate_report_prompt()

            appLogger.info("🤖 Running the analysis with retrieval chain...")
            result = chain.invoke(report)

            self._generate_pdf_report(result, pdf_path)
            self._generate_json_report(result, json_path)

            appLogger.info("✅ Report generation complete! Files saved successfully. 🛡️")
            return "Report generation complete. PDF and JSON reports have been saved."

        except Exception as e:
            appLogger.error(f"🚨 Error during report generation: {e}")
            return f"Error during report generation: {e}"

    def _process_scan_results(self, scan_results):
        """
        Processes the raw scan results into text chunks suitable for analysis. Each type of alert is formatted and 
        converted into a structured text format, which is then split into smaller chunks for processing.

        Args:
            scan_results (dict): A dictionary containing the scan results, where each key is a type of alert and 
                                  each value is a list of alerts for that type.

        Returns:
            list: A list of text documents representing the processed scan results, split into manageable chunks.
        """
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
        """
        Generates the prompt to be used by the Groq model for generating a detailed security report. The prompt 
        instructs the model to analyze the scan results and produce a comprehensive report with actionable insights.

        Returns:
            str: The prompt used for generating the security report.
        """
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
        """
        Generates a PDF report based on the analysis results and saves it to the specified file path.

        Args:
            analysis (dict): The analysis results containing actionable insights and findings.
            file_path (str, optional): Path where the PDF report will be saved. Defaults to "security_report.pdf".
        """
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", style='B', size=16)
            pdf.cell(200, 10, txt="Security Vulnerability Report", ln=True, align='C')
            pdf.ln(10)
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt=analysis.get("results", ""))
            pdf.output(file_path)
            appLogger.info(f"📄 PDF report generated: {file_path}")
        except Exception as e:
            appLogger.error(f"⚠️ Error generating PDF report: {e}")

    def _generate_json_report(self, analysis, file_path="security_report.json"):
        """
        Generates a JSON report based on the analysis results and saves it to the specified file path.

        Args:
            analysis (dict): The analysis results containing actionable insights and findings.
            file_path (str, optional): Path where the JSON report will be saved. Defaults to "security_report.json".
        """
        try:
            report_data = {"analysis": analysis.get("results", "")}
            with open(file_path, 'w') as json_file:
                json.dump(report_data, json_file, indent=4)
            appLogger.info(f"📂 JSON report generated: {file_path}")
        except Exception as e:
            appLogger.error(f"⚠️ Error generating JSON report: {e}")