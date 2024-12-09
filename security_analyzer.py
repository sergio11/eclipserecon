from langchain_groq import ChatGroq
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import FAISS
from langchain.chains import RetrievalQA
from langchain.text_splitter import CharacterTextSplitter
from fpdf import FPDF
import json

class SecurityAnalyzer:
    """
    A class responsible for analyzing security scan data using RAG (Retrieval-Augmented Generation) and generating
    detailed security reports with actionable insights, recommendations, and a security improvement plan.
    """
    
    def __init__(self, model_id="llama3-70b-8192", groq_api_key=None):
        """
        Initializes the SecurityAnalyzerRAG with the ChatGroq model and API key.

        Args:
            model_id (str): The ID of the model to use (default is "llama3-70b-8192").
            groq_api_key (str): The Groq API key for the model.
        """
        if not groq_api_key:
            raise ValueError("Groq API key is required.")

        # Initialize the ChatGroq model for RAG
        self.model = ChatGroq(model=model_id, temperature=0.5, api_key=groq_api_key)
        self.embeddings = HuggingFaceEmbeddings()

        print("Groq model initialized successfully.")

    def generate_report(self, scan_results: dict, pdf_path="security_report.pdf", json_path="security_report.json"):
        """
        Generates a comprehensive security report with recommendations and insights based on scan results.

        Args:
            scan_results (dict): The results of the security scan (e.g., OWASP ZAP results).
            pdf_path (str): Path to save the PDF report (default is "security_report.pdf").
            json_path (str): Path to save the JSON report (default is "security_report.json").
        
        Returns:
            str: Message indicating the completion of the report generation.
        """
        try:
            # Preprocess the scan results to create manageable chunks
            print("Splitting scan results into chunks...")
            chunks = self._process_scan_results(scan_results)

            # Create FAISS index from the chunks
            print("Creating FAISS index for document retrieval...")
            vector_store = FAISS.from_documents(chunks, self.embeddings)

            # Set up the retriever for the RAG process
            retriever = vector_store.as_retriever()
            chain = RetrievalQA.from_chain_type(self.model, retriever=retriever)

            # Define the prompt for generating the report
            print("Generating report with the model...")
            report = self._generate_report_prompt()

            # Run the analysis using the retrieval chain
            result = chain.run(report)

            # Generate PDF and JSON reports
            self._generate_pdf_report(result, pdf_path)
            self._generate_json_report(result, json_path)

            return "Report generation complete. PDF and JSON reports have been saved."

        except Exception as e:
            print(f"Error during report generation: {e}")
            return f"Error during report generation: {e}"

    def _process_scan_results(self, scan_results):
        """
        Preprocesses the scan results into chunks suitable for document processing by the model.

        Args:
            scan_results (dict): The security scan results (alerts and findings).

        Returns:
            list: A list of document chunks.
        """
        # Flattening and formatting the scan results into a readable format
        scan_text = ""
        for alert_type, alerts in scan_results.items():
            scan_text += f"{alert_type.upper()}:\n"
            for alert in alerts:
                scan_text += f"- {alert['alert']} (Risk: {alert['risk']}) at URL: {alert['url']}\n"
                scan_text += f"  Description: {alert.get('description', 'N/A')}\n"
                scan_text += f"  Solution: {alert.get('solution', 'N/A')}\n\n"

        # Split the scan results into chunks using a text splitter for easier processing
        text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
        return text_splitter.create_documents([scan_text])

    def _generate_report_prompt(self):
        """
        Creates a detailed prompt to generate the security report using the Groq model.

        Returns:
            str: The formatted prompt for generating the report.
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
        Generates a PDF report based on the analysis result.

        Args:
            analysis (str): The analysis generated by the model.
            file_path (str): Path to save the generated PDF report.
        """
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", style='B', size=16)
            pdf.cell(200, 10, txt="Security Vulnerability Report", ln=True, align='C')
            pdf.ln(10)
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt=analysis)
            pdf.output(file_path)
            print(f"PDF report generated: {file_path}")
        except Exception as e:
            print(f"Error generating PDF report: {e}")

    def _generate_json_report(self, analysis, file_path="security_report.json"):
        """
        Generates a JSON report based on the analysis result.

        Args:
            analysis (str): The analysis generated by the model.
            file_path (str): Path to save the generated JSON report.
        """
        try:
            report_data = {"analysis": analysis}
            with open(file_path, 'w') as json_file:
                json.dump(report_data, json_file, indent=4)
            print(f"JSON report generated: {file_path}")
        except Exception as e:
            print(f"Error generating JSON report: {e}")