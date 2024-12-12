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
            chunks = self._split_log_into_chunks(scan_results)

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
        
    
    def _convert_scan_results_to_text(self, scan_results):
        """
        Converts the scan results into a structured text format suitable for analysis and report generation.
        
        This method processes the scan results, specifically the OWASP ZAP scan data, and extracts the most relevant 
        details regarding vulnerabilities, risks, URLs, descriptions, and recommended solutions. The text format produced 
        is optimized for Retrieval-Augmented Generation (RAG), ensuring that only the critical information is included 
        in a clean and compact format, reducing unnecessary characters and redundancy.
        
        Args:
            scan_results (dict): A dictionary containing the results from OWASP ZAP scans, which includes vulnerabilities,
                                scan alerts (active and passive), subdomains, and sitemaps.
        
        Returns:
            str: A formatted string containing the relevant details from the scan results, organized by type of alert 
                and vulnerability, ready for analysis or further processing.
        """
        text_parts = []

        # Ensure 'owasp' field is parsed correctly
        if 'owasp' in scan_results:
            owasp_alerts = scan_results['owasp']
            
            for host, alert_str in owasp_alerts.items():
                try:
                    alert_data = json.loads(alert_str)
                    text_parts.append(f"Host: {host}")
                    # Iterate over scan types (passive_scan, active_scan)
                    for scan_type, alert_list in alert_data.items():
                        if isinstance(alert_list, list):
                            text_parts.append(f"\n{scan_type.replace('_', ' ').title()}:")
                            # Iterate through each alert and extract relevant information
                            for alert in alert_list:
                                alert_name = alert.get('alert', 'N/A')
                                risk_level = alert.get('risk', 'N/A')
                                url = alert.get('url', 'N/A')
                                description = alert.get('description', 'N/A')
                                solution = alert.get('solution', 'N/A')
                                
                                text_parts.append(f"  Alert: {alert_name}")
                                text_parts.append(f"  Risk: {risk_level}")
                                text_parts.append(f"  URL: {url}")
                                text_parts.append(f"  Description: {description}")
                                text_parts.append(f"  Solution: {solution}")
                
                except json.JSONDecodeError:
                    text_parts.append(f"Error parsing OWASP scan results for host: {host}")

        # Process subdomains found in the scan results
        if 'subdomains' in scan_results and isinstance(scan_results['subdomains'], list):
            text_parts.append(f"\nSubdomains: {', '.join(scan_results['subdomains'])}")

        # Process sitemaps found in the scan results
        if 'sitemaps' in scan_results and isinstance(scan_results['sitemaps'], list):
            text_parts.append(f"\nSitemaps: {', '.join(scan_results['sitemaps'])}")

        # Process vulnerabilities identified in the scan results
        if 'vulnerabilities' in scan_results and isinstance(scan_results['vulnerabilities'], dict):
            text_parts.append(f"\nVulnerabilities identified:")
            for host, urls in scan_results['vulnerabilities'].items():
                if isinstance(urls, list):
                    text_parts.append(f"  Host: {host}")
                    text_parts.append(f"  URLs: {', '.join(urls)}")

        # Join and return the text parts as a single string
        return "\n\n".join(text_parts)

    def _split_log_into_chunks(self, scan_results):
        """
        Splits the log data (scan_results) into smaller chunks to facilitate better processing.

        Args:
            scan_results (dict): The scan results containing logs or data to split.

        Returns:
            list: A list of text chunks created from the scan results.
        """
        data = self._convert_scan_results_to_text(scan_results)
        appLogger.info(f"🔪data : {data} ...")
        # Split the log into chunks
        chunk_size = 4500
        text_splitter = CharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=0)
        appLogger.info(f"🔪 Splitting log into chunks of size {chunk_size}...")
        return text_splitter.create_documents([data])

    def _generate_report_prompt(self):
        """
        Generates a comprehensive prompt to be used by the Groq model for generating a detailed
        cybersecurity report based on the scan results from OWASP ZAP. The prompt guides the model 
        to prioritize critical issues, actionable recommendations, and provides a structured approach 
        to the report.

        The model is instructed to act as a cybersecurity expert, focusing on the most urgent and severe 
        vulnerabilities and providing clear, structured, and expert-level insights. It should **ignore** any 
        non-critical, irrelevant, or low-priority information that does not directly impact the system's security.
        """
        return (
            "You are an AI-powered cybersecurity expert, tasked with analyzing a series of security scan results "
            "from OWASP ZAP. Your objective is to generate a **detailed, structured, and actionable security report** "
            "based on the data provided. The report should focus specifically on the **most critical vulnerabilities**, "
            "weaknesses, and security risks identified during the scan, with clear and prioritized recommendations for remediation. "
            "You must **ignore** any non-critical, irrelevant, or low-priority findings that do not pose significant risks to the system's security.\n\n"
            
            "The report should include the following sections:\n\n"
            
            "**1. Executive Summary:**\n"
            "   - Provide a high-level overview of the most critical findings, focusing on the most severe vulnerabilities. "
            "     Include any immediate threats that require urgent attention. Do not include irrelevant or less important details.\n\n"
            
            "**2. Vulnerability Analysis:**\n"
            "   - Analyze the most significant vulnerabilities found in the scan. Explain their impact on the system, "
            "     why they are considered critical, and how they can be exploited. Prioritize vulnerabilities by severity, "
            "     with high-risk issues listed first. For each vulnerability, provide a **clear description** of the issue, "
            "     its **potential impact**, and **how to mitigate** it. Exclude vulnerabilities that have low impact or low exploitability.\n\n"
            
            "**3. Recommendations:**\n"
            "   - Provide **specific, actionable steps** that can be taken to address each identified vulnerability. "
            "     These recommendations should be practical, prioritized, and focused on improving overall system security. "
            "     Avoid including steps that are only tangentially related to security or those that have minimal impact.\n\n"
            
            "**4. Plan of Action:**\n"
            "   - Create a **step-by-step plan of action** for addressing the most urgent security issues. Prioritize actions "
            "     based on the criticality of the vulnerabilities and the potential risk to the system. Exclude actions for low-priority issues.\n\n"
            
            "**5. Conclusion:**\n"
            "   - Provide a summary of the overall security posture of the system. Highlight any areas of concern that need ongoing "
            "     monitoring and review. Make sure to reiterate the most critical vulnerabilities and the **immediate actions** "
            "     that need to be taken. Avoid mentioning issues that have no significant effect on the system's security.\n\n"
            
            "Throughout the report, ensure that the language is **clear, professional, and actionable**. The report should be "
            "designed to guide system administrators and security teams in addressing security issues effectively, prioritizing "
            "the most critical threats first. Focus on providing expert-level insights that will help in making informed decisions "
            "to secure the system and mitigate risks. Only include **high-priority, relevant findings** and **ignore** any irrelevant or "
            "less impactful data."
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
            pdf.multi_cell(0, 10, txt=analysis.get("result", ""))
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
            report_data = {"analysis": analysis.get("result", "")}
            with open(file_path, 'w') as json_file:
                json.dump(report_data, json_file, indent=4)
            appLogger.info(f"📂 JSON report generated: {file_path}")
        except Exception as e:
            appLogger.error(f"⚠️ Error generating JSON report: {e}")