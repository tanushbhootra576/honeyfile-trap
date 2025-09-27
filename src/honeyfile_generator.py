"""
Honeyfile Generator Module
Creates realistic decoy files to lure potential attackers.
"""

import os
import random
import string
import datetime
from typing import List, Dict, Optional
from pathlib import Path


class HoneyfileGenerator:
    """Generates various types of decoy files with realistic content."""
    
    def __init__(self, output_dir: str = "./honeyfiles"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Predefined realistic filenames
        self.filename_templates = {
            "sensitive": [
                "passwords.txt", "credentials.txt", "login_info.txt",
                "admin_access.txt", "database_config.txt", "api_keys.txt",
                "ssh_keys.txt", "backup_codes.txt", "secret_keys.txt"
            ],
            "financial": [
                "budget_2024.xlsx", "payroll.xlsx", "financial_report.pdf",
                "tax_documents.pdf", "invoice_template.docx", "expenses.xls"
            ],
            "corporate": [
                "employee_data.xlsx", "confidential_memo.docx", "project_plans.pptx",
                "client_database.xlsx", "marketing_strategy.pdf", "contracts.zip"
            ],
            "personal": [
                "personal_notes.txt", "family_photos.zip", "medical_records.pdf",
                "insurance_docs.docx", "will_testament.pdf", "diary.txt"
            ]
        }
        
        # Content templates for different file types
        self.content_templates = {
            "txt": self._generate_text_content,
            "doc": self._generate_document_content,
            "docx": self._generate_document_content,
            "pdf": self._generate_pdf_placeholder,
            "xlsx": self._generate_spreadsheet_placeholder,
            "xls": self._generate_spreadsheet_placeholder,
            "pptx": self._generate_presentation_placeholder,
            "zip": self._generate_archive_placeholder,
            "rar": self._generate_archive_placeholder
        }
    
    def generate_honeyfile(self, 
                          filename: Optional[str] = None, 
                          file_type: Optional[str] = None,
                          category: str = "sensitive") -> Path:
        """
        Generate a single honeyfile.
        
        Args:
            filename: Custom filename (if None, generates random)
            file_type: File extension type
            category: Category of file (sensitive, financial, corporate, personal)
            
        Returns:
            Path to the created honeyfile
        """
        if filename is None:
            filename = random.choice(self.filename_templates.get(category, 
                                                               self.filename_templates["sensitive"]))
        
        if file_type is None:
            file_type = filename.split('.')[-1] if '.' in filename else 'txt'
        
        # Ensure filename has correct extension
        base_name = filename.split('.')[0] if '.' in filename else filename
        full_filename = f"{base_name}.{file_type}"
        
        file_path = self.output_dir / full_filename
        
        # Generate content based on file type
        content = self._generate_content(file_type, category, base_name)
        
        # Write the file
        with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(content)
        
        # Set realistic file modification time (random time in past 30 days)
        random_time = datetime.datetime.now() - datetime.timedelta(
            days=random.randint(1, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        timestamp = random_time.timestamp()
        os.utime(file_path, (timestamp, timestamp))
        
        return file_path
    
    def generate_honeyfarm(self, 
                          count: int = 10, 
                          categories: List[str] = None) -> List[Path]:
        """
        Generate multiple honeyfiles (a "honey farm").
        
        Args:
            count: Number of files to generate
            categories: List of categories to use
            
        Returns:
            List of paths to created honeyfiles
        """
        if categories is None:
            categories = list(self.filename_templates.keys())
        
        created_files = []
        
        for _ in range(count):
            category = random.choice(categories)
            try:
                file_path = self.generate_honeyfile(category=category)
                created_files.append(file_path)
                print(f"✓ Created honeyfile: {file_path.name}")
            except Exception as e:
                print(f"✗ Failed to create honeyfile: {e}")
        
        return created_files
    
    def _generate_content(self, file_type: str, category: str, filename: str) -> str:
        """Generate content based on file type and category."""
        generator = self.content_templates.get(file_type, self._generate_text_content)
        return generator(category, filename)
    
    def _generate_text_content(self, category: str, filename: str) -> str:
        """Generate realistic text content."""
        content_generators = {
            "sensitive": self._generate_credentials_content,
            "financial": self._generate_financial_content,
            "corporate": self._generate_corporate_content,
            "personal": self._generate_personal_content
        }
        
        generator = content_generators.get(category, self._generate_generic_content)
        return generator(filename)
    
    def _generate_credentials_content(self, filename: str) -> str:
        """Generate fake credentials content."""
        usernames = ["admin", "administrator", "root", "user", "manager", "developer"]
        domains = ["company.com", "internal.local", "corp.net", "enterprise.org"]
        services = ["Database", "FTP Server", "Email", "VPN", "Admin Panel", "API Gateway"]
        
        content = f"# {filename.upper()} - CONFIDENTIAL\n"
        content += f"# Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        content += "# DO NOT SHARE OR DISTRIBUTE\n\n"
        
        for i in range(random.randint(3, 8)):
            service = random.choice(services)
            username = random.choice(usernames) + str(random.randint(1, 999))
            password = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=12))
            server = f"{random.choice(['srv', 'db', 'app'])}{random.randint(1,99)}.{random.choice(domains)}"
            
            content += f"[{service}]\n"
            content += f"Server: {server}\n"
            content += f"Username: {username}\n"
            content += f"Password: {password}\n"
            content += f"Port: {random.randint(1000, 9999)}\n\n"
        
        content += "# Security Notes:\n"
        content += "# - Change passwords monthly\n"
        content += "# - Use VPN for remote access\n"
        content += "# - Enable 2FA where possible\n"
        
        return content
    
    def _generate_financial_content(self, filename: str) -> str:
        """Generate fake financial content."""
        content = f"FINANCIAL REPORT - {filename.upper()}\n"
        content += f"Report Date: {datetime.datetime.now().strftime('%B %d, %Y')}\n"
        content += "=" * 50 + "\n\n"
        
        content += "QUARTERLY REVENUE BREAKDOWN:\n"
        for quarter in ["Q1", "Q2", "Q3", "Q4"]:
            revenue = random.randint(50000, 500000)
            content += f"{quarter} 2024: ${revenue:,}\n"
        
        content += "\nDEPARTMENT BUDGETS:\n"
        departments = ["IT", "Marketing", "Sales", "HR", "Operations", "R&D"]
        for dept in departments:
            budget = random.randint(10000, 100000)
            content += f"{dept}: ${budget:,}\n"
        
        content += "\nEXPENSE CATEGORIES:\n"
        expenses = ["Office Rent", "Utilities", "Salaries", "Software Licenses", "Travel"]
        for expense in expenses:
            amount = random.randint(5000, 50000)
            content += f"{expense}: ${amount:,}\n"
        
        return content
    
    def _generate_corporate_content(self, filename: str) -> str:
        """Generate fake corporate content."""
        content = f"CORPORATE DOCUMENT: {filename.upper()}\n"
        content += f"Classification: CONFIDENTIAL\n"
        content += f"Date: {datetime.datetime.now().strftime('%Y-%m-%d')}\n"
        content += "=" * 60 + "\n\n"
        
        content += "EMPLOYEE DIRECTORY:\n"
        for i in range(random.randint(5, 15)):
            first_names = ["John", "Jane", "Michael", "Sarah", "David", "Lisa", "Robert", "Emily"]
            last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller"]
            
            name = f"{random.choice(first_names)} {random.choice(last_names)}"
            emp_id = f"EMP{random.randint(1000, 9999)}"
            department = random.choice(["IT", "Marketing", "Sales", "HR", "Finance"])
            
            content += f"Name: {name}\n"
            content += f"Employee ID: {emp_id}\n"
            content += f"Department: {department}\n"
            content += f"Email: {name.lower().replace(' ', '.')}@company.com\n\n"
        
        return content
    
    def _generate_personal_content(self, filename: str) -> str:
        """Generate fake personal content."""
        content = f"Personal Notes - {filename}\n"
        content += f"Last Updated: {datetime.datetime.now().strftime('%B %d, %Y')}\n"
        content += "=" * 40 + "\n\n"
        
        notes = [
            "Remember to call mom this weekend",
            "Doctor appointment scheduled for next Tuesday",
            "Need to renew driver's license",
            "Wedding anniversary is coming up",
            "Book vacation tickets for summer",
            "Update insurance beneficiaries",
            "Check credit report quarterly",
            "Backup important files monthly"
        ]
        
        for note in random.sample(notes, random.randint(3, 6)):
            content += f"• {note}\n"
        
        content += "\nIMPORTANT CONTACTS:\n"
        contacts = [
            ("Dr. Smith", "555-0123"),
            ("Insurance Agent", "555-0456"),
            ("Bank Manager", "555-0789"),
            ("Lawyer", "555-0321")
        ]
        
        for name, phone in contacts:
            content += f"{name}: {phone}\n"
        
        return content
    
    def _generate_generic_content(self, filename: str) -> str:
        """Generate generic content when category is unknown."""
        content = f"Document: {filename}\n"
        content += f"Created: {datetime.datetime.now()}\n"
        content += "-" * 30 + "\n\n"
        content += "This is a confidential document containing sensitive information.\n"
        content += "Please handle with appropriate security measures.\n"
        return content
    
    def _generate_document_content(self, category: str, filename: str) -> str:
        """Generate content that appears to be a document file."""
        content = "Microsoft Word Document Placeholder\n"
        content += "This file appears to be a .doc/.docx file but is actually text.\n"
        content += f"Filename: {filename}\n"
        content += f"Category: {category}\n"
        content += "\nFor a real implementation, you would use libraries like:\n"
        content += "- python-docx for .docx files\n"
        content += "- PyPDF2 for PDF files\n"
        return content
    
    def _generate_pdf_placeholder(self, category: str, filename: str) -> str:
        """Generate PDF placeholder content."""
        return f"PDF Document Placeholder - {filename}\nThis would be binary PDF content in a real implementation."
    
    def _generate_spreadsheet_placeholder(self, category: str, filename: str) -> str:
        """Generate spreadsheet placeholder content."""
        return f"Excel Spreadsheet Placeholder - {filename}\nThis would be binary Excel content in a real implementation."
    
    def _generate_presentation_placeholder(self, category: str, filename: str) -> str:
        """Generate presentation placeholder content."""
        return f"PowerPoint Presentation Placeholder - {filename}\nThis would be binary PowerPoint content in a real implementation."
    
    def _generate_archive_placeholder(self, category: str, filename: str) -> str:
        """Generate archive placeholder content."""
        return f"Archive Placeholder - {filename}\nThis would be binary archive content in a real implementation."
    
    def list_honeyfiles(self) -> List[Path]:
        """List all existing honeyfiles."""
        if not self.output_dir.exists():
            return []
        
        return [f for f in self.output_dir.iterdir() if f.is_file()]
    
    def remove_honeyfile(self, filename: str) -> bool:
        """Remove a specific honeyfile."""
        file_path = self.output_dir / filename
        try:
            if file_path.exists():
                file_path.unlink()
                return True
            return False
        except Exception:
            return False
    
    def clear_all_honeyfiles(self) -> int:
        """Remove all honeyfiles. Returns count of removed files."""
        count = 0
        for file_path in self.list_honeyfiles():
            try:
                file_path.unlink()
                count += 1
            except Exception:
                continue
        return count


def main():
    """Demo function for testing the honeyfile generator."""
    generator = HoneyfileGenerator()
    
    print("🍯 Honeyfile Generator Demo")
    print("=" * 40)
    
    # Generate some sample honeyfiles
    print("\nGenerating honeyfiles...")
    files = generator.generate_honeyfarm(count=5)
    
    print(f"\n✓ Successfully created {len(files)} honeyfiles:")
    for file_path in files:
        print(f"  • {file_path.name}")
    
    print(f"\nHoneyfiles location: {generator.output_dir.absolute()}")


if __name__ == "__main__":
    main()