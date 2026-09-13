import os
import frontmatter
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_community.embeddings.fastembed import FastEmbedEmbeddings
from dotenv import load_dotenv

load_dotenv()


class PolicyDatabase:

    def __init__(self, persist_directory: str = "./chroma_data"):
        self.embeddings = FastEmbedEmbeddings(
            model_name="BAAI/bge-small-en-v1.5"
        )

        self.persist_directory = persist_directory
        self.vector_store = None

        self.score_threshold = float(
            os.getenv("POLICY_SCORE_THRESHOLD", "0.45")
        )

        self._initialize_db()

    def _initialize_db(self):

        if (
            os.path.exists(self.persist_directory)
            and os.listdir(self.persist_directory)
        ):
            self.vector_store = Chroma(
                persist_directory=self.persist_directory,
                embedding_function=self.embeddings,
                collection_name="trust_gateway_policies",
                collection_metadata={"hnsw:space": "cosine"}
            )

        else:
            self._build_initial_db()

    def _build_initial_db(self):
        policies_dir = "app/security/policies"
        documents = []

        if not os.path.exists(policies_dir):
            raise RuntimeError(f"Policy directory not found: {policies_dir}")

        # Initialize the splitter to break on paragraphs, headers, and bullet points
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=300, 
            chunk_overlap=0,
            separators=["\n\n", "\n### ", "\n- ", "\n* "]
        )

        for filename in os.listdir(policies_dir):
            if filename.endswith(".md"):
                filepath = os.path.join(policies_dir, filename)
                
                with open(filepath, "r", encoding="utf-8") as f:
                    post = frontmatter.load(f)
                    
                    # Extract parent metadata from the frontmatter
                    parent_metadata = {
                        "policy_id": post.get("policy_id", "UNKNOWN"),
                        "category": post.get("category", "GENERAL"),
                        "severity": post.get("severity", "MEDIUM"),
                        "action": post.get("action", "BLOCK")
                    }
                    
                    # Split the whole document into atomic rule chunks
                    chunks = text_splitter.split_text(post.content.strip())
                    
                    for chunk in chunks:
                        # Skip empty chunks
                        if not chunk.strip():
                            continue
                            
                        # Create a separate Document for every rule, cloning the parent metadata
                        doc = Document(
                            page_content=chunk.strip(),
                            metadata=parent_metadata.copy()
                        )
                        documents.append(doc)

        if not documents:
            raise RuntimeError(f"No policy files found in {policies_dir}")

        self.vector_store = Chroma.from_documents(
            documents=documents,
            embedding=self.embeddings,
            persist_directory=self.persist_directory,
            collection_name="trust_gateway_policies",
            collection_metadata={"hnsw:space": "cosine"}
        )

    def retrieve_relevant_policies(
        self,
        query: str,
        category: str,
        k: int = 2
    ):

        results_with_scores = (
            self.vector_store
            .similarity_search_with_relevance_scores(
                query=query,
                k=k,
                filter={"category": category}
                if category else None
            )
        )

        print(f"\n[DEBUG RAG] Query: '{query}'")
        print(f"[DEBUG RAG] Category Filter: '{category}'")

        for doc, score in results_with_scores:
            print(
                f"[DEBUG RAG] Found "
                f"{doc.metadata.get('policy_id')} | "
                f"Score: {score:.4f}"
            )

        print(
            f"[DEBUG RAG] Current Threshold: "
            f"{self.score_threshold}\n"
        )

        filtered_docs = [
            doc for doc, score in results_with_scores
            if score >= self.score_threshold
        ]

        # If it's a known threat category but similarity was low, fall back to top result
        if not filtered_docs and results_with_scores and category != "BENIGN":
            filtered_docs = [results_with_scores[0][0]]

        return filtered_docs
    def get_policies_by_category(self, category: str):
        """Fallback to retrieve category policies without threshold filtering."""
        results = self.vector_store.get(where={"category": category})
        docs = []
        if results and results["documents"]:
            for text, meta in zip(results["documents"], results["metadatas"]):
                docs.append(Document(page_content=text, metadata=meta))
        return docs

policy_db = PolicyDatabase()