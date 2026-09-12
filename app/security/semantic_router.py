from typing import TypedDict
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from app.security.policy_db import policy_db
from dotenv import load_dotenv

load_dotenv()

class GraphState(TypedDict):
    prompt: str
    intent_category: str
    retrieved_policies: str
    is_safe: bool
    reasoning: str

class SemanticEngine:
    def __init__(self):
        # Using GPT-4o-mini for efficient and cost-effective processing of prompts
        self.llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        self.retriever = policy_db.get_retriever()
        self.graph = self._build_graph()

    async def classify_intent(self, state: GraphState):
        classifier_prompt = PromptTemplate.from_template(
            "Classify intent into: [BENIGN, PROMPT_INJECTION, DATA_EXTRACTION, MALICIOUS_CODE].\n"
            "Prompt: {prompt}\nCategory:"
        )
        chain = classifier_prompt | self.llm
        result = await chain.ainvoke({"prompt": state["prompt"]}) 
        return {"intent_category": result.content.strip()}

    async def retrieve_policy(self, state: GraphState):
        docs = await self.retriever.ainvoke(state["prompt"])
        policy_text = "\n".join([doc.page_content for doc in docs])
        return {"retrieved_policies": policy_text}

    async def evaluate_safety(self, state: GraphState):
        judge_prompt = PromptTemplate.from_template(
            "Evaluate if User Prompt violates Company Policy.\n"
            "Policy: {policies}\nPrompt: {prompt}\n"
            "Respond strictly 'SAFE' or 'UNSAFE', followed by a reason."
        )
        chain = judge_prompt | self.llm
        result = await chain.ainvoke({
            "policies": state["retrieved_policies"], 
            "prompt": state["prompt"]
        })
        
        response = result.content.strip()
        return {"is_safe": response.startswith("SAFE"), "reasoning": response}

    def route_based_on_intent(self, state: GraphState):
        # The latency saver: Bypass RAG entirely if the prompt is benign
        if state["intent_category"] == "BENIGN":
            return "skip_to_end"
        return "fetch_policy"

    def _build_graph(self):
        workflow = StateGraph(GraphState)
        workflow.add_node("classify", self.classify_intent)
        workflow.add_node("retrieve", self.retrieve_policy)
        workflow.add_node("judge", self.evaluate_safety)
        
        workflow.set_entry_point("classify")
        workflow.add_conditional_edges("classify", self.route_based_on_intent, {
            "skip_to_end": END, "fetch_policy": "retrieve"
        })
        workflow.add_edge("retrieve", "judge")
        workflow.add_edge("judge", END)
        return workflow.compile()

    async def evaluate(self, prompt: str) -> dict:
        initial_state = {
            "prompt": prompt, "intent_category": "", "retrieved_policies": "", 
            "is_safe": True, "reasoning": "Benign prompt, no policy check required."
        }
        return await self.graph.ainvoke(initial_state)