//! AI Analysis Module for PyNEAT
//!
//! Provides LLM-based code analysis capabilities.
//!
//! Copyright (C) 2026 PyNEAT Authors

pub mod llm;

pub use llm::{LlmAnalyzer, LlmAnalysisResult, AiFix, has_api_key};
