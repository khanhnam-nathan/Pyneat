"""Rule for cleaning code blocks in isolation using LibCST."""

import libcst as cst
from typing import List, Optional
from pyneat.core.types import CodeFile, RuleConfig, TransformationResult
from pyneat.rules.base import Rule
from pyneat.rules.imports import ImportCleaningRule

class IsolatedBlockCleaner(Rule):
    """Cleans code blocks (If, Try, For, FunctionDef) in isolation."""
    
    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        self.import_cleaner = ImportCleaningRule(config)
    
    @property
    def description(self) -> str:
        return "Cleans code blocks (If, Try, For, FunctionDef) in isolation"
    
    def apply(self, code_file: CodeFile) -> TransformationResult:
        try:
            changes = []
            
            # Parse the entire file with LibCST
            module = cst.parse_module(code_file.content)
            
            # Create transformer to process isolated blocks
            transformer = _IsolatedBlockTransformer(self.import_cleaner, changes)
            
            # Apply transformation
            transformed_module = module.visit(transformer)
            
            # Get the transformed content
            transformed_content = transformed_module.code
            
            return self._create_result(code_file, transformed_content, changes)
            
        except Exception as e:
            return self._create_error_result(code_file, f"Isolated block cleaning failed: {str(e)}")


class _IsolatedBlockTransformer(cst.CSTTransformer):
    """LibCST transformer for processing isolated code blocks."""
    
    def __init__(self, import_cleaner: ImportCleaningRule, changes: List[str]):
        super().__init__()
        self.import_cleaner = import_cleaner
        self.changes = changes
    
    def leave_Try(self, original_node: cst.Try, updated_node: cst.Try) -> cst.Try:
        """Clean Try blocks in isolation."""
        return self._clean_isolated_block(original_node, updated_node, "Try")
    
    def leave_If(self, original_node: cst.If, updated_node: cst.If) -> cst.If:
        """Clean If blocks in isolation."""
        return self._clean_isolated_block(original_node, updated_node, "If")
    
    def leave_For(self, original_node: cst.For, updated_node: cst.For) -> cst.For:
        """Clean For blocks in isolation."""
        return self._clean_isolated_block(original_node, updated_node, "For")
    
    def leave_FunctionDef(self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef) -> cst.FunctionDef:
        """Clean FunctionDef blocks in isolation."""
        return self._clean_isolated_block(original_node, updated_node, "FunctionDef")
    
    def _clean_isolated_block(self, original_node: cst.CSTNode, updated_node: cst.CSTNode, block_type: str) -> cst.CSTNode:
        """Clean an isolated code block while preserving indentation."""
        try:
            # Extract the block content as a string
            block_code = cst.Module([]).code_for_node(original_node)
            
            # Create a temporary code file for this block
            block_file = CodeFile(path=None, content=block_code)
            
            # Apply import cleaning to this isolated block
            result = self.import_cleaner.apply(block_file)
            
            if result.success and result.has_changes:
                # Parse the cleaned block back into a CST node
                cleaned_block = cst.parse_statement(result.transformed_content)
                
                # Record the changes
                for change in result.changes_made:
                    self.changes.append(f"{block_type} block: {change}")
                
                return cleaned_block
            
        except Exception as e:
            # If cleaning fails, return the original node
            self.changes.append(f"{block_type} block cleaning failed: {str(e)}")
        
        return updated_node