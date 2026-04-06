"""Rule for cleaning code blocks in isolation using LibCST."""

import libcst as cst
from typing import List
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

    IGNORE_TAGS = ("# pyneat: ignore", "# pyneat: off")

    def __init__(self, import_cleaner: ImportCleaningRule, changes: List[str]):
        super().__init__()
        self.import_cleaner = import_cleaner
        self.changes = changes

    def _check_ignore(self, node: cst.CSTNode) -> bool:
        """Return True if the node has a leading comment tagged with ignore."""
        if not hasattr(node, "leading_lines"):
            return False
        for line in node.leading_lines:
            if line.comment and any(tag in line.comment.value for tag in self.IGNORE_TAGS):
                return True
        return False
    
    def leave_Try(self, original_node: cst.Try, updated_node: cst.Try) -> cst.Try:
        """Clean Try blocks in isolation."""
        return self._clean_isolated_block(original_node, updated_node, "Try")
    
    def leave_If(self, original_node: cst.If, updated_node: cst.If) -> cst.If:
        """Clean If blocks in isolation."""
        return self._clean_isolated_block(original_node, updated_node, "If")
    
    def leave_For(self, original_node: cst.For, updated_node: cst.For) -> cst.For:
        """Clean For blocks in isolation."""
        return self._clean_isolated_block(original_node, updated_node, "For")

    def leave_ClassDef(self, original_node: cst.ClassDef, updated_node: cst.ClassDef) -> cst.ClassDef:
        """Clean ClassDef blocks in isolation (skip if decorated)."""
        # Skip decorated classes - decorators are not preserved when re-parsing
        if original_node.decorators:
            return updated_node
        return self._clean_isolated_block(original_node, updated_node, "ClassDef")

    def leave_FunctionDef(self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef) -> cst.FunctionDef:
        """Clean FunctionDef blocks in isolation (skip if decorated)."""
        # Skip decorated functions - decorators are not preserved when re-parsing
        if original_node.decorators:
            return updated_node
        return self._clean_isolated_block(original_node, updated_node, "FunctionDef")
    
    def _clean_isolated_block(self, original_node: cst.CSTNode, updated_node: cst.CSTNode, block_type: str) -> cst.CSTNode:
        """Clean an isolated code block while preserving indentation."""
        if self._check_ignore(original_node):
            return updated_node

        # Skip decorated functions/classes - decorators are not preserved in re-parsing
        if hasattr(original_node, 'decorators') and original_node.decorators:
            return updated_node

        try:
            # Extract the block content as a string
            block_code = cst.Module([]).code_for_node(original_node)
            
            # Create a temporary code file for this block
            block_file = CodeFile(path=None, content=block_code)
            
            # Apply import cleaning to this isolated block
            result = self.import_cleaner.apply(block_file)
            
            if result.success and result.has_changes:
                # Parse the cleaned block back into a CST node
                # Must use parse_module() not parse_statement() because the block
                # may contain multiple statements (e.g., function body with many lines)
                cleaned_module = cst.parse_module(result.transformed_content)
                
                # Extract the first (and usually only) top-level statement
                if cleaned_module.body:
                    cleaned_block = cleaned_module.body[0]
                else:
                    cleaned_block = updated_node

                # Record the changes
                for change in result.changes_made:
                    self.changes.append(f"{block_type} block: {change}")
                
                return cleaned_block
            
        except Exception as e:
            # If cleaning fails, return the original node
            self.changes.append(f"{block_type} block cleaning failed: {str(e)}")
        
        return updated_node