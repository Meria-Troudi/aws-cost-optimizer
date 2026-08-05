"""
CostSummarizer - DEPRECATED
This service is no longer needed. All cost aggregations are now
performed on-the-fly from CostRecord table.
"""

from sqlalchemy.orm import Session


class CostSummarizer:
 
    
    def summarize(self, db: Session, scan):
       
        print("\n=== Cost Summarizer (DEPRECATED) ===")
        print("Cost analysis is now performed on-the-fly from CostRecord")
        print("No summary tables are created")
        
        return {
            "service_costs": 0,
            "usage_type_costs": 0,
        }
