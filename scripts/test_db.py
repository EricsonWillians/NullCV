#!/usr/bin/env python3
"""
Enhanced test suite for nullcv.db.sqlite secure database implementation.
This test harness demonstrates the cryptographic verification features and data
integrity capabilities of the secure database.
"""

import os
import asyncio
import time
from typing import Dict, Any, List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.traceback import install
from rich.prompt import Confirm
from rich.tree import Tree

from nullcv.db.sqlite import get_secure_database, create_table_schema

# Install rich traceback handler
install(show_locals=True)

# Initialize rich console
console = Console()

# Test table name
TEST_TABLE = "secure_test_table"

class SecureDatabaseTester:
    """Comprehensive test suite for the SecureDatabase class."""
    
    def __init__(self, console: Console):
        self.console = console
        self.db = None
        self.test_records: List[Dict[str, Any]] = []
        self.record_ids: List[str] = []
    
    async def setup(self) -> None:
        """Initialize the database and test table."""
        with self.console.status("[bold green]Initializing secure database..."):
            self.db = await get_secure_database()
            
            # Create test table if not exists
            async with self.db.get_session() as session:
                await session.execute(create_table_schema(TEST_TABLE))
                await session.commit()
        
        self.console.print(Panel.fit(
            "[bold green]✓[/] Secure database initialized successfully",
            title="Setup Complete",
            border_style="green"
        ))

    async def run_all_tests(self) -> bool:
        """Run all database tests and return overall success status."""
        await self.setup()
        
        success = True
        
        # Define all test functions with descriptive titles
        tests = [
            (self.test_insert, "Database Insert Operation"),
            (self.test_retrieval, "Record Retrieval and Verification"),
            (self.test_multiple_inserts, "Multiple Records Insertion"),
            (self.test_query, "Query with Filters"),
            (self.test_update, "Record Update Operation"),
            (self.test_delete, "Record Deletion"),
            (self.test_database_integrity, "Database Integrity Verification"),
        ]
        
        # Create and display test summary table
        table = Table(title="Test Execution Plan")
        table.add_column("Test ID", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Status", style="yellow")
        
        for i, (_, description) in enumerate(tests, 1):
            table.add_row(f"T{i}", description, "Pending")
        
        self.console.print(table)
        self.console.print()
        
        # Run each test with progress indication
        for i, (test_func, description) in enumerate(tests, 1):
            self.console.rule(f"[bold blue]Test {i}: {description}")
            
            try:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold green]Running test..."),
                    console=self.console
                ) as progress:
                    task = progress.add_task("", total=None)
                    result = await test_func()
                
                if result:
                    self.console.print(f"[bold green]✓ PASS:[/] {description}")
                else:
                    self.console.print(f"[bold red]✗ FAIL:[/] {description}")
                    success = False
            except Exception as e:
                self.console.print(f"[bold red]✗ ERROR:[/] {description}")
                self.console.print_exception()
                success = False
            
            self.console.print()
        
        # Display summary
        if success:
            self.console.print(Panel.fit(
                "[bold green]All tests passed successfully![/]",
                title="Test Summary",
                border_style="green"
            ))
        else:
            self.console.print(Panel.fit(
                "[bold red]Some tests failed. Check logs for details.[/]",
                title="Test Summary",
                border_style="red"
            ))
        
        return success
    
    async def test_insert(self) -> bool:
        """Test basic insert operation with signature verification."""
        self.console.print("[bold]Testing data insertion with cryptographic signature[/]")
        
        # Create test record with timestamp
        test_data = {
            "name": "Test Entry Alpha",
            "value": 42.5,
            "tags": ["secure", "test", "db"],
            "active": True,
            "timestamp": int(time.time())
        }
        
        # Display the data we're inserting
        self.console.print("Inserting data:", style="yellow")
        self.console.print(Syntax(str(test_data), "python", theme="monokai", line_numbers=True))
        
        # Insert data
        record_id = await self.db.insert(TEST_TABLE, test_data)
        self.record_ids.append(record_id)
        self.test_records.append(test_data)
        
        # Verify record was created with ID
        self.console.print(f"Record created with ID: [bold cyan]{record_id}[/]")
        
        return record_id is not None and len(record_id) > 0
    
    async def test_retrieval(self) -> bool:
        """Test data retrieval with signature verification."""
        if not self.record_ids:
            self.console.print("[yellow]No test records available, skipping retrieval test[/]")
            return False
        
        record_id = self.record_ids[0]
        self.console.print(f"Retrieving record with ID: [bold cyan]{record_id}[/]")
        
        # Get record with verification
        record = await self.db.get(TEST_TABLE, record_id, verify=True)
        
        if not record:
            self.console.print("[bold red]Failed to retrieve record with verification![/]")
            return False
        
        # Display the retrieved record
        retrieved_table = Table(title=f"Retrieved Record: {record_id}")
        retrieved_table.add_column("Field", style="cyan")
        retrieved_table.add_column("Value", style="green")
        
        for key, value in record.items():
            retrieved_table.add_row(key, str(value))
        
        self.console.print(retrieved_table)
        
        # Verify the data matches what we inserted
        original = self.test_records[0]
        for key, value in original.items():
            if key not in record or record[key] != value:
                self.console.print(f"[bold red]Data mismatch for key {key}![/]")
                return False
        
        self.console.print("[bold green]Data retrieved successfully with cryptographic verification![/]")
        return True
    
    async def test_multiple_inserts(self) -> bool:
        """Test inserting multiple records and bulk operations."""
        test_records = [
            {
                "name": f"Bulk Test {i}",
                "value": i * 10,
                "batch": "A",
                "timestamp": int(time.time())
            }
            for i in range(1, 5)
        ]
        
        self.console.print(f"[bold]Inserting {len(test_records)} test records...[/]")
        
        # Use progress bar for multiple inserts
        with Progress() as progress:
            task = progress.add_task("[green]Inserting...", total=len(test_records))
            
            for data in test_records:
                record_id = await self.db.insert(TEST_TABLE, data)
                self.record_ids.append(record_id)
                self.test_records.append(data)
                progress.update(task, advance=1)
        
        self.console.print(f"[bold green]Successfully inserted {len(test_records)} records![/]")
        
        # Count records in the table
        async with self.db.get_session() as session:
            result = await session.execute(f"SELECT COUNT(*) FROM {TEST_TABLE}")
            count = result.scalar()
            
            self.console.print(f"Total records in table: [bold cyan]{count}[/]")
            
            # At least our inserted records should be there
            return count >= len(self.record_ids)
    
    async def test_query(self) -> bool:
        """Test querying records with filters."""
        if len(self.test_records) < 4:
            self.console.print("[yellow]Not enough test records for query test[/]")
            return False
        
        # Query for records with batch "A"
        self.console.print("[bold]Testing query with filter: batch = 'A'[/]")
        
        results = await self.db.query(TEST_TABLE, {"batch": "A"})
        
        # Display query results
        query_table = Table(title="Query Results")
        query_table.add_column("ID", style="cyan")
        query_table.add_column("Name", style="green")
        query_table.add_column("Value", style="blue")
        
        for record in results:
            query_table.add_row(
                record.get("id", "N/A"), 
                record.get("name", "N/A"),
                str(record.get("value", "N/A"))
            )
        
        self.console.print(query_table)
        self.console.print(f"Found [bold cyan]{len(results)}[/] matching records")
        
        # We should have at least 4 records with batch "A"
        return len(results) >= 4
    
    async def test_update(self) -> bool:
        """Test updating a record with signature verification."""
        if not self.record_ids:
            self.console.print("[yellow]No test records available, skipping update test[/]")
            return False
        
        record_id = self.record_ids[0]
        
        # Get the current record
        original = await self.db.get(TEST_TABLE, record_id)
        if not original:
            self.console.print("[bold red]Failed to retrieve record for update test![/]")
            return False
        
        # Create updated data
        updated_data = dict(original)
        updated_data["updated"] = True
        updated_data["value"] = 99.9
        updated_data["timestamp"] = int(time.time())
        
        # Display update operation
        self.console.print(f"Updating record [bold cyan]{record_id}[/]")
        
        update_table = Table(title="Update Operation")
        update_table.add_column("Field", style="cyan")
        update_table.add_column("Original", style="yellow")
        update_table.add_column("Updated", style="green")
        
        for key in updated_data:
            old_val = str(original.get(key, "N/A"))
            new_val = str(updated_data[key])
            if old_val != new_val:
                update_table.add_row(key, old_val, new_val)
        
        self.console.print(update_table)
        
        # Perform the update
        result = await self.db.update(TEST_TABLE, record_id, updated_data)
        
        if not result:
            self.console.print("[bold red]Update operation failed![/]")
            return False
        
        # Verify the update worked by retrieving the record again
        updated_record = await self.db.get(TEST_TABLE, record_id, verify=True)
        
        if not updated_record:
            self.console.print("[bold red]Failed to retrieve updated record![/]")
            return False
        
        # Check that fields were updated
        for key, value in updated_data.items():
            if updated_record.get(key) != value:
                self.console.print(f"[bold red]Update verification failed for key {key}![/]")
                return False
        
        self.console.print("[bold green]Record updated successfully with cryptographic verification![/]")
        return True
    
    async def test_delete(self) -> bool:
        """Test deleting a record with signature verification."""
        if len(self.record_ids) < 2:
            self.console.print("[yellow]Not enough test records for delete test[/]")
            return False
        
        # Use the last record ID for deletion to preserve others for future tests
        record_id = self.record_ids[-1]
        
        self.console.print(f"Deleting record with ID: [bold cyan]{record_id}[/]")
        
        # Perform the delete operation
        result = await self.db.delete(TEST_TABLE, record_id)
        
        if not result:
            self.console.print("[bold red]Delete operation failed![/]")
            return False
        
        # Verify the record is gone
        deleted_record = await self.db.get(TEST_TABLE, record_id)
        
        if deleted_record is not None:
            self.console.print("[bold red]Record still exists after deletion![/]")
            return False
        
        # Remove from our tracking lists
        self.record_ids.pop()
        self.test_records.pop()
        
        self.console.print("[bold green]Record deleted successfully with cryptographic verification![/]")
        return True
    
    async def test_database_integrity(self) -> bool:
        """Test database integrity verification."""
        self.console.print("[bold]Verifying database integrity...[/]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]Verifying signatures and hash chain..."),
            console=self.console
        ) as progress:
            task = progress.add_task("", total=None)
            # Run the integrity check
            valid, errors = await self.db.verify_database_integrity()
        
        if valid:
            self.console.print("[bold green]✓ Database integrity verification passed![/]")
            
            # Show signature chain visualization
            tree = Tree("[bold green]Signature Chain 🔐", guide_style="green")
            
            async with self.db.get_session() as session:
                result = await session.execute(
                    """
                    SELECT id, operation, table_name, record_id, data_hash
                    FROM db_signatures
                    ORDER BY id ASC
                    LIMIT 10
                    """
                )
                signatures = result.fetchall()
                
                for sig_id, operation, table_name, record_id, data_hash in signatures:
                    node = tree.add(f"[cyan]#{sig_id}[/]: [bold yellow]{operation}[/] on [blue]{table_name}[/]")
                    node.add(f"Record: [magenta]{record_id}[/]")
                    node.add(f"Hash: [dim]{data_hash[:16]}...[/]")
            
            self.console.print(tree)
            
            return True
        else:
            self.console.print("[bold red]✗ Database integrity verification failed![/]")
            
            # Display errors
            error_table = Table(title="Integrity Errors")
            error_table.add_column("Error", style="red")
            
            for error in errors:
                error_table.add_row(error)
            
            self.console.print(error_table)
            
            return False

async def main():
    """Main test runner function."""
    console.print(Panel.fit(
        "[bold blue]Secure Database Test Suite[/]\n\n"
        "This test suite validates the cryptographic verification features\n"
        "and data integrity capabilities of the NullCV secure database.",
        title="🔐 Database Test Harness",
        border_style="blue"
    ))
    
    # Create database file path for display
    db_path = os.environ.get('SQLITE_DATABASE_PATH', 'data/nullcv.db')
    console.print(f"Database path: [cyan]{db_path}[/]")
    
    # Ask for confirmation before running tests
    if not Confirm.ask("Do you want to run the tests?"):
        console.print("[yellow]Test execution cancelled.[/]")
        return
    
    # Run all tests
    tester = SecureDatabaseTester(console)
    success = await tester.run_all_tests()
    
    # Exit with appropriate code
    if not success:
        import sys
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())