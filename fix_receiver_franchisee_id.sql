-- Fix receiver_franchisee_id constraint to allow NULL values
-- This allows courier bookings to have receivers who are not franchisees

-- First, check if the foreign key constraint exists and drop it
SET @constraint_name = (
  SELECT CONSTRAINT_NAME
FROM information_schema.KEY_COLUMN_USAGE
WHERE TABLE_SCHEMA = 'daakbox_dbx'
  AND TABLE_NAME = 'courier_bookings'
  AND COLUMN_NAME = 'receiver_franchisee_id'
  AND REFERENCED_TABLE_NAME IS NOT NULL
);

-- Drop the foreign key constraint if it exists
SET @sql =
IF(@constraint_name IS NOT NULL,
  CONCAT
('ALTER TABLE courier_bookings DROP FOREIGN KEY ', @constraint_name),
  'SELECT "No foreign key constraint found"'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Now modify the column to allow NULL values
ALTER TABLE courier_bookings MODIFY COLUMN receiver_franchisee_id INT NULL;

-- Update existing records where receiver_franchisee_id is 0 to NULL for better data integrity
UPDATE courier_bookings SET receiver_franchisee_id = NULL WHERE receiver_franchisee_id = 0;

-- Add a comment to explain the field
ALTER TABLE courier_bookings MODIFY COLUMN receiver_franchisee_id INT NULL COMMENT 'NULL for non-franchisee receivers, franchisee ID for franchisee receivers';

-- Optionally, recreate the foreign key constraint if you want to maintain referential integrity
-- ALTER TABLE courier_bookings ADD CONSTRAINT courier_bookings_receiver_franchisee_id_foreign
-- FOREIGN KEY (receiver_franchisee_id) REFERENCES franchisees(id) ON DELETE SET NULL;
