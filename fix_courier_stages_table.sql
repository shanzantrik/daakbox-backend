-- Fix courier_stages table structure to match backend expectations
-- The backend expects: id, stage_name, stage_order, is_active, created_at
-- Current table has: id, title, description, is_active, created_by, updated_by, created_at, updated_at, deleted_at

-- First, backup the existing data
CREATE TABLE courier_stages_backup AS SELECT * FROM courier_stages;

-- Drop the existing table
DROP TABLE courier_stages;

-- Create the new table with the correct structure
CREATE TABLE courier_stages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  stage_name VARCHAR(100) NOT NULL UNIQUE,
  stage_order INT DEFAULT 0,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert the default stages that the backend expects
INSERT INTO courier_stages (stage_name, stage_order) VALUES
('Booking Created', 1),
('Pickup Scheduled', 2),
('Picked Up', 3),
('In Transit', 4),
('Out for Delivery', 5),
('Delivered', 6),
('Returned', 7),
('Cancelled', 8);

-- Verify the new structure
-- DESCRIBE courier_stages;
-- SELECT * FROM courier_stages ORDER BY stage_order;
