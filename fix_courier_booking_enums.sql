-- Fix ENUM column mismatches in courier_bookings table
-- This script aligns the database ENUM values with the frontend form values

-- Fix Modes_of_Services column
-- Frontend sends: 'air', 'road', 'train'
-- Database was expecting: 'By Air', 'By Surface', 'By Train'
ALTER TABLE courier_bookings MODIFY COLUMN Modes_of_Services ENUM
('air', 'road', 'train') NOT NULL;

-- Fix service_type column
-- Frontend sends: 'standard', 'express', 'oda'
-- Database was expecting: 'standard', 'express', 'priority'
ALTER TABLE courier_bookings MODIFY COLUMN service_type ENUM
('standard', 'express', 'oda') NOT NULL;

-- Fix payment_mode column
-- Frontend sends: 'cash', 'credit', 'cheque', 'to_pay'
-- Database was expecting: 'cash', 'online', 'cod'
ALTER TABLE courier_bookings MODIFY COLUMN payment_mode ENUM
('cash', 'credit', 'cheque', 'to_pay') NOT NULL;

-- Fix Consignment_nature column
-- Frontend sends: 'General' (default)
-- Database was expecting: 'dox', 'non-dox'
ALTER TABLE courier_bookings MODIFY COLUMN Consignment_nature ENUM
('General', 'dox', 'non-dox') NOT NULL;

-- Fix status column
-- Backend sends: 'active' (default)
-- Database was expecting: 'booked', 'picked_up', 'in_transit', etc.
ALTER TABLE courier_bookings MODIFY COLUMN status ENUM
('active', 'booked', 'picked_up', 'in_transit', 'out_for_delivery', 'delivered', 'returned', 'cancelled')
NOT NULL DEFAULT 'active';

-- Verify the changes
-- DESCRIBE courier_bookings Modes_of_Services, service_type, payment_mode, Consignment_nature, status;
