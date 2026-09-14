-- Varargs, tables and generic for.
-- Expected output: "10\nsum=10"

local function collect(...)
    local items = {...}
    local n = 0
    for i, v in ipairs(items) do
        n = n + v
    end
    return n
end

print(collect(1, 2, 3, 4))
print("sum=" .. collect(1, 2, 3, 4))