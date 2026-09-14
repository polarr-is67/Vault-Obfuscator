-- Basic arithmetic and recursion.
-- Expected output: "hello\n123\n12345\n"

local x = 3

local function add(a, b)
    return a + b
end

local function fact(n)
    if n <= 1 then return 1 end
    return n * fact(n - 1)
end

print("hello")
print(add(fact(5), x))

for i = 1, 5 do
    io.write(i)
end
print("")