-- Closures, upvalues and metamethods.

local function counter()
    local n = 0
    return function()
        n = n + 1
        return n
    end
end

local c = counter()
io.write(c(), c(), c())   -- 123
print("")

local mt = {
    __add = function(a, b) return a.x + b.x end,
}
local a = setmetatable({x = 21}, mt)
local b = setmetatable({x = 21}, mt)
print(a + b)              -- 42