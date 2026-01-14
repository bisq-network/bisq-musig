function Link(el)
  if el.target:match("^http") then
    return el
  end
  if el.target:match("%.md$") then
    el.target = el.target:gsub("%.md$", ".md.html")
  end
  return el
end
