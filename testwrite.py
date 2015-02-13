from __future__ import unicode_literals, print_function, absolute_import, division

from writemdict import MDictWriter

outfile = open("testoutput.mdx", "wb")
d = {
    "alpha":"<i>alpha</i>",
	"beta":"Letter <b>beta</b>",
	"gamma":"Capital version is Γ &lt;"
	}
writer = MDictWriter(d)
writer.write(outfile)
outfile.close()
