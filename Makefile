SOURCES := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')

TARGET = agent

.DEFAULT: $(TARGET)
$(TARGET): $(SOURCES) Makefile
	go build -o $@ .

clean:
	rm -f $(TARGET)
