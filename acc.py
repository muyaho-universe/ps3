def calculate_accuracy(data):
    # Split lines from the input text
    lines = data.strip().split("\n")

    # Initialize counters
    total_count = 0
    correct_count = 0

    # Iterate through lines to parse and compare truth and result
    for line in lines:
        if "truth =" in line and "result =" in line:
            # Extract truth and result values
            truth = line.split("truth = ")[1].split(" ")[0]
            result = line.split("result = ")[1].strip()

            # Compare values
            total_count += 1
            if truth == result:
                correct_count += 1

    # Calculate accuracy
    if total_count == 0:
        return 0  # Avoid division by zero

    accuracy = correct_count / total_count
    return accuracy

# Read input text from temp.txt
with open('temp.txt', 'r') as file:
    input_text = file.read()

# Calculate and print accuracy
accuracy = calculate_accuracy(input_text)
print(f"Accuracy: {accuracy:.2%}")
