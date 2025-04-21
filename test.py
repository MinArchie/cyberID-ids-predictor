import numpy as np
import matplotlib.pyplot as plt

# Time array from 0 to 10 seconds (with 0.01s step)
t = np.linspace(0, 10, 1000)

# Define the function x(t)
x_t = (1/6) - (1/2)*np.exp(-2*t) + (1/3)*np.exp(-3*t)

# Plotting
plt.figure(figsize=(8, 5))
plt.plot(t, x_t, label=r'$x(t) = \frac{1}{6} - \frac{1}{2}e^{-2t} + \frac{1}{3}e^{-3t}$', color='darkblue')
plt.title('Satellite Angular Position Response to Step Torque')
plt.xlabel('Time (seconds)')
plt.ylabel('Angular Position x(t)')
plt.grid(True)
plt.legend()
plt.axhline(y=1/6, color='red', linestyle='--', label='Final Angle = 1/6 rad')
plt.tight_layout()
plt.show()
