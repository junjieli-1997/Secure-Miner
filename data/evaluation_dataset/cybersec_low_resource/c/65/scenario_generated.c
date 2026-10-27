double rand_double() {
	int r = rand();
	return (double)r / ( (double)RAND_MAX + 1.0 );
}
