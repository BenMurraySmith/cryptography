program prime_number_generator_program
    use png_mod
    implicit none
    integer :: lower_bound, upper_bound
    integer, allocatable :: prime

    print *, "--- PRIME NUMBER GENERATOR ---"
    print *, "Note: maximum upper bound is 32-bit integer."
    print *, ""
    print *, "Enter a lower and upper bound for prime: "

    read *, lower_bound, upper_bound
    
    call validate_input_parameters(lower_bound, upper_bound)

    call generate_prime(lower_bound, upper_bound, prime)
    
    if(.not. allocated(prime)) then
        print *, "Could not find prime in integer range: ", lower_bound, " - ", upper_bound
    else
        print *, "Found prime: ", prime
        deallocate(prime)
    end if
    

end program prime_number_generator_program