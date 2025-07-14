module png_mod
    implicit none

    private
    public :: validate_input_parameters, generate_prime

contains
    pure recursive function gcd(a,b) result(c)
        implicit none
        integer, intent(in) :: a,b
        integer :: c

        if(a<b) then
            c = gcd(b,a)
        end if
        
        if(b==0) then
            c = a
        else
            c = gcd(b,mod(a,b))
        end if
    end function gcd

    subroutine validate_input_parameters(lower, upper)
        implicit none
        integer :: lower, upper

        if(lower<=2) then
            print *, "lower bound must be greater than or equal to 3"
            stop
        else if(lower > upper) then
            print *, "lower bound must be less than upper bound"
            stop
        else if(upper > 2147483647) then
            print *, "Upper bound exceeded limit. Upper bound must be < 32 bits."
            stop
        end if
    end subroutine validate_input_parameters

    subroutine generate_prime(lower_bound, upper_bound, prime)
        implicit none
        integer, intent(in) :: lower_bound, upper_bound
        integer :: gcd_, i, j
        integer, allocatable, intent(out) :: prime
        logical :: is_coprime

        do i=lower_bound, upper_bound
            is_coprime=.true.
            do j=2,lower_bound-1
                gcd_ = gcd(i,j)
                if(gcd_/=1) then
                    is_coprime=.false.
                    exit
                end if
            end do
        
            if(is_coprime) then
                allocate(prime)
                prime = i
                exit
            end if
        end do
    end subroutine generate_prime
end module png_mod