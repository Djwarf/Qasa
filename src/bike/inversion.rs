//! Polynomial inversion in GF(2)[x]/(x^r - 1)
//!
//! This module implements polynomial inversion using the Extended Euclidean Algorithm

use super::polynomial::BinaryPolynomial;
use crate::error::{CryptoError, CryptoResult};

/// Compute the multiplicative inverse of a polynomial in GF(2)[x]/(x^r - 1)
///
/// Uses the Extended Euclidean Algorithm (EEA) to find poly^(-1) mod (x^r - 1)
///
/// Returns an error if the polynomial is not invertible
pub fn compute_inverse(poly: &BinaryPolynomial) -> CryptoResult<BinaryPolynomial> {
    let r = poly.r();

    // Create the modulus: x^r + 1 (which is x^r - 1 in GF(2))
    let mut modulus = BinaryPolynomial::new(r + 1);
    modulus.set_coeff(0, 1);
    modulus.set_coeff(r, 1);

    // Extended Euclidean Algorithm
    let mut r0 = extend_polynomial(poly, r + 1);
    let mut r1 = modulus.clone();

    let mut t0 = BinaryPolynomial::new(r + 1);
    t0.set_coeff(0, 1); // t0 = 1

    let mut t1 = BinaryPolynomial::new(r + 1); // t1 = 0

    while r1.hamming_weight() > 0 {
        let (quotient, remainder) = polynomial_div(&r0, &r1)?;

        // Update r values
        r0 = r1;
        r1 = remainder;

        // Update t values: t_new = t0 - quotient * t1
        let q_times_t1 = polynomial_mul_extended(&quotient, &t1, r + 1)?;
        let t_new = polynomial_add_extended(&t0, &q_times_t1, r + 1)?;

        t0 = t1;
        t1 = t_new;
    }

    // Check if gcd is 1 (polynomial is invertible)
    if r0.hamming_weight() != 1 || r0.get_coeff(0) != 1 {
        return Err(CryptoError::bike_error(
            "inversion",
            "Polynomial is not invertible",
            crate::error::error_codes::BIKE_KEY_GENERATION_FAILED,
        ));
    }

    // Result is t0, reduced modulo r
    let result = reduce_polynomial(&t0, r);
    Ok(result)
}

/// Extend a polynomial to a larger degree
fn extend_polynomial(poly: &BinaryPolynomial, new_r: usize) -> BinaryPolynomial {
    let mut extended = BinaryPolynomial::new(new_r);
    for i in 0..poly.r() {
        if poly.get_coeff(i) == 1 {
            extended.set_coeff(i, 1);
        }
    }
    extended
}

/// Reduce a polynomial from larger degree to r bits
fn reduce_polynomial(poly: &BinaryPolynomial, r: usize) -> BinaryPolynomial {
    let mut reduced = BinaryPolynomial::new(r);
    for i in 0..r {
        if poly.get_coeff(i) == 1 {
            reduced.set_coeff(i, 1);
        }
    }
    reduced
}

/// Polynomial division in GF(2)[x]
///
/// Returns (quotient, remainder) such that dividend = quotient * divisor + remainder
fn polynomial_div(dividend: &BinaryPolynomial, divisor: &BinaryPolynomial) -> CryptoResult<(BinaryPolynomial, BinaryPolynomial)> {
    if divisor.hamming_weight() == 0 {
        return Err(CryptoError::bike_error(
            "division",
            "Division by zero polynomial",
            crate::error::error_codes::BIKE_KEY_GENERATION_FAILED,
        ));
    }

    let r = dividend.r();
    let mut quotient = BinaryPolynomial::new(r);
    let mut remainder = dividend.clone();

    // Find degree of divisor (highest set bit)
    let divisor_deg = find_degree(divisor);

    loop {
        let remainder_deg = find_degree(&remainder);

        if remainder_deg < divisor_deg || remainder.hamming_weight() == 0 {
            break;
        }

        // Compute the shift amount
        let shift = remainder_deg - divisor_deg;

        // Set quotient bit
        quotient.set_coeff(shift, 1);

        // Subtract divisor * x^shift from remainder (XOR in GF(2))
        let shifted_divisor = shift_polynomial(divisor, shift);
        remainder = polynomial_add_extended(&remainder, &shifted_divisor, r)?;
    }

    Ok((quotient, remainder))
}

/// Find the degree of a polynomial (position of highest set bit)
fn find_degree(poly: &BinaryPolynomial) -> usize {
    for i in (0..poly.r()).rev() {
        if poly.get_coeff(i) == 1 {
            return i;
        }
    }
    0
}

/// Shift polynomial left by n positions
fn shift_polynomial(poly: &BinaryPolynomial, n: usize) -> BinaryPolynomial {
    let r = poly.r();
    let mut shifted = BinaryPolynomial::new(r);

    for i in 0..r {
        if poly.get_coeff(i) == 1 && i + n < r {
            shifted.set_coeff(i + n, 1);
        }
    }

    shifted
}

/// Add two polynomials with extended size
fn polynomial_add_extended(a: &BinaryPolynomial, b: &BinaryPolynomial, r: usize) -> CryptoResult<BinaryPolynomial> {
    let mut result = BinaryPolynomial::new(r);

    for i in 0..r {
        let a_bit = if i < a.r() { a.get_coeff(i) } else { 0 };
        let b_bit = if i < b.r() { b.get_coeff(i) } else { 0 };
        result.set_coeff(i, a_bit ^ b_bit);
    }

    Ok(result)
}

/// Multiply two polynomials with extended size
fn polynomial_mul_extended(a: &BinaryPolynomial, b: &BinaryPolynomial, r: usize) -> CryptoResult<BinaryPolynomial> {
    let mut result = BinaryPolynomial::new(r);

    for i in 0..a.r() {
        if a.get_coeff(i) == 0 {
            continue;
        }
        for j in 0..b.r() {
            if b.get_coeff(j) == 1 && i + j < r {
                result.flip_coeff(i + j);
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_division() {
        // Test: (x^3 + x + 1) / (x + 1) = x^2 + 1, remainder = 0
        let mut dividend = BinaryPolynomial::new(10);
        dividend.set_coeff(0, 1);
        dividend.set_coeff(1, 1);
        dividend.set_coeff(3, 1);

        let mut divisor = BinaryPolynomial::new(10);
        divisor.set_coeff(0, 1);
        divisor.set_coeff(1, 1);

        let (quotient, remainder) = polynomial_div(&dividend, &divisor).unwrap();

        // Quotient should be x^2 + 1
        assert_eq!(quotient.get_coeff(0), 1);
        assert_eq!(quotient.get_coeff(2), 1);

        // Remainder should be 0
        assert_eq!(remainder.hamming_weight(), 0);
    }

    #[test]
    fn test_simple_inversion() {
        // Test inversion of x + 1 in small field
        let mut poly = BinaryPolynomial::new(7);
        poly.set_coeff(0, 1);
        poly.set_coeff(1, 1);

        let result = compute_inverse(&poly);
        assert!(result.is_ok());
    }
}
