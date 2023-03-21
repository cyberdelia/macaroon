@file:JvmName("Predicates")

package com.lapanthere.macaroon.predicates

import com.lapanthere.macaroon.Caveat
import com.lapanthere.macaroon.CaveatVerifier
import com.lapanthere.macaroon.predicates.Operator.EQUAL
import com.lapanthere.macaroon.predicates.Operator.GREATER_OR_EQUAL
import com.lapanthere.macaroon.predicates.Operator.GREATER_THAN
import com.lapanthere.macaroon.predicates.Operator.IN
import com.lapanthere.macaroon.predicates.Operator.LESS_OR_EQUAL
import com.lapanthere.macaroon.predicates.Operator.LOWER_THAN
import com.lapanthere.macaroon.predicates.Operator.NOT_EQUAL
import com.lapanthere.macaroon.predicates.Operator.NOT_IN
import java.time.Instant
import kotlin.reflect.KClass
import kotlin.reflect.typeOf

public fun field(name: String): Field = Field(name)

internal enum class Operator(private val representation: String) {
    EQUAL("="), NOT_EQUAL("!="),
    GREATER_THAN(">"), GREATER_OR_EQUAL(">="),
    LOWER_THAN("<"), LESS_OR_EQUAL("<="),
    IN("in"), NOT_IN("!in");

    companion object {
        @JvmStatic
        fun findValue(value: String): Operator? = values()
            .find { v -> v.representation == value }
    }

    override fun toString(): String = representation
}

public data class Field(public val name: String) {
    // Not contains
    public infix fun <E : Any> notIn(value: E): Predicate =
        notContainsAll(listOf(value))

    public infix fun <E : Any> notContains(value: E): Predicate =
        notContainsAll(listOf(value))

    public fun <E : Any> notContains(vararg values: E): Predicate =
        notContainsAll(values.toList())

    public infix fun <E : Any> notContainsAll(values: Collection<E>): Predicate =
        Predicate(this, NOT_IN, values)

    // Contains
    public infix fun <E : Any> `in`(value: E): Predicate =
        containsAll(listOf(value))

    public infix fun <E : Any> contains(value: E): Predicate =
        containsAll(listOf(value))

    public fun <E : Any> containsAll(vararg values: E): Predicate =
        containsAll(values.toList())

    public infix fun <E : Any> containsAll(values: Collection<E>): Predicate =
        Predicate(this, IN, values)

    // Equal
    public infix fun <T : Comparable<T>> eq(value: T): Predicate = equal(value)

    public infix fun <T : Comparable<T>> equal(value: T): Predicate =
        Predicate(this, EQUAL, value)

    // Not equal
    public infix fun <T : Comparable<T>> ne(value: T): Predicate = notEqual(value)

    public infix fun <T : Comparable<T>> notEqual(value: T): Predicate =
        Predicate(this, NOT_EQUAL, value)

    // Greater or equal
    public infix fun <T : Comparable<T>> ge(value: T): Predicate = greaterOrEqual(value)

    public infix fun <T : Comparable<T>> greaterOrEqual(value: T): Predicate =
        Predicate(this, GREATER_OR_EQUAL, value)

    // Greater than
    public infix fun <T : Comparable<T>> gt(value: T): Predicate = greaterThan(value)

    public infix fun <T : Comparable<T>> greaterThan(value: T): Predicate =
        Predicate(this, GREATER_THAN, value)

    // Less or equal
    public infix fun <T : Comparable<T>> le(value: T): Predicate = lessOrEqual(value)

    public infix fun <T : Comparable<T>> lessOrEqual(value: T): Predicate =
        Predicate(this, LESS_OR_EQUAL, value)

    // Less than
    public infix fun <T : Comparable<T>> lt(value: T): Predicate = lessThan(value)

    public infix fun <T : Comparable<T>> lessThan(value: T): Predicate =
        Predicate(this, LOWER_THAN, value)

    override fun toString(): String = this.name
}

public class Predicate internal constructor(
    private val field: Field,
    private val operator: Operator,
    private val value: Any,
) {
    override fun toString(): String = "$field $operator " +
        when (value) {
            is Collection<*> -> value.joinToString(",")
            else -> value
        }
}

public class PredicateVerifier<T : Comparable<T>> @PublishedApi internal constructor(
    field: String,
    private val value: T,
    private val klass: KClass<T>,
) : CaveatVerifier {
    private val matcher =
        Regex(
            """\A${Regex.escape(field)} (?<operator>${Operator.values().joinToString("|")}) (?<value>.*)\z""",
        )

    @Suppress("UNCHECKED_CAST")
    override fun verify(caveat: Caveat): Boolean {
        val match = matcher.find(caveat.value)
        return if (match != null) {
            val (operator, rawValue) = match.destructured
            val predicateValue = fromString(rawValue, klass) as T? ?: return false
            when (Operator.findValue(operator)) {
                EQUAL -> predicateValue == value
                NOT_EQUAL -> predicateValue != value
                GREATER_THAN -> value > predicateValue
                GREATER_OR_EQUAL -> value >= predicateValue
                LOWER_THAN -> value < predicateValue
                LESS_OR_EQUAL -> value <= predicateValue
                else -> false
            }
        } else {
            false
        }
    }
}

public class CollectionPredicateVerifier<T : Any> @PublishedApi internal constructor(
    field: String,
    private val value: Collection<T>,
    private val klass: KClass<T>,
) : CaveatVerifier {
    private val matcher =
        Regex(
            """\A${Regex.escape(field)} (?<operator>${Operator.values().joinToString("|")}) (?<value>.*)\z""",
        )

    override fun verify(caveat: Caveat): Boolean {
        val match = matcher.find(caveat.value)
        return if (match != null) {
            val (operator, rawValue) = match.destructured
            val values = rawValue.split(",").map {
                fromString(it, klass)
            } as Collection<*>
            when (Operator.findValue(operator)) {
                IN -> values.containsAll(value)
                NOT_IN -> !values.containsAll(value)
                else -> false
            }
        } else {
            false
        }
    }
}

private fun fromString(value: String, klass: KClass<*>): Any? =
    when (klass) {
        String::class -> value
        Int::class -> value.toInt()
        Long::class -> value.toLong()
        Double::class -> value.toDouble()
        Float::class -> value.toFloat()
        Boolean::class -> value.toBooleanStrict()
        Instant::class -> Instant.parse(value)
        else -> klass.constructors.firstOrNull { it.parameters.size == 1 && it.parameters.first().type == typeOf<String>() }
            ?.call(value)
    }
