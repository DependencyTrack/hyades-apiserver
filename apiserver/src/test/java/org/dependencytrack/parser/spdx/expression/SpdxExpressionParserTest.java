/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.parser.spdx.expression;

import org.dependencytrack.parser.spdx.expression.model.SpdxExpression;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SpdxExpressionParserTest {

    @Test
    void testParsingOfSuperfluousParentheses() {
        var exp = SpdxExpressionParser.getInstance().parse("(Apache OR MIT WITH (CPE) AND GPL WITH ((CC0 OR GPL-2)))");
        assertEquals("OR(AND(WITH(GPL, OR(CC0, GPL-2)), WITH(MIT, CPE)), Apache)", exp.toString());
    }

    @Test
    void testThatAndOperatorBindsStrongerThanOrOperator() {
        var exp = SpdxExpressionParser.getInstance().parse("LGPL-2.1-only OR BSD-3-Clause AND MIT");
        assertEquals("OR(AND(BSD-3-Clause, MIT), LGPL-2.1-only)", exp.toString());
    }

    @Test
    void testThatWithOperatorBindsStrongerThanAndOperator() {
        var exp = SpdxExpressionParser.getInstance().parse("LGPL-2.1-only WITH CPE AND MIT OR BSD-3-Clause");
        assertEquals("OR(AND(MIT, WITH(LGPL-2.1-only, CPE)), BSD-3-Clause)", exp.toString());
    }

    @Test
    void testThatParenthesesOverrideOperatorPrecedence() {
        var exp = SpdxExpressionParser.getInstance().parse("MIT AND (LGPL-2.1-or-later OR BSD-3-Clause)");
        assertEquals("AND(MIT, OR(BSD-3-Clause, LGPL-2.1-or-later))", exp.toString());
    }

    @Test
    void testParsingWithMissingSpaceAfterParenthesis() {
        var exp = SpdxExpressionParser.getInstance().parse("(MIT)AND(LGPL-2.1-or-later WITH(CC0 OR GPL-2))");
        assertEquals("AND(MIT, WITH(LGPL-2.1-or-later, OR(CC0, GPL-2)))", exp.toString());
    }

    @Test
    void testMissingClosingParenthesis() {
        var exp = SpdxExpressionParser.getInstance().parse("MIT (OR BSD-3-Clause");
        assertEquals(SpdxExpression.INVALID, exp);
    }

    @Test
    void testMissingOpeningParenthesis() {
        var exp = SpdxExpressionParser.getInstance().parse("MIT )(OR BSD-3-Clause");
        assertEquals(SpdxExpression.INVALID, exp);
    }

    @Test
    void testDanglingOperator() {
        var exp = SpdxExpressionParser.getInstance().parse("GPL-3.0-or-later AND GPL-2.0-or-later AND GPL-2.0-only AND");
        assertEquals(SpdxExpression.INVALID, exp);
    }

    @Test
    void testMissingOperand() {
        assertEquals(SpdxExpression.INVALID, SpdxExpressionParser.getInstance().parse("MIT OR"));
        assertEquals(SpdxExpression.INVALID, SpdxExpressionParser.getInstance().parse("OR MIT"));
        assertEquals(SpdxExpression.INVALID, SpdxExpressionParser.getInstance().parse("MIT AND OR Apache-2.0"));
    }

    @Test
    void testDanglingOperands() {
        assertEquals(SpdxExpression.INVALID, SpdxExpressionParser.getInstance().parse("MIT Apache-2.0"));
    }

    @Test
    void testStandalonePlus() {
        assertEquals(SpdxExpression.INVALID, SpdxExpressionParser.getInstance().parse("+"));
        assertEquals(SpdxExpression.INVALID, SpdxExpressionParser.getInstance().parse("MIT +"));
    }

}