/*
 * Copyright (C) 2016 Cyber Defense Institute.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jp.cyberdefense.burp.json;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * @author Toru Tomita
 */
public class PrettyPrintJsonTest {

	@Test
	public void testJSON() {
		PrettyPrintJson json = new PrettyPrintJson();
		String str = "{\"foodsId\":\"\u3046\u3069\u3093\"}";
		String expected = "{\n" 
				 + "  \"foodsId\": \"うどん\"\n"
				 + "}";
		String actual = json.parseJson(str);
		assertEquals(expected, actual);
		/**
		 *　should be like this...
		 * {
		 * 	"foodsId": "うどん"
		 * }
		 */
	}
}
