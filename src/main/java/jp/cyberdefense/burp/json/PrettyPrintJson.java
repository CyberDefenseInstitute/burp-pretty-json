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

import org.apache.log4j.Logger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

/**
 * @author Toru Tomita
 */
public class PrettyPrintJson {
	static Logger log = Logger.getLogger(PrettyPrintJson.class.toString());
	private static PrettyPrintJson instance;
	private Gson gson = new GsonBuilder().setPrettyPrinting().create();
	private JsonParser jp = new JsonParser();
	
	public PrettyPrintJson() {
		instance = null;
	}
	
	public static PrettyPrintJson getInstance(){
		
		if (instance == null){
			synchronized(PrettyPrintJson.class) {
				if (instance == null){
					instance = new PrettyPrintJson();
					log.debug("a Singletone of PrettyPrintJson");
				}
			}
		}
		return instance;
	}
	
	public String parseJson(String json){
		log.debug("parseJson:" + json);
		JsonElement je = jp.parse(json);
		return gson.toJson(je);
	}

}
