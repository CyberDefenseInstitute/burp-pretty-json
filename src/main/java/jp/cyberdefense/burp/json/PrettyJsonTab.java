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

import java.awt.Component;
import java.util.List;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.ITextEditor;

/**
 * @author Toru Tomita
 */
public class PrettyJsonTab implements IMessageEditorTab {
	static Logger log = LogManager.getLogger(PrettyJsonTab.class.toString());
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private boolean editable;
	private ITextEditor txtInput;
	private byte[] currentMessage;
  private boolean isRequest;

	public PrettyJsonTab(IMessageEditorController controller, boolean editable,
			IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
		this.editable = editable;
		this.callbacks = callbacks;
		this.helpers = helpers;
		txtInput = this.callbacks.createTextEditor();
		txtInput.setEditable(editable);
		
	}

	public String getTabCaption() {
		log.debug("getTabCaption: Pretty JSON ");
		return "Pretty JSON";
	}

	public Component getUiComponent() {
		return txtInput.getComponent();
	}

	public boolean isEnabled(byte[] content, boolean isReq) {
		// enable this tab for requests containing a data parameter
		// return isReq;
		log.debug("isEnabled: "+ isReq);
		return (isJson(content, isReq));

	}

	public void setMessage(byte[] content, boolean isReq) {
		txtInput.setText(null);
		if (content == null) {
			// clear our display
			txtInput.setText(null);
			txtInput.setEditable(false);
		} else {
			PrettyPrintJson json = PrettyPrintJson.getInstance();
			// retrieve the data parameter
			int offset = isReq ? helpers.analyzeRequest(content).getBodyOffset() : helpers.analyzeResponse(content).getBodyOffset();
			// deserialize the parameter value
			String msg = new String(content, offset, content.length-offset);

			log.debug("setMessage / raw content: "+new String(content, offset, content.length - offset));

			txtInput.setText(json.parseJson(msg).getBytes());
			log.debug("setMessage / formatted json: "+json.parseJson(msg));
			txtInput.setEditable(editable);
		}

		// remember the displayed content
		currentMessage = content;
    isRequest = isReq;
	}

	public byte[] getMessage() {
		// determine whether the user modified the deserialized data
        if (txtInput.isTextModified())
        {
            // reserialize the data
            byte[] body = txtInput.getText();
			      List<String> headers = isRequest ? helpers.analyzeRequest(currentMessage).getHeaders() : helpers.analyzeResponse(currentMessage).getHeaders();
            return helpers.buildHttpMessage(headers, body);
        }
        else return currentMessage;
	}

	private boolean isJson(byte[] content, boolean isReq) {
		boolean isJson = false;
		// in case of response and json 
		if (!isReq){
			IResponseInfo iRes = helpers.analyzeResponse(content);
			String mime = iRes.getStatedMimeType();
			if (mime.equalsIgnoreCase("JSON"))
				return true;
		}
		// in case of request and json
		if (isReq){
			IRequestInfo iReq = helpers.analyzeRequest(content);
			if (IRequestInfo.CONTENT_TYPE_JSON == iReq.getContentType())
				return true;
		}	
		return isJson;
	}

	public boolean isModified() {
		return txtInput.isTextModified();
	}

	public byte[] getSelectedData() {
		return txtInput.getSelectedText();
	}
	

}
