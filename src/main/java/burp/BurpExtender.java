package burp;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import jp.cyberdefense.burp.json.PrettyJsonTab;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;


public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
	static Logger log = Logger.getLogger(BurpExtender.class.toString());
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
	public IMessageEditorTab createNewInstance(
			IMessageEditorController controller, boolean editable) {
		Path currentRelativePath = Paths.get("");
		String s = currentRelativePath.toAbsolutePath().toString();
		
		PropertyConfigurator.configure(s + "/log4j.properties");
		
		log.debug("create a new instance of PrettyJsonTab");
		
        return new PrettyJsonTab(controller, editable,callbacks, helpers);
        
	}

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        log.debug("keep a reference to our callbacks object");
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        log.debug("obtain an extension helpers object");
        
        // set our extension name
        callbacks.setExtensionName("Pretty print JSON editor");
        log.debug("set our extension name");
        
        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);
        log.debug("register ourselves as a message editor tab factory");
	}

}
