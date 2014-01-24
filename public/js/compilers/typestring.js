define(['typescript'], function(TypeScript) {
  'use strict';

  var filename = 'typestring.ts';

  /**
   * Compile a string of TypeScript, return as a string of JavaScript
   *
   * @param {String} input - TypeScript to compile
   * @return {String} JavaScript output
   * @throws TypeScript compile error
   */
  return {
    compile: function(input) {
      var compiler = new TypeScript.TypeScriptCompiler();

      var snapshot = TypeScript.ScriptSnapshot.fromString(input);
      compiler.addFile(filename, snapshot);

      var iter = compiler.compile();

      var output = '';
      while(iter.moveNext()) {
        var current = iter.current().outputFiles[0];
        output += !!current ? current.text : '';
      }

      var diagnostics = compiler.getSemanticDiagnostics(filename);
      if (!output && diagnostics.length) {
        throw new Error(diagnostics[0].text());
      }

      return output;
    }
  };
});
