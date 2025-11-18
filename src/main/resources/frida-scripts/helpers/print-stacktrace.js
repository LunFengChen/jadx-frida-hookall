// Print Java Stack Trace
function showJavaStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

// Usage Example:
// Java.perform(function() {
//     var TargetClass = Java.use('com.example.YourClass');
//     TargetClass.yourMethod.implementation = function() {
//         console.log('[+] Method called');
//         showJavaStacks(); // Print stack trace
//         return this.yourMethod.apply(this, arguments);
//     };
// });
