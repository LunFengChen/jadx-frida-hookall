// Print Function Arguments
function printArgs(args) {
    console.log("========== Arguments ==========");
    for (var i = 0; i < args.length; i++) {
        console.log("  arg[" + i + "]: " + args[i]);
        if (args[i] != null) {
            console.log("    type: " + typeof args[i]);
        }
    }
    console.log("================================");
}

// Usage Example:
// Java.perform(function() {
//     var TargetClass = Java.use('com.example.YourClass');
//     TargetClass.yourMethod.implementation = function() {
//         printArgs(arguments);
//         return this.yourMethod.apply(this, arguments);
//     };
// });
