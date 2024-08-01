<?php

require 'vendor/autoload.php';

use PhpParser\Error;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter;

$code = file_get_contents($argv[1]);

$parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);

try {
    $ast = $parser->parse($code);

    $printer = new PrettyPrinter\Standard;
    $formattedCode = $printer->prettyPrintFile($ast);

    echo json_encode(['code' => $formattedCode], JSON_PRETTY_PRINT);

} catch (Error $e) {
    echo "Parse error: ", $e->getMessage();
}
?>

