function GetName();
{
    var name = prompt("What's your name?");
    alert("Hello ${name}!");
}

document.getElementById("GetName").onclick = GetName();
