using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapPost("/encrypt",  ([FromBody] string cadena)  =>
{
     // Realiza la operación deseada con el parámetro.
    string cadenaEncriptada = Encript.EncriptadorClave.Encriptar(cadena);

    // Devuelve la salida de la operación
    return (cadenaEncriptada);
})
.WithName("encrypt")
.WithOpenApi();

app.MapPost("/decrypt",  ([FromBody] string cadenacifrada)  =>
{
     // Realiza la operación deseada con el parámetro.
    string cadenaDecifrada = Encript.EncriptadorClave.DesEncriptar(cadenacifrada);

    // Devuelve la salida de la operación
    return (cadenaDecifrada);
})
.WithName("decrypt")
.WithOpenApi();

app.Run();

