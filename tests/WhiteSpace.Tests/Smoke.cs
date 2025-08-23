using System.Net.Http.Headers;
using System.Net.Http.Json;
using Xunit;

public class Smoke : IClassFixture<CustomWebAppFactory>
{
    private readonly HttpClient _client;

    public Smoke(CustomWebAppFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task EndToEnd()
    {
        // VALID input (username min 3, email валидный)
        var username = "tom";
        var email = "tom@example.com";
        var password = "pass";

        // register (на чистой БД должен быть 200; если поменяешь фабрику — может быть 409, это ок)
        var reg = await _client.PostAsJsonAsync("/auth/register", new { username, email, password });
        if (!reg.IsSuccessStatusCode && reg.StatusCode != System.Net.HttpStatusCode.Conflict)
        {
            var body = await reg.Content.ReadAsStringAsync();
            throw new Exception($"Register failed: {(int)reg.StatusCode} {reg.StatusCode} :: {body}");
        }

        // login
        var login = await _client.PostAsJsonAsync("/auth/login", new { usernameOrEmail = username, password });
        var loginBody = await login.Content.ReadAsStringAsync();
        login.EnsureSuccessStatusCode(); // если упадёт — в вывод попадёт loginBody
        var loginJson = System.Text.Json.JsonDocument.Parse(loginBody).RootElement;
        var token = loginJson.GetProperty("token").GetString();
        Assert.False(string.IsNullOrWhiteSpace(token));

        // auth client
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // create post
        var post = await _client.PostAsJsonAsync("/posts", new { body = "test from xunit" });
        var postBody = await post.Content.ReadAsStringAsync();
        post.EnsureSuccessStatusCode();

        // feed
        var feed = await _client.GetFromJsonAsync<List<Dictionary<string, object>>>("/feed");
        Assert.NotNull(feed);
        Assert.NotEmpty(feed!);
    }
}