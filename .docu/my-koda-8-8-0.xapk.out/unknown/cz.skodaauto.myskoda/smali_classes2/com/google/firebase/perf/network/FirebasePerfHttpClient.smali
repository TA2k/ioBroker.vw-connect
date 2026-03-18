.class public Lcom/google/firebase/perf/network/FirebasePerfHttpClient;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static execute(Lorg/apache/http/client/HttpClient;Lorg/apache/http/HttpHost;Lorg/apache/http/HttpRequest;Lorg/apache/http/client/ResponseHandler;)Ljava/lang/Object;
    .locals 5
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lorg/apache/http/client/HttpClient;",
            "Lorg/apache/http/HttpHost;",
            "Lorg/apache/http/HttpRequest;",
            "Lorg/apache/http/client/ResponseHandler<",
            "+TT;>;)TT;"
        }
    .end annotation

    .line 123
    new-instance v0, Lzt/h;

    invoke-direct {v0}, Lzt/h;-><init>()V

    .line 124
    sget-object v1, Lyt/h;->v:Lyt/h;

    .line 125
    new-instance v2, Ltt/e;

    invoke-direct {v2, v1}, Ltt/e;-><init>(Lyt/h;)V

    .line 126
    :try_start_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 127
    invoke-virtual {p1}, Lorg/apache/http/HttpHost;->toURI()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {p2}, Lorg/apache/http/HttpRequest;->getRequestLine()Lorg/apache/http/RequestLine;

    move-result-object v3

    invoke-interface {v3}, Lorg/apache/http/RequestLine;->getUri()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ltt/e;->p(Ljava/lang/String;)V

    .line 128
    invoke-interface {p2}, Lorg/apache/http/HttpRequest;->getRequestLine()Lorg/apache/http/RequestLine;

    move-result-object v1

    invoke-interface {v1}, Lorg/apache/http/RequestLine;->getMethod()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ltt/e;->i(Ljava/lang/String;)V

    .line 129
    invoke-static {p2}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    move-result-object v1

    if-eqz v1, :cond_0

    .line 130
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    move-result-wide v3

    invoke-virtual {v2, v3, v4}, Ltt/e;->k(J)V

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 131
    :cond_0
    :goto_0
    invoke-virtual {v0}, Lzt/h;->l()V

    .line 132
    iget-wide v3, v0, Lzt/h;->d:J

    .line 133
    invoke-virtual {v2, v3, v4}, Ltt/e;->l(J)V

    .line 134
    new-instance v1, Lvt/f;

    invoke-direct {v1, p3, v0, v2}, Lvt/f;-><init>(Lorg/apache/http/client/ResponseHandler;Lzt/h;Ltt/e;)V

    invoke-interface {p0, p1, p2, v1}, Lorg/apache/http/client/HttpClient;->execute(Lorg/apache/http/HttpHost;Lorg/apache/http/HttpRequest;Lorg/apache/http/client/ResponseHandler;)Ljava/lang/Object;

    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    .line 135
    :goto_1
    invoke-static {v0, v2, v2}, Lvj/b;->A(Lzt/h;Ltt/e;Ltt/e;)V

    .line 136
    throw p0
.end method

.method public static execute(Lorg/apache/http/client/HttpClient;Lorg/apache/http/HttpHost;Lorg/apache/http/HttpRequest;Lorg/apache/http/client/ResponseHandler;Lorg/apache/http/protocol/HttpContext;)Ljava/lang/Object;
    .locals 5
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lorg/apache/http/client/HttpClient;",
            "Lorg/apache/http/HttpHost;",
            "Lorg/apache/http/HttpRequest;",
            "Lorg/apache/http/client/ResponseHandler<",
            "+TT;>;",
            "Lorg/apache/http/protocol/HttpContext;",
            ")TT;"
        }
    .end annotation

    .line 140
    new-instance v0, Lzt/h;

    invoke-direct {v0}, Lzt/h;-><init>()V

    .line 141
    sget-object v1, Lyt/h;->v:Lyt/h;

    .line 142
    new-instance v2, Ltt/e;

    invoke-direct {v2, v1}, Ltt/e;-><init>(Lyt/h;)V

    .line 143
    :try_start_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 144
    invoke-virtual {p1}, Lorg/apache/http/HttpHost;->toURI()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {p2}, Lorg/apache/http/HttpRequest;->getRequestLine()Lorg/apache/http/RequestLine;

    move-result-object v3

    invoke-interface {v3}, Lorg/apache/http/RequestLine;->getUri()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ltt/e;->p(Ljava/lang/String;)V

    .line 145
    invoke-interface {p2}, Lorg/apache/http/HttpRequest;->getRequestLine()Lorg/apache/http/RequestLine;

    move-result-object v1

    invoke-interface {v1}, Lorg/apache/http/RequestLine;->getMethod()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ltt/e;->i(Ljava/lang/String;)V

    .line 146
    invoke-static {p2}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    move-result-object v1

    if-eqz v1, :cond_0

    .line 147
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    move-result-wide v3

    invoke-virtual {v2, v3, v4}, Ltt/e;->k(J)V

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 148
    :cond_0
    :goto_0
    invoke-virtual {v0}, Lzt/h;->l()V

    .line 149
    iget-wide v3, v0, Lzt/h;->d:J

    .line 150
    invoke-virtual {v2, v3, v4}, Ltt/e;->l(J)V

    .line 151
    new-instance v1, Lvt/f;

    invoke-direct {v1, p3, v0, v2}, Lvt/f;-><init>(Lorg/apache/http/client/ResponseHandler;Lzt/h;Ltt/e;)V

    invoke-interface {p0, p1, p2, v1, p4}, Lorg/apache/http/client/HttpClient;->execute(Lorg/apache/http/HttpHost;Lorg/apache/http/HttpRequest;Lorg/apache/http/client/ResponseHandler;Lorg/apache/http/protocol/HttpContext;)Ljava/lang/Object;

    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    .line 152
    :goto_1
    invoke-static {v0, v2, v2}, Lvj/b;->A(Lzt/h;Ltt/e;Ltt/e;)V

    .line 153
    throw p0
.end method

.method public static execute(Lorg/apache/http/client/HttpClient;Lorg/apache/http/client/methods/HttpUriRequest;Lorg/apache/http/client/ResponseHandler;)Ljava/lang/Object;
    .locals 5
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lorg/apache/http/client/HttpClient;",
            "Lorg/apache/http/client/methods/HttpUriRequest;",
            "Lorg/apache/http/client/ResponseHandler<",
            "TT;>;)TT;"
        }
    .end annotation

    .line 1
    new-instance v0, Lzt/h;

    invoke-direct {v0}, Lzt/h;-><init>()V

    .line 2
    sget-object v1, Lyt/h;->v:Lyt/h;

    .line 3
    new-instance v2, Ltt/e;

    invoke-direct {v2, v1}, Ltt/e;-><init>(Lyt/h;)V

    .line 4
    :try_start_0
    invoke-interface {p1}, Lorg/apache/http/client/methods/HttpUriRequest;->getURI()Ljava/net/URI;

    move-result-object v1

    invoke-virtual {v1}, Ljava/net/URI;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ltt/e;->p(Ljava/lang/String;)V

    invoke-interface {p1}, Lorg/apache/http/client/methods/HttpUriRequest;->getMethod()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ltt/e;->i(Ljava/lang/String;)V

    .line 5
    invoke-static {p1}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    move-result-object v1

    if-eqz v1, :cond_0

    .line 6
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    move-result-wide v3

    invoke-virtual {v2, v3, v4}, Ltt/e;->k(J)V

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 7
    :cond_0
    :goto_0
    invoke-virtual {v0}, Lzt/h;->l()V

    .line 8
    iget-wide v3, v0, Lzt/h;->d:J

    .line 9
    invoke-virtual {v2, v3, v4}, Ltt/e;->l(J)V

    .line 10
    new-instance v1, Lvt/f;

    invoke-direct {v1, p2, v0, v2}, Lvt/f;-><init>(Lorg/apache/http/client/ResponseHandler;Lzt/h;Ltt/e;)V

    invoke-interface {p0, p1, v1}, Lorg/apache/http/client/HttpClient;->execute(Lorg/apache/http/client/methods/HttpUriRequest;Lorg/apache/http/client/ResponseHandler;)Ljava/lang/Object;

    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    .line 11
    :goto_1
    invoke-static {v0, v2, v2}, Lvj/b;->A(Lzt/h;Ltt/e;Ltt/e;)V

    .line 12
    throw p0
.end method

.method public static execute(Lorg/apache/http/client/HttpClient;Lorg/apache/http/client/methods/HttpUriRequest;Lorg/apache/http/client/ResponseHandler;Lorg/apache/http/protocol/HttpContext;)Ljava/lang/Object;
    .locals 5
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lorg/apache/http/client/HttpClient;",
            "Lorg/apache/http/client/methods/HttpUriRequest;",
            "Lorg/apache/http/client/ResponseHandler<",
            "TT;>;",
            "Lorg/apache/http/protocol/HttpContext;",
            ")TT;"
        }
    .end annotation

    .line 108
    new-instance v0, Lzt/h;

    invoke-direct {v0}, Lzt/h;-><init>()V

    .line 109
    sget-object v1, Lyt/h;->v:Lyt/h;

    .line 110
    new-instance v2, Ltt/e;

    invoke-direct {v2, v1}, Ltt/e;-><init>(Lyt/h;)V

    .line 111
    :try_start_0
    invoke-interface {p1}, Lorg/apache/http/client/methods/HttpUriRequest;->getURI()Ljava/net/URI;

    move-result-object v1

    invoke-virtual {v1}, Ljava/net/URI;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ltt/e;->p(Ljava/lang/String;)V

    invoke-interface {p1}, Lorg/apache/http/client/methods/HttpUriRequest;->getMethod()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ltt/e;->i(Ljava/lang/String;)V

    .line 112
    invoke-static {p1}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    move-result-object v1

    if-eqz v1, :cond_0

    .line 113
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    move-result-wide v3

    invoke-virtual {v2, v3, v4}, Ltt/e;->k(J)V

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 114
    :cond_0
    :goto_0
    invoke-virtual {v0}, Lzt/h;->l()V

    .line 115
    iget-wide v3, v0, Lzt/h;->d:J

    .line 116
    invoke-virtual {v2, v3, v4}, Ltt/e;->l(J)V

    .line 117
    new-instance v1, Lvt/f;

    invoke-direct {v1, p2, v0, v2}, Lvt/f;-><init>(Lorg/apache/http/client/ResponseHandler;Lzt/h;Ltt/e;)V

    invoke-interface {p0, p1, v1, p3}, Lorg/apache/http/client/HttpClient;->execute(Lorg/apache/http/client/methods/HttpUriRequest;Lorg/apache/http/client/ResponseHandler;Lorg/apache/http/protocol/HttpContext;)Ljava/lang/Object;

    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    .line 118
    :goto_1
    invoke-static {v0, v2, v2}, Lvj/b;->A(Lzt/h;Ltt/e;Ltt/e;)V

    .line 119
    throw p0
.end method

.method public static execute(Lorg/apache/http/client/HttpClient;Lorg/apache/http/HttpHost;Lorg/apache/http/HttpRequest;)Lorg/apache/http/HttpResponse;
    .locals 6
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 16
    invoke-static {}, Lzt/h;->m()J

    invoke-static {}, Lzt/h;->h()J

    move-result-wide v0

    .line 17
    sget-object v2, Lyt/h;->v:Lyt/h;

    .line 18
    new-instance v3, Ltt/e;

    invoke-direct {v3, v2}, Ltt/e;-><init>(Lyt/h;)V

    .line 19
    :try_start_0
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 20
    invoke-virtual {p1}, Lorg/apache/http/HttpHost;->toURI()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {p2}, Lorg/apache/http/HttpRequest;->getRequestLine()Lorg/apache/http/RequestLine;

    move-result-object v4

    invoke-interface {v4}, Lorg/apache/http/RequestLine;->getUri()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3, v2}, Ltt/e;->p(Ljava/lang/String;)V

    .line 21
    invoke-interface {p2}, Lorg/apache/http/HttpRequest;->getRequestLine()Lorg/apache/http/RequestLine;

    move-result-object v2

    invoke-interface {v2}, Lorg/apache/http/RequestLine;->getMethod()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3, v2}, Ltt/e;->i(Ljava/lang/String;)V

    .line 22
    invoke-static {p2}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    move-result-object v2

    if-eqz v2, :cond_0

    .line 23
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    move-result-wide v4

    invoke-virtual {v3, v4, v5}, Ltt/e;->k(J)V

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 24
    :cond_0
    :goto_0
    invoke-static {}, Lzt/h;->m()J

    move-result-wide v4

    .line 25
    invoke-static {}, Lzt/h;->h()J

    move-result-wide v0

    .line 26
    invoke-virtual {v3, v4, v5}, Ltt/e;->l(J)V

    .line 27
    invoke-interface {p0, p1, p2}, Lorg/apache/http/client/HttpClient;->execute(Lorg/apache/http/HttpHost;Lorg/apache/http/HttpRequest;)Lorg/apache/http/HttpResponse;

    move-result-object p0

    .line 28
    invoke-static {}, Lzt/h;->m()J

    invoke-static {}, Lzt/h;->h()J

    move-result-wide p1

    sub-long/2addr p1, v0

    .line 29
    invoke-virtual {v3, p1, p2}, Ltt/e;->o(J)V

    .line 30
    invoke-interface {p0}, Lorg/apache/http/HttpResponse;->getStatusLine()Lorg/apache/http/StatusLine;

    move-result-object p1

    invoke-interface {p1}, Lorg/apache/http/StatusLine;->getStatusCode()I

    move-result p1

    invoke-virtual {v3, p1}, Ltt/e;->j(I)V

    .line 31
    invoke-static {p0}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    move-result-object p1

    if-eqz p1, :cond_1

    .line 32
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    move-result-wide p1

    invoke-virtual {v3, p1, p2}, Ltt/e;->n(J)V

    .line 33
    :cond_1
    invoke-static {p0}, Lvt/g;->b(Lorg/apache/http/HttpResponse;)Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_2

    .line 34
    invoke-virtual {v3, p1}, Ltt/e;->m(Ljava/lang/String;)V

    .line 35
    :cond_2
    invoke-virtual {v3}, Ltt/e;->h()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    .line 36
    :goto_1
    invoke-static {}, Lzt/h;->m()J

    invoke-static {}, Lzt/h;->h()J

    move-result-wide p1

    sub-long/2addr p1, v0

    .line 37
    invoke-virtual {v3, p1, p2}, Ltt/e;->o(J)V

    .line 38
    invoke-static {v3}, Lvt/g;->c(Ltt/e;)V

    .line 39
    throw p0
.end method

.method public static execute(Lorg/apache/http/client/HttpClient;Lorg/apache/http/HttpHost;Lorg/apache/http/HttpRequest;Lorg/apache/http/protocol/HttpContext;)Lorg/apache/http/HttpResponse;
    .locals 6
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 40
    invoke-static {}, Lzt/h;->m()J

    invoke-static {}, Lzt/h;->h()J

    move-result-wide v0

    .line 41
    sget-object v2, Lyt/h;->v:Lyt/h;

    .line 42
    new-instance v3, Ltt/e;

    invoke-direct {v3, v2}, Ltt/e;-><init>(Lyt/h;)V

    .line 43
    :try_start_0
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 44
    invoke-virtual {p1}, Lorg/apache/http/HttpHost;->toURI()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {p2}, Lorg/apache/http/HttpRequest;->getRequestLine()Lorg/apache/http/RequestLine;

    move-result-object v4

    invoke-interface {v4}, Lorg/apache/http/RequestLine;->getUri()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3, v2}, Ltt/e;->p(Ljava/lang/String;)V

    .line 45
    invoke-interface {p2}, Lorg/apache/http/HttpRequest;->getRequestLine()Lorg/apache/http/RequestLine;

    move-result-object v2

    invoke-interface {v2}, Lorg/apache/http/RequestLine;->getMethod()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3, v2}, Ltt/e;->i(Ljava/lang/String;)V

    .line 46
    invoke-static {p2}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    move-result-object v2

    if-eqz v2, :cond_0

    .line 47
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    move-result-wide v4

    invoke-virtual {v3, v4, v5}, Ltt/e;->k(J)V

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 48
    :cond_0
    :goto_0
    invoke-static {}, Lzt/h;->m()J

    move-result-wide v4

    .line 49
    invoke-static {}, Lzt/h;->h()J

    move-result-wide v0

    .line 50
    invoke-virtual {v3, v4, v5}, Ltt/e;->l(J)V

    .line 51
    invoke-interface {p0, p1, p2, p3}, Lorg/apache/http/client/HttpClient;->execute(Lorg/apache/http/HttpHost;Lorg/apache/http/HttpRequest;Lorg/apache/http/protocol/HttpContext;)Lorg/apache/http/HttpResponse;

    move-result-object p0

    .line 52
    invoke-static {}, Lzt/h;->m()J

    invoke-static {}, Lzt/h;->h()J

    move-result-wide p1

    sub-long/2addr p1, v0

    .line 53
    invoke-virtual {v3, p1, p2}, Ltt/e;->o(J)V

    .line 54
    invoke-interface {p0}, Lorg/apache/http/HttpResponse;->getStatusLine()Lorg/apache/http/StatusLine;

    move-result-object p1

    invoke-interface {p1}, Lorg/apache/http/StatusLine;->getStatusCode()I

    move-result p1

    invoke-virtual {v3, p1}, Ltt/e;->j(I)V

    .line 55
    invoke-static {p0}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    move-result-object p1

    if-eqz p1, :cond_1

    .line 56
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    move-result-wide p1

    invoke-virtual {v3, p1, p2}, Ltt/e;->n(J)V

    .line 57
    :cond_1
    invoke-static {p0}, Lvt/g;->b(Lorg/apache/http/HttpResponse;)Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_2

    .line 58
    invoke-virtual {v3, p1}, Ltt/e;->m(Ljava/lang/String;)V

    .line 59
    :cond_2
    invoke-virtual {v3}, Ltt/e;->h()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    .line 60
    :goto_1
    invoke-static {}, Lzt/h;->m()J

    invoke-static {}, Lzt/h;->h()J

    move-result-wide p1

    sub-long/2addr p1, v0

    .line 61
    invoke-virtual {v3, p1, p2}, Ltt/e;->o(J)V

    .line 62
    invoke-static {v3}, Lvt/g;->c(Ltt/e;)V

    .line 63
    throw p0
.end method

.method public static execute(Lorg/apache/http/client/HttpClient;Lorg/apache/http/client/methods/HttpUriRequest;)Lorg/apache/http/HttpResponse;
    .locals 6
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 64
    invoke-static {}, Lzt/h;->m()J

    invoke-static {}, Lzt/h;->h()J

    move-result-wide v0

    .line 65
    sget-object v2, Lyt/h;->v:Lyt/h;

    .line 66
    new-instance v3, Ltt/e;

    invoke-direct {v3, v2}, Ltt/e;-><init>(Lyt/h;)V

    .line 67
    :try_start_0
    invoke-interface {p1}, Lorg/apache/http/client/methods/HttpUriRequest;->getURI()Ljava/net/URI;

    move-result-object v2

    invoke-virtual {v2}, Ljava/net/URI;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3, v2}, Ltt/e;->p(Ljava/lang/String;)V

    invoke-interface {p1}, Lorg/apache/http/client/methods/HttpUriRequest;->getMethod()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3, v2}, Ltt/e;->i(Ljava/lang/String;)V

    .line 68
    invoke-static {p1}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    move-result-object v2

    if-eqz v2, :cond_0

    .line 69
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    move-result-wide v4

    invoke-virtual {v3, v4, v5}, Ltt/e;->k(J)V

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 70
    :cond_0
    :goto_0
    invoke-static {}, Lzt/h;->m()J

    move-result-wide v4

    .line 71
    invoke-static {}, Lzt/h;->h()J

    move-result-wide v0

    .line 72
    invoke-virtual {v3, v4, v5}, Ltt/e;->l(J)V

    .line 73
    invoke-interface {p0, p1}, Lorg/apache/http/client/HttpClient;->execute(Lorg/apache/http/client/methods/HttpUriRequest;)Lorg/apache/http/HttpResponse;

    move-result-object p0

    .line 74
    invoke-static {}, Lzt/h;->m()J

    invoke-static {}, Lzt/h;->h()J

    move-result-wide v4

    sub-long/2addr v4, v0

    .line 75
    invoke-virtual {v3, v4, v5}, Ltt/e;->o(J)V

    .line 76
    invoke-interface {p0}, Lorg/apache/http/HttpResponse;->getStatusLine()Lorg/apache/http/StatusLine;

    move-result-object p1

    invoke-interface {p1}, Lorg/apache/http/StatusLine;->getStatusCode()I

    move-result p1

    invoke-virtual {v3, p1}, Ltt/e;->j(I)V

    .line 77
    invoke-static {p0}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    move-result-object p1

    if-eqz p1, :cond_1

    .line 78
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    move-result-wide v4

    invoke-virtual {v3, v4, v5}, Ltt/e;->n(J)V

    .line 79
    :cond_1
    invoke-static {p0}, Lvt/g;->b(Lorg/apache/http/HttpResponse;)Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_2

    .line 80
    invoke-virtual {v3, p1}, Ltt/e;->m(Ljava/lang/String;)V

    .line 81
    :cond_2
    invoke-virtual {v3}, Ltt/e;->h()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    .line 82
    :goto_1
    invoke-static {}, Lzt/h;->m()J

    invoke-static {}, Lzt/h;->h()J

    move-result-wide v4

    sub-long/2addr v4, v0

    .line 83
    invoke-virtual {v3, v4, v5}, Ltt/e;->o(J)V

    .line 84
    invoke-static {v3}, Lvt/g;->c(Ltt/e;)V

    .line 85
    throw p0
.end method

.method public static execute(Lorg/apache/http/client/HttpClient;Lorg/apache/http/client/methods/HttpUriRequest;Lorg/apache/http/protocol/HttpContext;)Lorg/apache/http/HttpResponse;
    .locals 6
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 86
    invoke-static {}, Lzt/h;->m()J

    invoke-static {}, Lzt/h;->h()J

    move-result-wide v0

    .line 87
    sget-object v2, Lyt/h;->v:Lyt/h;

    .line 88
    new-instance v3, Ltt/e;

    invoke-direct {v3, v2}, Ltt/e;-><init>(Lyt/h;)V

    .line 89
    :try_start_0
    invoke-interface {p1}, Lorg/apache/http/client/methods/HttpUriRequest;->getURI()Ljava/net/URI;

    move-result-object v2

    invoke-virtual {v2}, Ljava/net/URI;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3, v2}, Ltt/e;->p(Ljava/lang/String;)V

    invoke-interface {p1}, Lorg/apache/http/client/methods/HttpUriRequest;->getMethod()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3, v2}, Ltt/e;->i(Ljava/lang/String;)V

    .line 90
    invoke-static {p1}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    move-result-object v2

    if-eqz v2, :cond_0

    .line 91
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    move-result-wide v4

    invoke-virtual {v3, v4, v5}, Ltt/e;->k(J)V

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 92
    :cond_0
    :goto_0
    invoke-static {}, Lzt/h;->m()J

    move-result-wide v4

    .line 93
    invoke-static {}, Lzt/h;->h()J

    move-result-wide v0

    .line 94
    invoke-virtual {v3, v4, v5}, Ltt/e;->l(J)V

    .line 95
    invoke-interface {p0, p1, p2}, Lorg/apache/http/client/HttpClient;->execute(Lorg/apache/http/client/methods/HttpUriRequest;Lorg/apache/http/protocol/HttpContext;)Lorg/apache/http/HttpResponse;

    move-result-object p0

    .line 96
    invoke-static {}, Lzt/h;->m()J

    invoke-static {}, Lzt/h;->h()J

    move-result-wide p1

    sub-long/2addr p1, v0

    .line 97
    invoke-virtual {v3, p1, p2}, Ltt/e;->o(J)V

    .line 98
    invoke-interface {p0}, Lorg/apache/http/HttpResponse;->getStatusLine()Lorg/apache/http/StatusLine;

    move-result-object p1

    invoke-interface {p1}, Lorg/apache/http/StatusLine;->getStatusCode()I

    move-result p1

    invoke-virtual {v3, p1}, Ltt/e;->j(I)V

    .line 99
    invoke-static {p0}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    move-result-object p1

    if-eqz p1, :cond_1

    .line 100
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    move-result-wide p1

    invoke-virtual {v3, p1, p2}, Ltt/e;->n(J)V

    .line 101
    :cond_1
    invoke-static {p0}, Lvt/g;->b(Lorg/apache/http/HttpResponse;)Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_2

    .line 102
    invoke-virtual {v3, p1}, Ltt/e;->m(Ljava/lang/String;)V

    .line 103
    :cond_2
    invoke-virtual {v3}, Ltt/e;->h()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    .line 104
    :goto_1
    invoke-static {}, Lzt/h;->m()J

    invoke-static {}, Lzt/h;->h()J

    move-result-wide p1

    sub-long/2addr p1, v0

    .line 105
    invoke-virtual {v3, p1, p2}, Ltt/e;->o(J)V

    .line 106
    invoke-static {v3}, Lvt/g;->c(Ltt/e;)V

    .line 107
    throw p0
.end method
