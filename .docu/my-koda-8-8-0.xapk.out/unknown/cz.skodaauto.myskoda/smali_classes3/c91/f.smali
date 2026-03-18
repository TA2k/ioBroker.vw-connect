.class public final Lc91/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Lc91/g;->a:Lqz0/a;

    .line 2
    .line 3
    check-cast p0, Lqz0/a;

    .line 4
    .line 5
    invoke-interface {p1, p0}, Ltz0/c;->d(Lqz0/a;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lc91/m;

    .line 10
    .line 11
    iget-object p1, p0, Lc91/m;->a:Ljava/lang/String;

    .line 12
    .line 13
    if-eqz p1, :cond_1

    .line 14
    .line 15
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-nez p1, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    iget-object p0, p0, Lc91/m;->a:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {p0}, Lio/opentelemetry/sdk/logs/data/Body;->string(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/data/Body;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_1
    :goto_0
    invoke-static {}, Lio/opentelemetry/sdk/logs/data/Body;->empty()Lio/opentelemetry/sdk/logs/data/Body;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 1

    .line 1
    sget-object p0, Lc91/g;->a:Lqz0/a;

    .line 2
    .line 3
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, " io.opentelemetry.sdk.logs.data.Body"

    .line 8
    .line 9
    invoke-static {v0, p0}, Lkp/x8;->b(Ljava/lang/String;Lsz0/g;)Lsz0/m;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p2, Lio/opentelemetry/sdk/logs/data/Body;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lc91/g;->a:Lqz0/a;

    .line 9
    .line 10
    check-cast p0, Lqz0/a;

    .line 11
    .line 12
    new-instance v0, Lc91/m;

    .line 13
    .line 14
    invoke-interface {p2}, Lio/opentelemetry/sdk/logs/data/Body;->asString()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    invoke-direct {v0, p2}, Lc91/m;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-interface {p1, p0, v0}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method
