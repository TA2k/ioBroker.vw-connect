.class public final Lu3/a;
.super Llp/e1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Lu3/f;


# virtual methods
.method public final a(Lu3/h;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lu3/a;->a:Lu3/f;

    .line 2
    .line 3
    invoke-interface {p0}, Lu3/f;->getKey()Lu3/h;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-ne p1, p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public final b(Lu3/h;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lu3/a;->a:Lu3/f;

    .line 2
    .line 3
    invoke-interface {v0}, Lu3/f;->getKey()Lu3/h;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-ne p1, v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string p1, "Check failed."

    .line 11
    .line 12
    invoke-static {p1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :goto_0
    iget-object p0, p0, Lu3/a;->a:Lu3/f;

    .line 16
    .line 17
    invoke-interface {p0}, Lu3/f;->d()Lk1/q1;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
