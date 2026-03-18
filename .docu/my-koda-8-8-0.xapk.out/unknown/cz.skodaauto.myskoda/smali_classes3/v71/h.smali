.class public interface abstract Lv71/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public a()Z
    .locals 4

    .line 1
    invoke-interface {p0}, Lv71/h;->f()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-le v0, v1, :cond_1

    .line 7
    .line 8
    invoke-interface {p0}, Lv71/h;->f()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/4 v2, 0x2

    .line 13
    const/4 v3, 0x0

    .line 14
    if-ne v0, v2, :cond_0

    .line 15
    .line 16
    invoke-interface {p0}, Lv71/h;->e()Ljava/util/List;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Lw71/c;

    .line 25
    .line 26
    invoke-interface {p0}, Lv71/h;->e()Ljava/util/List;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, Lw71/c;

    .line 35
    .line 36
    invoke-static {v0, p0}, Lw71/d;->d(Lw71/c;Lw71/c;)Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    if-eqz p0, :cond_0

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    return v3

    .line 44
    :cond_1
    :goto_0
    return v1
.end method

.method public abstract b()Ls71/o;
.end method

.method public abstract c()Z
.end method

.method public abstract d()Lw71/b;
.end method

.method public abstract e()Ljava/util/List;
.end method

.method public abstract f()I
.end method
