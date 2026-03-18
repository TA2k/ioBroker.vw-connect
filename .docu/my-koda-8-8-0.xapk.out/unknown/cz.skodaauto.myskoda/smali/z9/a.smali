.class public final Lz9/a;
.super Lz9/u;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    const/4 v1, 0x0

    .line 6
    if-eqz p1, :cond_2

    .line 7
    .line 8
    instance-of v2, p1, Lz9/a;

    .line 9
    .line 10
    if-nez v2, :cond_1

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_1
    invoke-super {p0, p1}, Lz9/u;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_2

    .line 18
    .line 19
    move-object p0, p1

    .line 20
    check-cast p0, Lz9/a;

    .line 21
    .line 22
    check-cast p1, Lz9/a;

    .line 23
    .line 24
    return v0

    .line 25
    :cond_2
    :goto_0
    return v1
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    invoke-super {p0}, Lz9/u;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    mul-int/lit16 p0, p0, 0x3c1

    .line 6
    .line 7
    return p0
.end method
