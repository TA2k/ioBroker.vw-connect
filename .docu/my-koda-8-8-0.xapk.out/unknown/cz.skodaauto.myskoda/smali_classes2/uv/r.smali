.class public final Luv/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Luv/q;

.field public b:Luv/q;

.field public c:Luv/q;

.field public d:Luv/q;

.field public e:Luv/q;


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    instance-of v0, p1, Luv/r;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    iget-object v0, p0, Luv/r;->a:Luv/q;

    .line 8
    .line 9
    check-cast p1, Luv/r;

    .line 10
    .line 11
    iget-object v2, p1, Luv/r;->a:Luv/q;

    .line 12
    .line 13
    if-ne v0, v2, :cond_1

    .line 14
    .line 15
    iget-object v0, p0, Luv/r;->b:Luv/q;

    .line 16
    .line 17
    iget-object v2, p1, Luv/r;->b:Luv/q;

    .line 18
    .line 19
    if-ne v0, v2, :cond_1

    .line 20
    .line 21
    iget-object v0, p0, Luv/r;->c:Luv/q;

    .line 22
    .line 23
    iget-object v2, p1, Luv/r;->c:Luv/q;

    .line 24
    .line 25
    if-ne v0, v2, :cond_1

    .line 26
    .line 27
    iget-object v0, p0, Luv/r;->d:Luv/q;

    .line 28
    .line 29
    iget-object v2, p1, Luv/r;->d:Luv/q;

    .line 30
    .line 31
    if-ne v0, v2, :cond_1

    .line 32
    .line 33
    iget-object p0, p0, Luv/r;->e:Luv/q;

    .line 34
    .line 35
    iget-object p1, p1, Luv/r;->e:Luv/q;

    .line 36
    .line 37
    if-ne p0, p1, :cond_1

    .line 38
    .line 39
    const/4 p0, 0x1

    .line 40
    return p0

    .line 41
    :cond_1
    return v1
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    iget-object v1, p0, Luv/r;->b:Luv/q;

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    move-object v1, v0

    .line 11
    :cond_0
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    mul-int/lit8 v1, v1, 0xb

    .line 16
    .line 17
    iget-object p0, p0, Luv/r;->e:Luv/q;

    .line 18
    .line 19
    if-nez p0, :cond_1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    move-object v0, p0

    .line 23
    :goto_0
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    mul-int/lit8 p0, p0, 0x7

    .line 28
    .line 29
    add-int/2addr p0, v1

    .line 30
    return p0
.end method
