.class public final Lka/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public b:I

.field public c:I


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    goto :goto_0

    .line 5
    :cond_0
    instance-of v1, p1, Lka/a;

    .line 6
    .line 7
    if-nez v1, :cond_1

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_1
    check-cast p1, Lka/a;

    .line 11
    .line 12
    iget v1, p0, Lka/a;->a:I

    .line 13
    .line 14
    iget v2, p1, Lka/a;->a:I

    .line 15
    .line 16
    if-eq v1, v2, :cond_2

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_2
    const/16 v2, 0x8

    .line 20
    .line 21
    if-ne v1, v2, :cond_3

    .line 22
    .line 23
    iget v1, p0, Lka/a;->c:I

    .line 24
    .line 25
    iget v2, p0, Lka/a;->b:I

    .line 26
    .line 27
    sub-int/2addr v1, v2

    .line 28
    invoke-static {v1}, Ljava/lang/Math;->abs(I)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-ne v1, v0, :cond_3

    .line 33
    .line 34
    iget v1, p0, Lka/a;->c:I

    .line 35
    .line 36
    iget v2, p1, Lka/a;->b:I

    .line 37
    .line 38
    if-ne v1, v2, :cond_3

    .line 39
    .line 40
    iget v1, p0, Lka/a;->b:I

    .line 41
    .line 42
    iget v2, p1, Lka/a;->c:I

    .line 43
    .line 44
    if-ne v1, v2, :cond_3

    .line 45
    .line 46
    :goto_0
    return v0

    .line 47
    :cond_3
    iget v1, p0, Lka/a;->c:I

    .line 48
    .line 49
    iget v2, p1, Lka/a;->c:I

    .line 50
    .line 51
    if-eq v1, v2, :cond_4

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_4
    iget p0, p0, Lka/a;->b:I

    .line 55
    .line 56
    iget p1, p1, Lka/a;->b:I

    .line 57
    .line 58
    if-eq p0, p1, :cond_5

    .line 59
    .line 60
    :goto_1
    const/4 p0, 0x0

    .line 61
    return p0

    .line 62
    :cond_5
    return v0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget v0, p0, Lka/a;->a:I

    .line 2
    .line 3
    mul-int/lit8 v0, v0, 0x1f

    .line 4
    .line 5
    iget v1, p0, Lka/a;->b:I

    .line 6
    .line 7
    add-int/2addr v0, v1

    .line 8
    mul-int/lit8 v0, v0, 0x1f

    .line 9
    .line 10
    iget p0, p0, Lka/a;->c:I

    .line 11
    .line 12
    add-int/2addr v0, p0

    .line 13
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    invoke-static {v1}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, "["

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget v1, p0, Lka/a;->a:I

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    if-eq v1, v2, :cond_3

    .line 26
    .line 27
    const/4 v2, 0x2

    .line 28
    if-eq v1, v2, :cond_2

    .line 29
    .line 30
    const/4 v2, 0x4

    .line 31
    if-eq v1, v2, :cond_1

    .line 32
    .line 33
    const/16 v2, 0x8

    .line 34
    .line 35
    if-eq v1, v2, :cond_0

    .line 36
    .line 37
    const-string v1, "??"

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    const-string v1, "mv"

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    const-string v1, "up"

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    const-string v1, "rm"

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_3
    const-string v1, "add"

    .line 50
    .line 51
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ",s:"

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    iget v1, p0, Lka/a;->b:I

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v1, "c:"

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    iget p0, p0, Lka/a;->c:I

    .line 70
    .line 71
    const-string v1, ",p:null]"

    .line 72
    .line 73
    invoke-static {p0, v1, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0
.end method
