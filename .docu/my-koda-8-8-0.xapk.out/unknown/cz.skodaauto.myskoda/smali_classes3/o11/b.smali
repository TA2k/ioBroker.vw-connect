.class public abstract Lo11/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public a(Lo11/b;)I
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    goto :goto_2

    .line 5
    :cond_0
    invoke-virtual {p0}, Lo11/b;->h()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p1}, Lo11/b;->h()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const-string v3, "ReadablePartial objects must have matching field types"

    .line 14
    .line 15
    if-ne v1, v2, :cond_6

    .line 16
    .line 17
    invoke-virtual {p0}, Lo11/b;->h()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    move v2, v0

    .line 22
    :goto_0
    if-ge v2, v1, :cond_2

    .line 23
    .line 24
    invoke-virtual {p0, v2}, Lo11/b;->e(I)Ln11/b;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    invoke-virtual {p1, v2}, Lo11/b;->e(I)Ln11/b;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    if-ne v4, v5, :cond_1

    .line 33
    .line 34
    add-int/lit8 v2, v2, 0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    new-instance p0, Ljava/lang/ClassCastException;

    .line 38
    .line 39
    invoke-direct {p0, v3}, Ljava/lang/ClassCastException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_2
    invoke-virtual {p0}, Lo11/b;->h()I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    move v2, v0

    .line 48
    :goto_1
    if-ge v2, v1, :cond_5

    .line 49
    .line 50
    invoke-virtual {p0, v2}, Lo11/b;->f(I)I

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    invoke-virtual {p1, v2}, Lo11/b;->f(I)I

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    if-le v3, v4, :cond_3

    .line 59
    .line 60
    const/4 p0, 0x1

    .line 61
    return p0

    .line 62
    :cond_3
    invoke-virtual {p0, v2}, Lo11/b;->f(I)I

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    invoke-virtual {p1, v2}, Lo11/b;->f(I)I

    .line 67
    .line 68
    .line 69
    move-result v4

    .line 70
    if-ge v3, v4, :cond_4

    .line 71
    .line 72
    const/4 p0, -0x1

    .line 73
    return p0

    .line 74
    :cond_4
    add-int/lit8 v2, v2, 0x1

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_5
    :goto_2
    return v0

    .line 78
    :cond_6
    new-instance p0, Ljava/lang/ClassCastException;

    .line 79
    .line 80
    invoke-direct {p0, v3}, Ljava/lang/ClassCastException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p0
.end method

.method public abstract b(Ln11/b;)I
.end method

.method public abstract c()Ljp/u1;
.end method

.method public abstract d(ILjp/u1;)Ln11/a;
.end method

.method public final e(I)Ln11/b;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lo11/b;->c()Ljp/u1;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0, p1, v0}, Lo11/b;->d(ILjp/u1;)Ln11/a;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Ln11/a;->q()Ln11/b;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lo11/b;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    goto :goto_1

    .line 11
    :cond_1
    check-cast p1, Lo11/b;

    .line 12
    .line 13
    invoke-virtual {p0}, Lo11/b;->h()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-virtual {p1}, Lo11/b;->h()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-eq v1, v3, :cond_2

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_2
    invoke-virtual {p0}, Lo11/b;->h()I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    move v3, v2

    .line 29
    :goto_0
    if-ge v3, v1, :cond_5

    .line 30
    .line 31
    invoke-virtual {p0, v3}, Lo11/b;->f(I)I

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    invoke-virtual {p1, v3}, Lo11/b;->f(I)I

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    if-ne v4, v5, :cond_4

    .line 40
    .line 41
    invoke-virtual {p0, v3}, Lo11/b;->e(I)Ln11/b;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    invoke-virtual {p1, v3}, Lo11/b;->e(I)Ln11/b;

    .line 46
    .line 47
    .line 48
    move-result-object v5

    .line 49
    if-eq v4, v5, :cond_3

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_3
    add-int/lit8 v3, v3, 0x1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_4
    :goto_1
    return v2

    .line 56
    :cond_5
    invoke-virtual {p0}, Lo11/b;->c()Ljp/u1;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-virtual {p1}, Lo11/b;->c()Ljp/u1;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    if-ne p0, p1, :cond_6

    .line 65
    .line 66
    return v0

    .line 67
    :cond_6
    if-eqz p0, :cond_8

    .line 68
    .line 69
    if-nez p1, :cond_7

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_7
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    return p0

    .line 77
    :cond_8
    :goto_2
    return v2
.end method

.method public abstract f(I)I
.end method

.method public abstract g(Ln11/b;)Z
.end method

.method public abstract h()I
.end method

.method public hashCode()I
    .locals 5

    .line 1
    invoke-virtual {p0}, Lo11/b;->h()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x9d

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    :goto_0
    if-ge v2, v0, :cond_0

    .line 9
    .line 10
    mul-int/lit8 v1, v1, 0x17

    .line 11
    .line 12
    invoke-virtual {p0, v2}, Lo11/b;->f(I)I

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    add-int/2addr v3, v1

    .line 17
    mul-int/lit8 v3, v3, 0x17

    .line 18
    .line 19
    invoke-virtual {p0, v2}, Lo11/b;->e(I)Ln11/b;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    iget-byte v1, v1, Ln11/b;->e:B

    .line 24
    .line 25
    const/4 v4, 0x1

    .line 26
    shl-int v1, v4, v1

    .line 27
    .line 28
    add-int/2addr v1, v3

    .line 29
    add-int/lit8 v2, v2, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {p0}, Lo11/b;->c()Ljp/u1;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    add-int/2addr p0, v1

    .line 41
    return p0
.end method
