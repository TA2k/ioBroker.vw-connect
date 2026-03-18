.class public final Lw3/e;
.super Lh/w;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static d:Lw3/e;


# virtual methods
.method public final e(I)[I
    .locals 4

    .line 1
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-gtz v0, :cond_0

    .line 10
    .line 11
    goto :goto_2

    .line 12
    :cond_0
    if-lt p1, v0, :cond_1

    .line 13
    .line 14
    goto :goto_2

    .line 15
    :cond_1
    if-gez p1, :cond_2

    .line 16
    .line 17
    const/4 p1, 0x0

    .line 18
    :cond_2
    :goto_0
    if-ge p1, v0, :cond_4

    .line 19
    .line 20
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v1, p1}, Ljava/lang/String;->charAt(I)C

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    const/16 v2, 0xa

    .line 29
    .line 30
    if-ne v1, v2, :cond_4

    .line 31
    .line 32
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-virtual {v1, p1}, Ljava/lang/String;->charAt(I)C

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eq v1, v2, :cond_3

    .line 41
    .line 42
    if-eqz p1, :cond_4

    .line 43
    .line 44
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    add-int/lit8 v3, p1, -0x1

    .line 49
    .line 50
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-ne v1, v2, :cond_3

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    add-int/lit8 p1, p1, 0x1

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_4
    :goto_1
    if-lt p1, v0, :cond_5

    .line 61
    .line 62
    :goto_2
    const/4 p0, 0x0

    .line 63
    return-object p0

    .line 64
    :cond_5
    add-int/lit8 v1, p1, 0x1

    .line 65
    .line 66
    :goto_3
    if-ge v1, v0, :cond_6

    .line 67
    .line 68
    invoke-virtual {p0, v1}, Lw3/e;->q(I)Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-nez v2, :cond_6

    .line 73
    .line 74
    add-int/lit8 v1, v1, 0x1

    .line 75
    .line 76
    goto :goto_3

    .line 77
    :cond_6
    invoke-virtual {p0, p1, v1}, Lh/w;->i(II)[I

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0
.end method

.method public final m(I)[I
    .locals 4

    .line 1
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-gtz v0, :cond_0

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_0
    if-gtz p1, :cond_1

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_1
    if-le p1, v0, :cond_2

    .line 16
    .line 17
    move p1, v0

    .line 18
    :cond_2
    :goto_0
    const/16 v0, 0xa

    .line 19
    .line 20
    if-lez p1, :cond_3

    .line 21
    .line 22
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    add-int/lit8 v2, p1, -0x1

    .line 27
    .line 28
    invoke-virtual {v1, v2}, Ljava/lang/String;->charAt(I)C

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-ne v1, v0, :cond_3

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lw3/e;->q(I)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-nez v1, :cond_3

    .line 39
    .line 40
    add-int/lit8 p1, p1, -0x1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_3
    if-gtz p1, :cond_4

    .line 44
    .line 45
    :goto_1
    const/4 p0, 0x0

    .line 46
    return-object p0

    .line 47
    :cond_4
    add-int/lit8 v1, p1, -0x1

    .line 48
    .line 49
    :goto_2
    if-lez v1, :cond_6

    .line 50
    .line 51
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-virtual {v2, v1}, Ljava/lang/String;->charAt(I)C

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    if-eq v2, v0, :cond_5

    .line 60
    .line 61
    if-eqz v1, :cond_6

    .line 62
    .line 63
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    add-int/lit8 v3, v1, -0x1

    .line 68
    .line 69
    invoke-virtual {v2, v3}, Ljava/lang/String;->charAt(I)C

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    if-ne v2, v0, :cond_5

    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_5
    add-int/lit8 v1, v1, -0x1

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_6
    :goto_3
    invoke-virtual {p0, v1, p1}, Lh/w;->i(II)[I

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0
.end method

.method public final q(I)Z
    .locals 2

    .line 1
    if-lez p1, :cond_1

    .line 2
    .line 3
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    add-int/lit8 v1, p1, -0x1

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/String;->charAt(I)C

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/16 v1, 0xa

    .line 14
    .line 15
    if-eq v0, v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eq p1, v0, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-virtual {p0, p1}, Ljava/lang/String;->charAt(I)C

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    if-ne p0, v1, :cond_1

    .line 36
    .line 37
    :cond_0
    const/4 p0, 0x1

    .line 38
    return p0

    .line 39
    :cond_1
    const/4 p0, 0x0

    .line 40
    return p0
.end method
