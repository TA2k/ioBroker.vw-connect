.class public abstract Lmx0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static A([J)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length p0, p0

    .line 7
    add-int/lit8 p0, p0, -0x1

    .line 8
    .line 9
    return p0
.end method

.method public static B(I[I)Ljava/lang/Integer;
    .locals 1

    .line 1
    if-ltz p0, :cond_0

    .line 2
    .line 3
    array-length v0, p1

    .line 4
    if-ge p0, v0, :cond_0

    .line 5
    .line 6
    aget p0, p1, p0

    .line 7
    .line 8
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return-object p0
.end method

.method public static C(I[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-ltz p0, :cond_0

    .line 7
    .line 8
    array-length v0, p1

    .line 9
    if-ge p0, v0, :cond_0

    .line 10
    .line 11
    aget-object p0, p1, p0

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return-object p0
.end method

.method public static D(Ljava/lang/Object;[Ljava/lang/Object;)I
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    if-nez p0, :cond_1

    .line 8
    .line 9
    array-length p0, p1

    .line 10
    :goto_0
    if-ge v0, p0, :cond_3

    .line 11
    .line 12
    aget-object v1, p1, v0

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    return v0

    .line 17
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_1
    array-length v1, p1

    .line 21
    :goto_1
    if-ge v0, v1, :cond_3

    .line 22
    .line 23
    aget-object v2, p1, v0

    .line 24
    .line 25
    invoke-virtual {p0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-eqz v2, :cond_2

    .line 30
    .line 31
    return v0

    .line 32
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_3
    const/4 p0, -0x1

    .line 36
    return p0
.end method

.method public static final E([Ljava/lang/Object;Ljava/lang/StringBuilder;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Lay0/k;)V
    .locals 3

    .line 1
    const-string p5, "<this>"

    .line 2
    .line 3
    invoke-static {p0, p5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 7
    .line 8
    .line 9
    array-length p3, p0

    .line 10
    const/4 p5, 0x0

    .line 11
    move v0, p5

    .line 12
    :goto_0
    if-ge p5, p3, :cond_1

    .line 13
    .line 14
    aget-object v1, p0, p5

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    add-int/2addr v0, v2

    .line 18
    if-le v0, v2, :cond_0

    .line 19
    .line 20
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 21
    .line 22
    .line 23
    :cond_0
    invoke-static {p1, v1, p6}, Lly0/q;->a(Ljava/lang/Appendable;Ljava/lang/Object;Lay0/k;)V

    .line 24
    .line 25
    .line 26
    add-int/lit8 p5, p5, 0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    invoke-virtual {p1, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public static F([BLjava/lang/String;Lf31/n;I)Ljava/lang/String;
    .locals 7

    .line 1
    and-int/lit8 v0, p3, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const-string p1, ", "

    .line 6
    .line 7
    :cond_0
    and-int/lit8 v0, p3, 0x2

    .line 8
    .line 9
    const-string v1, ""

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    move-object v0, v1

    .line 14
    goto :goto_0

    .line 15
    :cond_1
    const-string v0, "["

    .line 16
    .line 17
    :goto_0
    and-int/lit8 v2, p3, 0x4

    .line 18
    .line 19
    if-eqz v2, :cond_2

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_2
    const-string v1, "]"

    .line 23
    .line 24
    :goto_1
    and-int/lit8 v2, p3, 0x8

    .line 25
    .line 26
    const/16 v3, 0x20

    .line 27
    .line 28
    if-eqz v2, :cond_3

    .line 29
    .line 30
    const/4 v2, -0x1

    .line 31
    goto :goto_2

    .line 32
    :cond_3
    move v2, v3

    .line 33
    :goto_2
    and-int/2addr p3, v3

    .line 34
    if-eqz p3, :cond_4

    .line 35
    .line 36
    const/4 p2, 0x0

    .line 37
    :cond_4
    new-instance p3, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    invoke-direct {p3}, Ljava/lang/StringBuilder;-><init>()V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 43
    .line 44
    .line 45
    array-length v0, p0

    .line 46
    const/4 v3, 0x0

    .line 47
    move v4, v3

    .line 48
    :goto_3
    if-ge v3, v0, :cond_8

    .line 49
    .line 50
    aget-byte v5, p0, v3

    .line 51
    .line 52
    add-int/lit8 v4, v4, 0x1

    .line 53
    .line 54
    const/4 v6, 0x1

    .line 55
    if-le v4, v6, :cond_5

    .line 56
    .line 57
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 58
    .line 59
    .line 60
    :cond_5
    if-ltz v2, :cond_6

    .line 61
    .line 62
    if-gt v4, v2, :cond_8

    .line 63
    .line 64
    :cond_6
    if-eqz p2, :cond_7

    .line 65
    .line 66
    invoke-static {v5}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    invoke-virtual {p2, v5}, Lf31/n;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    check-cast v5, Ljava/lang/CharSequence;

    .line 75
    .line 76
    invoke-virtual {p3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 77
    .line 78
    .line 79
    goto :goto_4

    .line 80
    :cond_7
    invoke-static {v5}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v5

    .line 84
    invoke-virtual {p3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 85
    .line 86
    .line 87
    :goto_4
    add-int/lit8 v3, v3, 0x1

    .line 88
    .line 89
    goto :goto_3

    .line 90
    :cond_8
    if-ltz v2, :cond_9

    .line 91
    .line 92
    if-le v4, v2, :cond_9

    .line 93
    .line 94
    const-string p0, "..."

    .line 95
    .line 96
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 97
    .line 98
    .line 99
    :cond_9
    invoke-virtual {p3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 100
    .line 101
    .line 102
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0
.end method

.method public static G([C)Ljava/lang/String;
    .locals 7

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, ""

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 9
    .line 10
    .line 11
    array-length v2, p0

    .line 12
    const/4 v3, 0x0

    .line 13
    move v4, v3

    .line 14
    :goto_0
    if-ge v3, v2, :cond_1

    .line 15
    .line 16
    aget-char v5, p0, v3

    .line 17
    .line 18
    const/4 v6, 0x1

    .line 19
    add-int/2addr v4, v6

    .line 20
    if-le v4, v6, :cond_0

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 23
    .line 24
    .line 25
    :cond_0
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 26
    .line 27
    .line 28
    add-int/lit8 v3, v3, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method

.method public static H([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;
    .locals 7

    .line 1
    and-int/lit8 v0, p5, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const-string p1, ", "

    .line 6
    .line 7
    :cond_0
    move-object v2, p1

    .line 8
    and-int/lit8 p1, p5, 0x2

    .line 9
    .line 10
    const-string v0, ""

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    move-object v3, v0

    .line 15
    goto :goto_0

    .line 16
    :cond_1
    move-object v3, p2

    .line 17
    :goto_0
    and-int/lit8 p1, p5, 0x4

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    move-object v4, v0

    .line 22
    goto :goto_1

    .line 23
    :cond_2
    move-object v4, p3

    .line 24
    :goto_1
    and-int/lit8 p1, p5, 0x20

    .line 25
    .line 26
    if-eqz p1, :cond_3

    .line 27
    .line 28
    const/4 p4, 0x0

    .line 29
    :cond_3
    move-object v6, p4

    .line 30
    const-string p1, "<this>"

    .line 31
    .line 32
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    const-string p1, "prefix"

    .line 36
    .line 37
    invoke-static {v3, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    new-instance v1, Ljava/lang/StringBuilder;

    .line 41
    .line 42
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 43
    .line 44
    .line 45
    const-string v5, "..."

    .line 46
    .line 47
    move-object v0, p0

    .line 48
    invoke-static/range {v0 .. v6}, Lmx0/n;->E([Ljava/lang/Object;Ljava/lang/StringBuilder;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Lay0/k;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0
.end method

.method public static I([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    array-length v0, p0

    .line 10
    add-int/lit8 v0, v0, -0x1

    .line 11
    .line 12
    aget-object p0, p0, v0

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 16
    .line 17
    const-string v0, "Array is empty."

    .line 18
    .line 19
    invoke-direct {p0, v0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    throw p0
.end method

.method public static J(Ljava/lang/Object;[Ljava/lang/Object;)I
    .locals 4

    .line 1
    const/4 v0, -0x1

    .line 2
    if-nez p0, :cond_2

    .line 3
    .line 4
    array-length p0, p1

    .line 5
    add-int/2addr p0, v0

    .line 6
    if-ltz p0, :cond_5

    .line 7
    .line 8
    :goto_0
    add-int/lit8 v1, p0, -0x1

    .line 9
    .line 10
    aget-object v2, p1, p0

    .line 11
    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    return p0

    .line 15
    :cond_0
    if-gez v1, :cond_1

    .line 16
    .line 17
    goto :goto_2

    .line 18
    :cond_1
    move p0, v1

    .line 19
    goto :goto_0

    .line 20
    :cond_2
    array-length v1, p1

    .line 21
    add-int/2addr v1, v0

    .line 22
    if-ltz v1, :cond_5

    .line 23
    .line 24
    :goto_1
    add-int/lit8 v2, v1, -0x1

    .line 25
    .line 26
    aget-object v3, p1, v1

    .line 27
    .line 28
    invoke-virtual {p0, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    if-eqz v3, :cond_3

    .line 33
    .line 34
    return v1

    .line 35
    :cond_3
    if-gez v2, :cond_4

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_4
    move v1, v2

    .line 39
    goto :goto_1

    .line 40
    :cond_5
    :goto_2
    return v0
.end method

.method public static K([F)Ljava/lang/Float;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return-object p0

    .line 11
    :cond_0
    array-length v0, p0

    .line 12
    add-int/lit8 v0, v0, -0x1

    .line 13
    .line 14
    aget p0, p0, v0

    .line 15
    .line 16
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static L(B[B)[B
    .locals 2

    .line 1
    array-length v0, p1

    .line 2
    add-int/lit8 v1, v0, 0x1

    .line 3
    .line 4
    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    aput-byte p0, p1, v0

    .line 9
    .line 10
    return-object p1
.end method

.method public static M([B[B)[B
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "elements"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    array-length v0, p0

    .line 12
    array-length v1, p1

    .line 13
    add-int v2, v0, v1

    .line 14
    .line 15
    invoke-static {p0, v2}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-static {p1, v2, p0, v0, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 21
    .line 22
    .line 23
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    return-object p0
.end method

.method public static N(Ljava/util/Collection;[Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 3

    .line 1
    array-length v0, p1

    .line 2
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    add-int/2addr v1, v0

    .line 7
    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    add-int/lit8 v2, v0, 0x1

    .line 26
    .line 27
    aput-object v1, p1, v0

    .line 28
    .line 29
    move v0, v2

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    return-object p1
.end method

.method public static O([Ljava/lang/Object;[Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    array-length v1, p1

    .line 8
    add-int v2, v0, v1

    .line 9
    .line 10
    invoke-static {p0, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-static {p1, v2, p0, v0, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 16
    .line 17
    .line 18
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-object p0
.end method

.method public static P([C)C
    .locals 2

    .line 1
    array-length v0, p0

    .line 2
    if-eqz v0, :cond_1

    .line 3
    .line 4
    const/4 v1, 0x1

    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    aget-char p0, p0, v0

    .line 9
    .line 10
    return p0

    .line 11
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 12
    .line 13
    const-string v0, "Array has more than one element."

    .line 14
    .line 15
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 20
    .line 21
    const-string v0, "Array is empty."

    .line 22
    .line 23
    invoke-direct {p0, v0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0
.end method

.method public static Q([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-ne v0, v1, :cond_0

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    aget-object p0, p0, v0

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    const-string v0, "Array has more than one element."

    .line 19
    .line 20
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 25
    .line 26
    const-string v0, "Array is empty."

    .line 27
    .line 28
    invoke-direct {p0, v0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0
.end method

.method public static R([BLgy0/j;)[B
    .locals 1

    .line 1
    const-string v0, "indices"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Lgy0/j;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    new-array p0, p0, [B

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    iget v0, p1, Lgy0/h;->d:I

    .line 17
    .line 18
    iget p1, p1, Lgy0/h;->e:I

    .line 19
    .line 20
    add-int/lit8 p1, p1, 0x1

    .line 21
    .line 22
    invoke-static {p0, v0, p1}, Lmx0/n;->n([BII)[B

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method public static S([Ljava/lang/Object;Ljava/util/Comparator;)V
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "comparator"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    array-length v0, p0

    .line 12
    const/4 v1, 0x1

    .line 13
    if-le v0, v1, :cond_0

    .line 14
    .line 15
    invoke-static {p0, p1}, Ljava/util/Arrays;->sort([Ljava/lang/Object;Ljava/util/Comparator;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public static T([Ljava/lang/Object;Ljava/util/Comparator;II)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "comparator"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, p2, p3, p1}, Ljava/util/Arrays;->sort([Ljava/lang/Object;IILjava/util/Comparator;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static U(I[B)Ljava/util/List;
    .locals 6

    .line 1
    if-ltz p0, :cond_5

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    array-length v0, p1

    .line 9
    if-lt p0, v0, :cond_1

    .line 10
    .line 11
    invoke-static {p1}, Lmx0/n;->W([B)Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_1
    const/4 v0, 0x0

    .line 17
    const/4 v1, 0x1

    .line 18
    if-ne p0, v1, :cond_2

    .line 19
    .line 20
    aget-byte p0, p1, v0

    .line 21
    .line 22
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :cond_2
    new-instance v2, Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-direct {v2, p0}, Ljava/util/ArrayList;-><init>(I)V

    .line 34
    .line 35
    .line 36
    array-length v3, p1

    .line 37
    move v4, v0

    .line 38
    :goto_0
    if-ge v0, v3, :cond_4

    .line 39
    .line 40
    aget-byte v5, p1, v0

    .line 41
    .line 42
    invoke-static {v5}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    add-int/2addr v4, v1

    .line 50
    if-ne v4, p0, :cond_3

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_3
    add-int/lit8 v0, v0, 0x1

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_4
    :goto_1
    return-object v2

    .line 57
    :cond_5
    const-string p1, "Requested element count "

    .line 58
    .line 59
    const-string v0, " is less than zero."

    .line 60
    .line 61
    invoke-static {p1, p0, v0}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 66
    .line 67
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw p1
.end method

.method public static final V([Ljava/lang/Object;Ljava/util/LinkedHashSet;)V
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    const/4 v1, 0x0

    .line 8
    :goto_0
    if-ge v1, v0, :cond_0

    .line 9
    .line 10
    aget-object v2, p0, v1

    .line 11
    .line 12
    invoke-interface {p1, v2}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    add-int/lit8 v1, v1, 0x1

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    return-void
.end method

.method public static W([B)Ljava/util/List;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    const/4 v2, 0x1

    .line 11
    if-eq v0, v2, :cond_1

    .line 12
    .line 13
    new-instance v0, Ljava/util/ArrayList;

    .line 14
    .line 15
    array-length v2, p0

    .line 16
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 17
    .line 18
    .line 19
    array-length v2, p0

    .line 20
    :goto_0
    if-ge v1, v2, :cond_0

    .line 21
    .line 22
    aget-byte v3, p0, v1

    .line 23
    .line 24
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    return-object v0

    .line 35
    :cond_1
    aget-byte p0, p0, v1

    .line 36
    .line 37
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :cond_2
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 47
    .line 48
    return-object p0
.end method

.method public static X([D)Ljava/util/List;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    const/4 v2, 0x1

    .line 11
    if-eq v0, v2, :cond_1

    .line 12
    .line 13
    new-instance v0, Ljava/util/ArrayList;

    .line 14
    .line 15
    array-length v2, p0

    .line 16
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 17
    .line 18
    .line 19
    array-length v2, p0

    .line 20
    :goto_0
    if-ge v1, v2, :cond_0

    .line 21
    .line 22
    aget-wide v3, p0, v1

    .line 23
    .line 24
    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    return-object v0

    .line 35
    :cond_1
    aget-wide v0, p0, v1

    .line 36
    .line 37
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :cond_2
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 47
    .line 48
    return-object p0
.end method

.method public static Y([F)Ljava/util/List;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    const/4 v2, 0x1

    .line 11
    if-eq v0, v2, :cond_1

    .line 12
    .line 13
    new-instance v0, Ljava/util/ArrayList;

    .line 14
    .line 15
    array-length v2, p0

    .line 16
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 17
    .line 18
    .line 19
    array-length v2, p0

    .line 20
    :goto_0
    if-ge v1, v2, :cond_0

    .line 21
    .line 22
    aget v3, p0, v1

    .line 23
    .line 24
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    return-object v0

    .line 35
    :cond_1
    aget p0, p0, v1

    .line 36
    .line 37
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :cond_2
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 47
    .line 48
    return-object p0
.end method

.method public static Z([I)Ljava/util/List;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-eq v0, v1, :cond_0

    .line 11
    .line 12
    invoke-static {p0}, Lmx0/n;->g0([I)Ljava/util/ArrayList;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_0
    const/4 v0, 0x0

    .line 18
    aget p0, p0, v0

    .line 19
    .line 20
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_1
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 30
    .line 31
    return-object p0
.end method

.method public static a([Ljava/lang/Object;)Ljava/lang/Iterable;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance v0, Lky0/p;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-direct {v0, p0, v1}, Lky0/p;-><init>(Ljava/lang/Object;I)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public static a0([J)Ljava/util/List;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    const/4 v2, 0x1

    .line 11
    if-eq v0, v2, :cond_1

    .line 12
    .line 13
    new-instance v0, Ljava/util/ArrayList;

    .line 14
    .line 15
    array-length v2, p0

    .line 16
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 17
    .line 18
    .line 19
    array-length v2, p0

    .line 20
    :goto_0
    if-ge v1, v2, :cond_0

    .line 21
    .line 22
    aget-wide v3, p0, v1

    .line 23
    .line 24
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    return-object v0

    .line 35
    :cond_1
    aget-wide v0, p0, v1

    .line 36
    .line 37
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :cond_2
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 47
    .line 48
    return-object p0
.end method

.method public static b([Ljava/lang/Object;)Ljava/util/List;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    const-string v0, "asList(...)"

    .line 11
    .line 12
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public static b0([Ljava/lang/Object;)Ljava/util/List;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    if-eq v0, v1, :cond_0

    .line 12
    .line 13
    new-instance v0, Ljava/util/ArrayList;

    .line 14
    .line 15
    new-instance v1, Lmx0/k;

    .line 16
    .line 17
    invoke-direct {v1, p0, v2}, Lmx0/k;-><init>([Ljava/lang/Object;Z)V

    .line 18
    .line 19
    .line 20
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 21
    .line 22
    .line 23
    return-object v0

    .line 24
    :cond_0
    aget-object p0, p0, v2

    .line 25
    .line 26
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :cond_1
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 32
    .line 33
    return-object p0
.end method

.method public static c([Ljava/lang/Object;)Lky0/j;
    .locals 2

    .line 1
    array-length v0, p0

    .line 2
    if-nez v0, :cond_0

    .line 3
    .line 4
    sget-object p0, Lky0/e;->a:Lky0/e;

    .line 5
    .line 6
    return-object p0

    .line 7
    :cond_0
    new-instance v0, Lky0/m;

    .line 8
    .line 9
    const/4 v1, 0x3

    .line 10
    invoke-direct {v0, p0, v1}, Lky0/m;-><init>(Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static c0([Z)Ljava/util/List;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    const/4 v2, 0x1

    .line 11
    if-eq v0, v2, :cond_1

    .line 12
    .line 13
    new-instance v0, Ljava/util/ArrayList;

    .line 14
    .line 15
    array-length v2, p0

    .line 16
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 17
    .line 18
    .line 19
    array-length v2, p0

    .line 20
    :goto_0
    if-ge v1, v2, :cond_0

    .line 21
    .line 22
    aget-boolean v3, p0, v1

    .line 23
    .line 24
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    return-object v0

    .line 35
    :cond_1
    aget-boolean p0, p0, v1

    .line 36
    .line 37
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :cond_2
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 47
    .line 48
    return-object p0
.end method

.method public static d(I[I)Z
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p1

    .line 7
    const/4 v1, 0x0

    .line 8
    move v2, v1

    .line 9
    :goto_0
    if-ge v2, v0, :cond_1

    .line 10
    .line 11
    aget v3, p1, v2

    .line 12
    .line 13
    if-ne p0, v3, :cond_0

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    const/4 v2, -0x1

    .line 20
    :goto_1
    if-ltz v2, :cond_2

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    return p0

    .line 24
    :cond_2
    return v1
.end method

.method public static final d0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;Z)Lcq0/j;
    .locals 21

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getType()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    const-string v3, "AUTO"

    .line 13
    .line 14
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-eqz v3, :cond_0

    .line 19
    .line 20
    sget-object v2, Lcq0/b;->d:Lcq0/b;

    .line 21
    .line 22
    :goto_0
    move-object v7, v2

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    const-string v3, "MANUAL"

    .line 25
    .line 26
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    sget-object v2, Lcq0/b;->e:Lcq0/b;

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    sget-object v2, Lcq0/b;->f:Lcq0/b;

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :goto_1
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getResolution()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    const v4, -0x451f8725

    .line 50
    .line 51
    .line 52
    if-eq v3, v4, :cond_6

    .line 53
    .line 54
    const v4, 0xa61047e

    .line 55
    .line 56
    .line 57
    if-eq v3, v4, :cond_4

    .line 58
    .line 59
    const v4, 0x2868ef7f

    .line 60
    .line 61
    .line 62
    if-eq v3, v4, :cond_2

    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_2
    const-string v3, "APPOINTMENT"

    .line 66
    .line 67
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-nez v2, :cond_3

    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_3
    sget-object v2, Lcq0/k;->e:Lcq0/k;

    .line 75
    .line 76
    goto :goto_3

    .line 77
    :cond_4
    const-string v3, "REJECTED"

    .line 78
    .line 79
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    if-nez v2, :cond_5

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_5
    sget-object v2, Lcq0/k;->f:Lcq0/k;

    .line 87
    .line 88
    goto :goto_3

    .line 89
    :cond_6
    const-string v3, "SUBMITTED"

    .line 90
    .line 91
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v2

    .line 95
    if-nez v2, :cond_7

    .line 96
    .line 97
    :goto_2
    const/4 v2, 0x0

    .line 98
    goto :goto_3

    .line 99
    :cond_7
    sget-object v2, Lcq0/k;->d:Lcq0/k;

    .line 100
    .line 101
    :goto_3
    if-nez v2, :cond_8

    .line 102
    .line 103
    const/4 v2, -0x1

    .line 104
    goto :goto_4

    .line 105
    :cond_8
    sget-object v3, Lzp0/f;->a:[I

    .line 106
    .line 107
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    aget v2, v3, v2

    .line 112
    .line 113
    :goto_4
    const/4 v3, 0x2

    .line 114
    const/4 v4, 0x1

    .line 115
    if-eq v2, v4, :cond_e

    .line 116
    .line 117
    if-eq v2, v3, :cond_a

    .line 118
    .line 119
    const/4 v3, 0x3

    .line 120
    if-eq v2, v3, :cond_9

    .line 121
    .line 122
    sget-object v2, Lcq0/l;->i:Lcq0/l;

    .line 123
    .line 124
    :goto_5
    move-object v8, v2

    .line 125
    goto :goto_6

    .line 126
    :cond_9
    sget-object v2, Lcq0/l;->h:Lcq0/l;

    .line 127
    .line 128
    goto :goto_5

    .line 129
    :cond_a
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 130
    .line 131
    .line 132
    move-result v2

    .line 133
    if-eqz v2, :cond_d

    .line 134
    .line 135
    if-eq v2, v4, :cond_c

    .line 136
    .line 137
    if-ne v2, v3, :cond_b

    .line 138
    .line 139
    sget-object v2, Lcq0/l;->i:Lcq0/l;

    .line 140
    .line 141
    goto :goto_5

    .line 142
    :cond_b
    new-instance v0, La8/r0;

    .line 143
    .line 144
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 145
    .line 146
    .line 147
    throw v0

    .line 148
    :cond_c
    sget-object v2, Lcq0/l;->g:Lcq0/l;

    .line 149
    .line 150
    goto :goto_5

    .line 151
    :cond_d
    sget-object v2, Lcq0/l;->f:Lcq0/l;

    .line 152
    .line 153
    goto :goto_5

    .line 154
    :cond_e
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 155
    .line 156
    .line 157
    move-result v2

    .line 158
    if-eqz v2, :cond_11

    .line 159
    .line 160
    if-eq v2, v4, :cond_10

    .line 161
    .line 162
    if-ne v2, v3, :cond_f

    .line 163
    .line 164
    sget-object v2, Lcq0/l;->i:Lcq0/l;

    .line 165
    .line 166
    goto :goto_5

    .line 167
    :cond_f
    new-instance v0, La8/r0;

    .line 168
    .line 169
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 170
    .line 171
    .line 172
    throw v0

    .line 173
    :cond_10
    sget-object v2, Lcq0/l;->e:Lcq0/l;

    .line 174
    .line 175
    goto :goto_5

    .line 176
    :cond_11
    sget-object v2, Lcq0/l;->d:Lcq0/l;

    .line 177
    .line 178
    goto :goto_5

    .line 179
    :goto_6
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getBookingId()Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object v4

    .line 183
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getServicePartner()Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 184
    .line 185
    .line 186
    move-result-object v2

    .line 187
    invoke-virtual {v2}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getName()Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v2

    .line 191
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getWarnings()Ljava/util/List;

    .line 192
    .line 193
    .line 194
    move-result-object v3

    .line 195
    if-eqz v3, :cond_19

    .line 196
    .line 197
    check-cast v3, Ljava/lang/Iterable;

    .line 198
    .line 199
    new-instance v6, Ljava/util/ArrayList;

    .line 200
    .line 201
    const/16 v9, 0xa

    .line 202
    .line 203
    invoke-static {v3, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 204
    .line 205
    .line 206
    move-result v9

    .line 207
    invoke-direct {v6, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 208
    .line 209
    .line 210
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 211
    .line 212
    .line 213
    move-result-object v3

    .line 214
    :goto_7
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 215
    .line 216
    .line 217
    move-result v9

    .line 218
    if-eqz v9, :cond_1a

    .line 219
    .line 220
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v9

    .line 224
    check-cast v9, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingWarningDto;

    .line 225
    .line 226
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    new-instance v10, Lcq0/r;

    .line 230
    .line 231
    invoke-virtual {v9}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingWarningDto;->getIconName()Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object v11

    .line 235
    invoke-virtual {v9}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingWarningDto;->getIconColor()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v12

    .line 239
    if-eqz v12, :cond_18

    .line 240
    .line 241
    invoke-virtual {v12}, Ljava/lang/String;->hashCode()I

    .line 242
    .line 243
    .line 244
    move-result v13

    .line 245
    const v14, -0x6430a78c

    .line 246
    .line 247
    .line 248
    if-eq v13, v14, :cond_16

    .line 249
    .line 250
    const v14, 0x13c71

    .line 251
    .line 252
    .line 253
    if-eq v13, v14, :cond_14

    .line 254
    .line 255
    const v14, 0x4ebd409

    .line 256
    .line 257
    .line 258
    if-eq v13, v14, :cond_12

    .line 259
    .line 260
    goto :goto_8

    .line 261
    :cond_12
    const-string v13, "WHITE"

    .line 262
    .line 263
    invoke-virtual {v12, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 264
    .line 265
    .line 266
    move-result v12

    .line 267
    if-nez v12, :cond_13

    .line 268
    .line 269
    goto :goto_8

    .line 270
    :cond_13
    sget-object v12, Lcq0/s;->d:Lcq0/s;

    .line 271
    .line 272
    goto :goto_9

    .line 273
    :cond_14
    const-string v13, "RED"

    .line 274
    .line 275
    invoke-virtual {v12, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    move-result v12

    .line 279
    if-nez v12, :cond_15

    .line 280
    .line 281
    goto :goto_8

    .line 282
    :cond_15
    sget-object v12, Lcq0/s;->f:Lcq0/s;

    .line 283
    .line 284
    goto :goto_9

    .line 285
    :cond_16
    const-string v13, "YELLOW"

    .line 286
    .line 287
    invoke-virtual {v12, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 288
    .line 289
    .line 290
    move-result v12

    .line 291
    if-nez v12, :cond_17

    .line 292
    .line 293
    goto :goto_8

    .line 294
    :cond_17
    sget-object v12, Lcq0/s;->e:Lcq0/s;

    .line 295
    .line 296
    goto :goto_9

    .line 297
    :cond_18
    :goto_8
    sget-object v12, Lcq0/s;->d:Lcq0/s;

    .line 298
    .line 299
    :goto_9
    invoke-virtual {v9}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingWarningDto;->getText()Ljava/lang/String;

    .line 300
    .line 301
    .line 302
    move-result-object v9

    .line 303
    invoke-direct {v10, v11, v12, v9}, Lcq0/r;-><init>(Ljava/lang/String;Lcq0/s;Ljava/lang/String;)V

    .line 304
    .line 305
    .line 306
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 307
    .line 308
    .line 309
    goto :goto_7

    .line 310
    :cond_19
    const/4 v6, 0x0

    .line 311
    :cond_1a
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getServicePartner()Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 312
    .line 313
    .line 314
    move-result-object v3

    .line 315
    invoke-static {v3}, Lmx0/n;->f0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;)Lcq0/n;

    .line 316
    .line 317
    .line 318
    move-result-object v9

    .line 319
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getCreationDate()Ljava/time/OffsetDateTime;

    .line 320
    .line 321
    .line 322
    move-result-object v10

    .line 323
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getAppointmentDate()Ljava/time/OffsetDateTime;

    .line 324
    .line 325
    .line 326
    move-result-object v11

    .line 327
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getContactedDate()Ljava/time/OffsetDateTime;

    .line 328
    .line 329
    .line 330
    move-result-object v12

    .line 331
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getUpdateDate()Ljava/time/OffsetDateTime;

    .line 332
    .line 333
    .line 334
    move-result-object v13

    .line 335
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getAcceptedDate()Ljava/time/OffsetDateTime;

    .line 336
    .line 337
    .line 338
    move-result-object v14

    .line 339
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getConfirmationDate()Ljava/time/OffsetDateTime;

    .line 340
    .line 341
    .line 342
    move-result-object v15

    .line 343
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getClosedDate()Ljava/time/OffsetDateTime;

    .line 344
    .line 345
    .line 346
    move-result-object v16

    .line 347
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getExtras()Ljava/util/List;

    .line 348
    .line 349
    .line 350
    move-result-object v3

    .line 351
    if-eqz v3, :cond_26

    .line 352
    .line 353
    check-cast v3, Ljava/lang/Iterable;

    .line 354
    .line 355
    new-instance v5, Ljava/util/ArrayList;

    .line 356
    .line 357
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 358
    .line 359
    .line 360
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 361
    .line 362
    .line 363
    move-result-object v3

    .line 364
    :goto_a
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 365
    .line 366
    .line 367
    move-result v18

    .line 368
    if-eqz v18, :cond_27

    .line 369
    .line 370
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v18

    .line 374
    move-object/from16 v1, v18

    .line 375
    .line 376
    check-cast v1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingExtrasDto;

    .line 377
    .line 378
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 379
    .line 380
    .line 381
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingExtrasDto;->getNotificationId()Ljava/lang/String;

    .line 382
    .line 383
    .line 384
    move-result-object v1

    .line 385
    if-eqz v1, :cond_1b

    .line 386
    .line 387
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 388
    .line 389
    .line 390
    move-result v18

    .line 391
    sparse-switch v18, :sswitch_data_0

    .line 392
    .line 393
    .line 394
    :cond_1b
    move-object/from16 v18, v0

    .line 395
    .line 396
    goto/16 :goto_b

    .line 397
    .line 398
    :sswitch_0
    move-object/from16 v18, v0

    .line 399
    .line 400
    const-string v0, "TYRE_CHANGE"

    .line 401
    .line 402
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 403
    .line 404
    .line 405
    move-result v0

    .line 406
    if-eqz v0, :cond_24

    .line 407
    .line 408
    sget-object v0, Lcq0/w;->g:Lcq0/w;

    .line 409
    .line 410
    goto/16 :goto_c

    .line 411
    .line 412
    :sswitch_1
    move-object/from16 v18, v0

    .line 413
    .line 414
    const-string v0, "VEHICLE_CHECK"

    .line 415
    .line 416
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 417
    .line 418
    .line 419
    move-result v0

    .line 420
    if-nez v0, :cond_1c

    .line 421
    .line 422
    goto/16 :goto_b

    .line 423
    .line 424
    :cond_1c
    sget-object v0, Lcq0/w;->e:Lcq0/w;

    .line 425
    .line 426
    goto/16 :goto_c

    .line 427
    .line 428
    :sswitch_2
    move-object/from16 v18, v0

    .line 429
    .line 430
    const-string v0, "ACCESSORIES"

    .line 431
    .line 432
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 433
    .line 434
    .line 435
    move-result v0

    .line 436
    if-nez v0, :cond_1d

    .line 437
    .line 438
    goto/16 :goto_b

    .line 439
    .line 440
    :cond_1d
    sget-object v0, Lcq0/w;->l:Lcq0/w;

    .line 441
    .line 442
    goto :goto_c

    .line 443
    :sswitch_3
    move-object/from16 v18, v0

    .line 444
    .line 445
    const-string v0, "BATTERY"

    .line 446
    .line 447
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 448
    .line 449
    .line 450
    move-result v0

    .line 451
    if-nez v0, :cond_1e

    .line 452
    .line 453
    goto :goto_b

    .line 454
    :cond_1e
    sget-object v0, Lcq0/w;->f:Lcq0/w;

    .line 455
    .line 456
    goto :goto_c

    .line 457
    :sswitch_4
    move-object/from16 v18, v0

    .line 458
    .line 459
    const-string v0, "AIR_CONDITIONING_CHECK"

    .line 460
    .line 461
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 462
    .line 463
    .line 464
    move-result v0

    .line 465
    if-nez v0, :cond_1f

    .line 466
    .line 467
    goto :goto_b

    .line 468
    :cond_1f
    sget-object v0, Lcq0/w;->k:Lcq0/w;

    .line 469
    .line 470
    goto :goto_c

    .line 471
    :sswitch_5
    move-object/from16 v18, v0

    .line 472
    .line 473
    const-string v0, "OIL_CHANGE"

    .line 474
    .line 475
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 476
    .line 477
    .line 478
    move-result v0

    .line 479
    if-nez v0, :cond_20

    .line 480
    .line 481
    goto :goto_b

    .line 482
    :cond_20
    sget-object v0, Lcq0/w;->h:Lcq0/w;

    .line 483
    .line 484
    goto :goto_c

    .line 485
    :sswitch_6
    move-object/from16 v18, v0

    .line 486
    .line 487
    const-string v0, "OTHERS"

    .line 488
    .line 489
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 490
    .line 491
    .line 492
    move-result v0

    .line 493
    if-nez v0, :cond_21

    .line 494
    .line 495
    goto :goto_b

    .line 496
    :cond_21
    sget-object v0, Lcq0/w;->i:Lcq0/w;

    .line 497
    .line 498
    goto :goto_c

    .line 499
    :sswitch_7
    move-object/from16 v18, v0

    .line 500
    .line 501
    const-string v0, "LIGHTS"

    .line 502
    .line 503
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 504
    .line 505
    .line 506
    move-result v0

    .line 507
    if-nez v0, :cond_22

    .line 508
    .line 509
    goto :goto_b

    .line 510
    :cond_22
    sget-object v0, Lcq0/w;->m:Lcq0/w;

    .line 511
    .line 512
    goto :goto_c

    .line 513
    :sswitch_8
    move-object/from16 v18, v0

    .line 514
    .line 515
    const-string v0, "INSPECTION"

    .line 516
    .line 517
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 518
    .line 519
    .line 520
    move-result v0

    .line 521
    if-nez v0, :cond_23

    .line 522
    .line 523
    goto :goto_b

    .line 524
    :cond_23
    sget-object v0, Lcq0/w;->j:Lcq0/w;

    .line 525
    .line 526
    goto :goto_c

    .line 527
    :cond_24
    :goto_b
    const/4 v0, 0x0

    .line 528
    :goto_c
    if-eqz v0, :cond_25

    .line 529
    .line 530
    invoke-virtual {v5, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 531
    .line 532
    .line 533
    :cond_25
    move-object/from16 v1, p0

    .line 534
    .line 535
    move-object/from16 v0, v18

    .line 536
    .line 537
    goto/16 :goto_a

    .line 538
    .line 539
    :cond_26
    const/4 v5, 0x0

    .line 540
    :cond_27
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getMileageInKm()Ljava/lang/Integer;

    .line 541
    .line 542
    .line 543
    move-result-object v18

    .line 544
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;->getAddOns()Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;

    .line 545
    .line 546
    .line 547
    move-result-object v0

    .line 548
    if-eqz v0, :cond_28

    .line 549
    .line 550
    new-instance v1, Lcq0/a;

    .line 551
    .line 552
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;->getPreferredDatetime()Ljava/time/OffsetDateTime;

    .line 553
    .line 554
    .line 555
    move-result-object v3

    .line 556
    move-object/from16 p0, v0

    .line 557
    .line 558
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;->getAlternativeDatetime()Ljava/time/OffsetDateTime;

    .line 559
    .line 560
    .line 561
    move-result-object v0

    .line 562
    move-object/from16 v19, v2

    .line 563
    .line 564
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;->getAdditionalInformation()Ljava/lang/String;

    .line 565
    .line 566
    .line 567
    move-result-object v2

    .line 568
    move-object/from16 v20, v4

    .line 569
    .line 570
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;->getCourtesyVehicle()Ljava/lang/Boolean;

    .line 571
    .line 572
    .line 573
    move-result-object v4

    .line 574
    invoke-direct {v1, v3, v0, v2, v4}, Lcq0/a;-><init>(Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/Boolean;)V

    .line 575
    .line 576
    .line 577
    goto :goto_d

    .line 578
    :cond_28
    move-object/from16 v19, v2

    .line 579
    .line 580
    move-object/from16 v20, v4

    .line 581
    .line 582
    const/4 v1, 0x0

    .line 583
    :goto_d
    new-instance v3, Lcq0/j;

    .line 584
    .line 585
    move-object/from16 v17, v5

    .line 586
    .line 587
    move-object/from16 v5, v19

    .line 588
    .line 589
    move-object/from16 v4, v20

    .line 590
    .line 591
    move/from16 v19, p1

    .line 592
    .line 593
    move-object/from16 v20, v1

    .line 594
    .line 595
    invoke-direct/range {v3 .. v20}, Lcq0/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Lcq0/b;Lcq0/l;Lcq0/n;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/util/ArrayList;Ljava/lang/Integer;ZLcq0/a;)V

    .line 596
    .line 597
    .line 598
    return-object v3

    .line 599
    :sswitch_data_0
    .sparse-switch
        -0x7aab068c -> :sswitch_8
        -0x7a299de3 -> :sswitch_7
        -0x746fa89d -> :sswitch_6
        -0x671f1923 -> :sswitch_5
        -0x4f48ab3b -> :sswitch_4
        0x170d39ed -> :sswitch_3
        0x43ab3710 -> :sswitch_2
        0x48e7f1f5 -> :sswitch_1
        0x5e09a657 -> :sswitch_0
    .end sparse-switch
.end method

.method public static e(Ljava/lang/Object;[Ljava/lang/Object;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1}, Lmx0/n;->D(Ljava/lang/Object;[Ljava/lang/Object;)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    if-ltz p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    return p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0
.end method

.method public static final e0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceDto;)Lcq0/m;
    .locals 13

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcq0/m;

    .line 7
    .line 8
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceDto;->getMaintenanceReport()Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const/4 v2, 0x0

    .line 13
    if-eqz v1, :cond_3

    .line 14
    .line 15
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;->getCapturedAt()Ljava/time/OffsetDateTime;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;->getInspectionDueInDays()Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v5

    .line 23
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;->getInspectionDueInKm()Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    const-wide v6, 0x408f400000000000L    # 1000.0

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    if-eqz v3, :cond_0

    .line 33
    .line 34
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    int-to-double v8, v3

    .line 39
    mul-double/2addr v8, v6

    .line 40
    new-instance v3, Lqr0/d;

    .line 41
    .line 42
    invoke-direct {v3, v8, v9}, Lqr0/d;-><init>(D)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    move-object v3, v2

    .line 47
    :goto_0
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;->getMileageInKm()Ljava/lang/Integer;

    .line 48
    .line 49
    .line 50
    move-result-object v8

    .line 51
    if-eqz v8, :cond_1

    .line 52
    .line 53
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 54
    .line 55
    .line 56
    move-result v8

    .line 57
    int-to-double v8, v8

    .line 58
    mul-double/2addr v8, v6

    .line 59
    new-instance v10, Lqr0/d;

    .line 60
    .line 61
    invoke-direct {v10, v8, v9}, Lqr0/d;-><init>(D)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_1
    move-object v10, v2

    .line 66
    :goto_1
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;->getOilServiceDueInDays()Ljava/lang/Integer;

    .line 67
    .line 68
    .line 69
    move-result-object v8

    .line 70
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;->getOilServiceDueInKm()Ljava/lang/Integer;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    if-eqz v1, :cond_2

    .line 75
    .line 76
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    int-to-double v11, v1

    .line 81
    mul-double/2addr v11, v6

    .line 82
    new-instance v1, Lqr0/d;

    .line 83
    .line 84
    invoke-direct {v1, v11, v12}, Lqr0/d;-><init>(D)V

    .line 85
    .line 86
    .line 87
    move-object v9, v1

    .line 88
    :goto_2
    move-object v6, v3

    .line 89
    goto :goto_3

    .line 90
    :cond_2
    move-object v9, v2

    .line 91
    goto :goto_2

    .line 92
    :goto_3
    new-instance v3, Lcq0/e;

    .line 93
    .line 94
    move-object v7, v10

    .line 95
    invoke-direct/range {v3 .. v9}, Lcq0/e;-><init>(Ljava/time/OffsetDateTime;Ljava/lang/Integer;Lqr0/d;Lqr0/d;Ljava/lang/Integer;Lqr0/d;)V

    .line 96
    .line 97
    .line 98
    goto :goto_4

    .line 99
    :cond_3
    move-object v3, v2

    .line 100
    :goto_4
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceDto;->getPreferredServicePartner()Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    if-eqz v1, :cond_4

    .line 105
    .line 106
    invoke-static {v1}, Lmx0/n;->f0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;)Lcq0/n;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    goto :goto_5

    .line 111
    :cond_4
    move-object v1, v2

    .line 112
    :goto_5
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceDto;->getPredictiveMaintenance()Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehiclePredictiveMaintenanceDto;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    if-eqz v4, :cond_7

    .line 117
    .line 118
    invoke-virtual {v4}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehiclePredictiveMaintenanceDto;->getSetting()Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehiclePredictiveMaintenanceSettingDto;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    if-eqz v4, :cond_7

    .line 123
    .line 124
    new-instance v5, Lcq0/g;

    .line 125
    .line 126
    invoke-virtual {v4}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehiclePredictiveMaintenanceSettingDto;->getServiceActivated()Ljava/lang/Boolean;

    .line 127
    .line 128
    .line 129
    move-result-object v6

    .line 130
    invoke-virtual {v4}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehiclePredictiveMaintenanceSettingDto;->getPreferredChannel()Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object v7

    .line 134
    if-eqz v7, :cond_6

    .line 135
    .line 136
    const-string v8, "PHONE"

    .line 137
    .line 138
    invoke-virtual {v7, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v8

    .line 142
    if-eqz v8, :cond_5

    .line 143
    .line 144
    sget-object v7, Lcq0/c;->e:Lcq0/c;

    .line 145
    .line 146
    goto :goto_6

    .line 147
    :cond_5
    const-string v8, "EMAIL"

    .line 148
    .line 149
    invoke-virtual {v7, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v7

    .line 153
    if-eqz v7, :cond_6

    .line 154
    .line 155
    sget-object v7, Lcq0/c;->d:Lcq0/c;

    .line 156
    .line 157
    goto :goto_6

    .line 158
    :cond_6
    move-object v7, v2

    .line 159
    :goto_6
    invoke-virtual {v4}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehiclePredictiveMaintenanceSettingDto;->getEmail()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v8

    .line 163
    invoke-virtual {v4}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehiclePredictiveMaintenanceSettingDto;->getPhone()Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v4

    .line 167
    invoke-direct {v5, v6, v7, v8, v4}, Lcq0/g;-><init>(Ljava/lang/Boolean;Lcq0/c;Ljava/lang/String;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    goto :goto_7

    .line 171
    :cond_7
    move-object v5, v2

    .line 172
    :goto_7
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceDto;->getCustomerService()Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceDto;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    if-eqz p0, :cond_b

    .line 177
    .line 178
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceDto;->getActiveBookings()Ljava/util/List;

    .line 179
    .line 180
    .line 181
    move-result-object v4

    .line 182
    const/16 v6, 0xa

    .line 183
    .line 184
    if-eqz v4, :cond_8

    .line 185
    .line 186
    check-cast v4, Ljava/lang/Iterable;

    .line 187
    .line 188
    new-instance v7, Ljava/util/ArrayList;

    .line 189
    .line 190
    invoke-static {v4, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 191
    .line 192
    .line 193
    move-result v8

    .line 194
    invoke-direct {v7, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 195
    .line 196
    .line 197
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 198
    .line 199
    .line 200
    move-result-object v4

    .line 201
    :goto_8
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 202
    .line 203
    .line 204
    move-result v8

    .line 205
    if-eqz v8, :cond_9

    .line 206
    .line 207
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v8

    .line 211
    check-cast v8, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;

    .line 212
    .line 213
    const/4 v9, 0x1

    .line 214
    invoke-static {v8, v9}, Lmx0/n;->d0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;Z)Lcq0/j;

    .line 215
    .line 216
    .line 217
    move-result-object v8

    .line 218
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 219
    .line 220
    .line 221
    goto :goto_8

    .line 222
    :cond_8
    move-object v7, v2

    .line 223
    :cond_9
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceDto;->getBookingHistory()Ljava/util/List;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    if-eqz p0, :cond_a

    .line 228
    .line 229
    check-cast p0, Ljava/lang/Iterable;

    .line 230
    .line 231
    new-instance v2, Ljava/util/ArrayList;

    .line 232
    .line 233
    invoke-static {p0, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 234
    .line 235
    .line 236
    move-result v4

    .line 237
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 238
    .line 239
    .line 240
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    :goto_9
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 245
    .line 246
    .line 247
    move-result v4

    .line 248
    if-eqz v4, :cond_a

    .line 249
    .line 250
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v4

    .line 254
    check-cast v4, Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;

    .line 255
    .line 256
    const/4 v6, 0x0

    .line 257
    invoke-static {v4, v6}, Lmx0/n;->d0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/CustomerServiceBookingDto;Z)Lcq0/j;

    .line 258
    .line 259
    .line 260
    move-result-object v4

    .line 261
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    goto :goto_9

    .line 265
    :cond_a
    new-instance p0, Lcq0/d;

    .line 266
    .line 267
    invoke-direct {p0, v7, v2}, Lcq0/d;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 268
    .line 269
    .line 270
    move-object v2, p0

    .line 271
    :cond_b
    invoke-direct {v0, v3, v1, v5, v2}, Lcq0/m;-><init>(Lcq0/e;Lcq0/n;Lcq0/g;Lcq0/d;)V

    .line 272
    .line 273
    .line 274
    return-object v0
.end method

.method public static f([Ljava/lang/Object;[Ljava/lang/Object;)Z
    .locals 8

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
    if-eqz p0, :cond_1c

    .line 7
    .line 8
    if-eqz p1, :cond_1c

    .line 9
    .line 10
    array-length v2, p0

    .line 11
    array-length v3, p1

    .line 12
    if-eq v2, v3, :cond_1

    .line 13
    .line 14
    goto/16 :goto_7

    .line 15
    .line 16
    :cond_1
    array-length v2, p0

    .line 17
    move v3, v1

    .line 18
    :goto_0
    if-ge v3, v2, :cond_1b

    .line 19
    .line 20
    aget-object v4, p0, v3

    .line 21
    .line 22
    aget-object v5, p1, v3

    .line 23
    .line 24
    if-ne v4, v5, :cond_2

    .line 25
    .line 26
    goto/16 :goto_5

    .line 27
    .line 28
    :cond_2
    if-eqz v4, :cond_1a

    .line 29
    .line 30
    if-nez v5, :cond_3

    .line 31
    .line 32
    goto/16 :goto_6

    .line 33
    .line 34
    :cond_3
    instance-of v6, v4, [Ljava/lang/Object;

    .line 35
    .line 36
    if-eqz v6, :cond_4

    .line 37
    .line 38
    instance-of v6, v5, [Ljava/lang/Object;

    .line 39
    .line 40
    if-eqz v6, :cond_4

    .line 41
    .line 42
    check-cast v4, [Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v5, [Ljava/lang/Object;

    .line 45
    .line 46
    invoke-static {v4, v5}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    if-nez v4, :cond_19

    .line 51
    .line 52
    return v1

    .line 53
    :cond_4
    instance-of v6, v4, [B

    .line 54
    .line 55
    if-eqz v6, :cond_5

    .line 56
    .line 57
    instance-of v6, v5, [B

    .line 58
    .line 59
    if-eqz v6, :cond_5

    .line 60
    .line 61
    check-cast v4, [B

    .line 62
    .line 63
    check-cast v5, [B

    .line 64
    .line 65
    invoke-static {v4, v5}, Ljava/util/Arrays;->equals([B[B)Z

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    if-nez v4, :cond_19

    .line 70
    .line 71
    return v1

    .line 72
    :cond_5
    instance-of v6, v4, [S

    .line 73
    .line 74
    if-eqz v6, :cond_6

    .line 75
    .line 76
    instance-of v6, v5, [S

    .line 77
    .line 78
    if-eqz v6, :cond_6

    .line 79
    .line 80
    check-cast v4, [S

    .line 81
    .line 82
    check-cast v5, [S

    .line 83
    .line 84
    invoke-static {v4, v5}, Ljava/util/Arrays;->equals([S[S)Z

    .line 85
    .line 86
    .line 87
    move-result v4

    .line 88
    if-nez v4, :cond_19

    .line 89
    .line 90
    return v1

    .line 91
    :cond_6
    instance-of v6, v4, [I

    .line 92
    .line 93
    if-eqz v6, :cond_7

    .line 94
    .line 95
    instance-of v6, v5, [I

    .line 96
    .line 97
    if-eqz v6, :cond_7

    .line 98
    .line 99
    check-cast v4, [I

    .line 100
    .line 101
    check-cast v5, [I

    .line 102
    .line 103
    invoke-static {v4, v5}, Ljava/util/Arrays;->equals([I[I)Z

    .line 104
    .line 105
    .line 106
    move-result v4

    .line 107
    if-nez v4, :cond_19

    .line 108
    .line 109
    return v1

    .line 110
    :cond_7
    instance-of v6, v4, [J

    .line 111
    .line 112
    if-eqz v6, :cond_8

    .line 113
    .line 114
    instance-of v6, v5, [J

    .line 115
    .line 116
    if-eqz v6, :cond_8

    .line 117
    .line 118
    check-cast v4, [J

    .line 119
    .line 120
    check-cast v5, [J

    .line 121
    .line 122
    invoke-static {v4, v5}, Ljava/util/Arrays;->equals([J[J)Z

    .line 123
    .line 124
    .line 125
    move-result v4

    .line 126
    if-nez v4, :cond_19

    .line 127
    .line 128
    return v1

    .line 129
    :cond_8
    instance-of v6, v4, [F

    .line 130
    .line 131
    if-eqz v6, :cond_9

    .line 132
    .line 133
    instance-of v6, v5, [F

    .line 134
    .line 135
    if-eqz v6, :cond_9

    .line 136
    .line 137
    check-cast v4, [F

    .line 138
    .line 139
    check-cast v5, [F

    .line 140
    .line 141
    invoke-static {v4, v5}, Ljava/util/Arrays;->equals([F[F)Z

    .line 142
    .line 143
    .line 144
    move-result v4

    .line 145
    if-nez v4, :cond_19

    .line 146
    .line 147
    return v1

    .line 148
    :cond_9
    instance-of v6, v4, [D

    .line 149
    .line 150
    if-eqz v6, :cond_a

    .line 151
    .line 152
    instance-of v6, v5, [D

    .line 153
    .line 154
    if-eqz v6, :cond_a

    .line 155
    .line 156
    check-cast v4, [D

    .line 157
    .line 158
    check-cast v5, [D

    .line 159
    .line 160
    invoke-static {v4, v5}, Ljava/util/Arrays;->equals([D[D)Z

    .line 161
    .line 162
    .line 163
    move-result v4

    .line 164
    if-nez v4, :cond_19

    .line 165
    .line 166
    return v1

    .line 167
    :cond_a
    instance-of v6, v4, [C

    .line 168
    .line 169
    if-eqz v6, :cond_b

    .line 170
    .line 171
    instance-of v6, v5, [C

    .line 172
    .line 173
    if-eqz v6, :cond_b

    .line 174
    .line 175
    check-cast v4, [C

    .line 176
    .line 177
    check-cast v5, [C

    .line 178
    .line 179
    invoke-static {v4, v5}, Ljava/util/Arrays;->equals([C[C)Z

    .line 180
    .line 181
    .line 182
    move-result v4

    .line 183
    if-nez v4, :cond_19

    .line 184
    .line 185
    return v1

    .line 186
    :cond_b
    instance-of v6, v4, [Z

    .line 187
    .line 188
    if-eqz v6, :cond_c

    .line 189
    .line 190
    instance-of v6, v5, [Z

    .line 191
    .line 192
    if-eqz v6, :cond_c

    .line 193
    .line 194
    check-cast v4, [Z

    .line 195
    .line 196
    check-cast v5, [Z

    .line 197
    .line 198
    invoke-static {v4, v5}, Ljava/util/Arrays;->equals([Z[Z)Z

    .line 199
    .line 200
    .line 201
    move-result v4

    .line 202
    if-nez v4, :cond_19

    .line 203
    .line 204
    return v1

    .line 205
    :cond_c
    instance-of v6, v4, Llx0/t;

    .line 206
    .line 207
    const/4 v7, 0x0

    .line 208
    if-eqz v6, :cond_f

    .line 209
    .line 210
    instance-of v6, v5, Llx0/t;

    .line 211
    .line 212
    if-eqz v6, :cond_f

    .line 213
    .line 214
    check-cast v4, Llx0/t;

    .line 215
    .line 216
    iget-object v4, v4, Llx0/t;->d:[B

    .line 217
    .line 218
    check-cast v5, Llx0/t;

    .line 219
    .line 220
    iget-object v5, v5, Llx0/t;->d:[B

    .line 221
    .line 222
    if-nez v4, :cond_d

    .line 223
    .line 224
    move-object v4, v7

    .line 225
    :cond_d
    if-nez v5, :cond_e

    .line 226
    .line 227
    goto :goto_1

    .line 228
    :cond_e
    move-object v7, v5

    .line 229
    :goto_1
    invoke-static {v4, v7}, Ljava/util/Arrays;->equals([B[B)Z

    .line 230
    .line 231
    .line 232
    move-result v4

    .line 233
    if-nez v4, :cond_19

    .line 234
    .line 235
    return v1

    .line 236
    :cond_f
    instance-of v6, v4, Llx0/a0;

    .line 237
    .line 238
    if-eqz v6, :cond_12

    .line 239
    .line 240
    instance-of v6, v5, Llx0/a0;

    .line 241
    .line 242
    if-eqz v6, :cond_12

    .line 243
    .line 244
    check-cast v4, Llx0/a0;

    .line 245
    .line 246
    iget-object v4, v4, Llx0/a0;->d:[S

    .line 247
    .line 248
    check-cast v5, Llx0/a0;

    .line 249
    .line 250
    iget-object v5, v5, Llx0/a0;->d:[S

    .line 251
    .line 252
    if-nez v4, :cond_10

    .line 253
    .line 254
    move-object v4, v7

    .line 255
    :cond_10
    if-nez v5, :cond_11

    .line 256
    .line 257
    goto :goto_2

    .line 258
    :cond_11
    move-object v7, v5

    .line 259
    :goto_2
    invoke-static {v4, v7}, Ljava/util/Arrays;->equals([S[S)Z

    .line 260
    .line 261
    .line 262
    move-result v4

    .line 263
    if-nez v4, :cond_19

    .line 264
    .line 265
    return v1

    .line 266
    :cond_12
    instance-of v6, v4, Llx0/v;

    .line 267
    .line 268
    if-eqz v6, :cond_15

    .line 269
    .line 270
    instance-of v6, v5, Llx0/v;

    .line 271
    .line 272
    if-eqz v6, :cond_15

    .line 273
    .line 274
    check-cast v4, Llx0/v;

    .line 275
    .line 276
    iget-object v4, v4, Llx0/v;->d:[I

    .line 277
    .line 278
    check-cast v5, Llx0/v;

    .line 279
    .line 280
    iget-object v5, v5, Llx0/v;->d:[I

    .line 281
    .line 282
    if-nez v4, :cond_13

    .line 283
    .line 284
    move-object v4, v7

    .line 285
    :cond_13
    if-nez v5, :cond_14

    .line 286
    .line 287
    goto :goto_3

    .line 288
    :cond_14
    move-object v7, v5

    .line 289
    :goto_3
    invoke-static {v4, v7}, Ljava/util/Arrays;->equals([I[I)Z

    .line 290
    .line 291
    .line 292
    move-result v4

    .line 293
    if-nez v4, :cond_19

    .line 294
    .line 295
    return v1

    .line 296
    :cond_15
    instance-of v6, v4, Llx0/x;

    .line 297
    .line 298
    if-eqz v6, :cond_18

    .line 299
    .line 300
    instance-of v6, v5, Llx0/x;

    .line 301
    .line 302
    if-eqz v6, :cond_18

    .line 303
    .line 304
    check-cast v4, Llx0/x;

    .line 305
    .line 306
    iget-object v4, v4, Llx0/x;->d:[J

    .line 307
    .line 308
    check-cast v5, Llx0/x;

    .line 309
    .line 310
    iget-object v5, v5, Llx0/x;->d:[J

    .line 311
    .line 312
    if-nez v4, :cond_16

    .line 313
    .line 314
    move-object v4, v7

    .line 315
    :cond_16
    if-nez v5, :cond_17

    .line 316
    .line 317
    goto :goto_4

    .line 318
    :cond_17
    move-object v7, v5

    .line 319
    :goto_4
    invoke-static {v4, v7}, Ljava/util/Arrays;->equals([J[J)Z

    .line 320
    .line 321
    .line 322
    move-result v4

    .line 323
    if-nez v4, :cond_19

    .line 324
    .line 325
    return v1

    .line 326
    :cond_18
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 327
    .line 328
    .line 329
    move-result v4

    .line 330
    if-nez v4, :cond_19

    .line 331
    .line 332
    return v1

    .line 333
    :cond_19
    :goto_5
    add-int/lit8 v3, v3, 0x1

    .line 334
    .line 335
    goto/16 :goto_0

    .line 336
    .line 337
    :cond_1a
    :goto_6
    return v1

    .line 338
    :cond_1b
    return v0

    .line 339
    :cond_1c
    :goto_7
    return v1
.end method

.method public static final f0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;)Lcq0/n;
    .locals 21

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getId()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getPartnerNumber()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getName()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getBrand()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getAddress()Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerAddressDto;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerAddressDto;->getCountryCode()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v9

    .line 32
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getLocation()Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerGpsCoordinatesDto;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    new-instance v6, Lcq0/t;

    .line 37
    .line 38
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerGpsCoordinatesDto;->getLatitude()D

    .line 39
    .line 40
    .line 41
    move-result-wide v7

    .line 42
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerGpsCoordinatesDto;->getLongitude()D

    .line 43
    .line 44
    .line 45
    move-result-wide v10

    .line 46
    invoke-direct {v6, v7, v8, v10, v11}, Lcq0/t;-><init>(DD)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getContact()Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerContactDto;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    const/4 v7, 0x0

    .line 54
    if-eqz v0, :cond_0

    .line 55
    .line 56
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerContactDto;->getPhone()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    move-object v10, v0

    .line 61
    goto :goto_0

    .line 62
    :cond_0
    move-object v10, v7

    .line 63
    :goto_0
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getContact()Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerContactDto;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    if-eqz v0, :cond_1

    .line 68
    .line 69
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerContactDto;->getUrl()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    move-object v11, v0

    .line 74
    goto :goto_1

    .line 75
    :cond_1
    move-object v11, v7

    .line 76
    :goto_1
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getContact()Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerContactDto;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    if-eqz v0, :cond_2

    .line 81
    .line 82
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerContactDto;->getEmail()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    move-object v12, v0

    .line 87
    goto :goto_2

    .line 88
    :cond_2
    move-object v12, v7

    .line 89
    :goto_2
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getAddress()Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerAddressDto;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    move-object v8, v7

    .line 94
    new-instance v7, Lcq0/h;

    .line 95
    .line 96
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerAddressDto;->getStreet()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v13

    .line 100
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerAddressDto;->getCity()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v14

    .line 104
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerAddressDto;->getZipCode()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    invoke-direct {v7, v13, v14, v0}, Lcq0/h;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getOpeningHours()Ljava/util/List;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    if-eqz v0, :cond_5

    .line 116
    .line 117
    check-cast v0, Ljava/lang/Iterable;

    .line 118
    .line 119
    new-instance v13, Ljava/util/ArrayList;

    .line 120
    .line 121
    const/16 v14, 0xa

    .line 122
    .line 123
    invoke-static {v0, v14}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 124
    .line 125
    .line 126
    move-result v15

    .line 127
    invoke-direct {v13, v15}, Ljava/util/ArrayList;-><init>(I)V

    .line 128
    .line 129
    .line 130
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 135
    .line 136
    .line 137
    move-result v15

    .line 138
    if-eqz v15, :cond_4

    .line 139
    .line 140
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v15

    .line 144
    check-cast v15, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerOpeningHoursDto;

    .line 145
    .line 146
    invoke-virtual {v15}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerOpeningHoursDto;->getPeriodStart()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v16

    .line 150
    invoke-static/range {v16 .. v16}, Ljava/time/DayOfWeek;->valueOf(Ljava/lang/String;)Ljava/time/DayOfWeek;

    .line 151
    .line 152
    .line 153
    move-result-object v8

    .line 154
    invoke-virtual {v15}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerOpeningHoursDto;->getPeriodEnd()Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v16

    .line 158
    invoke-static/range {v16 .. v16}, Ljava/time/DayOfWeek;->valueOf(Ljava/lang/String;)Ljava/time/DayOfWeek;

    .line 159
    .line 160
    .line 161
    move-result-object v14

    .line 162
    invoke-virtual {v15}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerOpeningHoursDto;->getOpeningTimes()Ljava/util/List;

    .line 163
    .line 164
    .line 165
    move-result-object v15

    .line 166
    check-cast v15, Ljava/lang/Iterable;

    .line 167
    .line 168
    move-object/from16 v16, v0

    .line 169
    .line 170
    new-instance v0, Ljava/util/ArrayList;

    .line 171
    .line 172
    move-object/from16 v17, v2

    .line 173
    .line 174
    const/16 v1, 0xa

    .line 175
    .line 176
    invoke-static {v15, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 177
    .line 178
    .line 179
    move-result v2

    .line 180
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 181
    .line 182
    .line 183
    invoke-interface {v15}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 184
    .line 185
    .line 186
    move-result-object v2

    .line 187
    :goto_4
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 188
    .line 189
    .line 190
    move-result v15

    .line 191
    if-eqz v15, :cond_3

    .line 192
    .line 193
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v15

    .line 197
    check-cast v15, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerOpeningTimesDto;

    .line 198
    .line 199
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 200
    .line 201
    .line 202
    move-result-object v18

    .line 203
    invoke-virtual/range {v18 .. v18}, Ljava/time/OffsetDateTime;->getOffset()Ljava/time/ZoneOffset;

    .line 204
    .line 205
    .line 206
    move-result-object v1

    .line 207
    move-object/from16 v18, v2

    .line 208
    .line 209
    const-string v2, "getOffset(...)"

    .line 210
    .line 211
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    new-instance v2, Lcq0/v;

    .line 215
    .line 216
    invoke-virtual {v15}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerOpeningTimesDto;->getFrom()Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v19

    .line 220
    move-object/from16 v20, v3

    .line 221
    .line 222
    invoke-static/range {v19 .. v19}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 223
    .line 224
    .line 225
    move-result-object v3

    .line 226
    invoke-static {v3, v1}, Ljava/time/OffsetTime;->of(Ljava/time/LocalTime;Ljava/time/ZoneOffset;)Ljava/time/OffsetTime;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    move-object/from16 v19, v4

    .line 231
    .line 232
    const-string v4, "of(...)"

    .line 233
    .line 234
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v15}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerOpeningTimesDto;->getTo()Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v15

    .line 241
    invoke-static {v15}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 242
    .line 243
    .line 244
    move-result-object v15

    .line 245
    invoke-static {v15, v1}, Ljava/time/OffsetTime;->of(Ljava/time/LocalTime;Ljava/time/ZoneOffset;)Ljava/time/OffsetTime;

    .line 246
    .line 247
    .line 248
    move-result-object v1

    .line 249
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    invoke-direct {v2, v3, v1}, Lcq0/v;-><init>(Ljava/time/OffsetTime;Ljava/time/OffsetTime;)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 256
    .line 257
    .line 258
    move-object/from16 v2, v18

    .line 259
    .line 260
    move-object/from16 v4, v19

    .line 261
    .line 262
    move-object/from16 v3, v20

    .line 263
    .line 264
    const/16 v1, 0xa

    .line 265
    .line 266
    goto :goto_4

    .line 267
    :cond_3
    move-object/from16 v20, v3

    .line 268
    .line 269
    move-object/from16 v19, v4

    .line 270
    .line 271
    new-instance v1, Lcq0/u;

    .line 272
    .line 273
    invoke-direct {v1, v8, v14, v0}, Lcq0/u;-><init>(Ljava/time/DayOfWeek;Ljava/time/DayOfWeek;Ljava/util/ArrayList;)V

    .line 274
    .line 275
    .line 276
    invoke-virtual {v13, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 277
    .line 278
    .line 279
    move-object/from16 v1, p0

    .line 280
    .line 281
    move-object/from16 v0, v16

    .line 282
    .line 283
    move-object/from16 v2, v17

    .line 284
    .line 285
    const/4 v8, 0x0

    .line 286
    const/16 v14, 0xa

    .line 287
    .line 288
    goto/16 :goto_3

    .line 289
    .line 290
    :cond_4
    move-object/from16 v17, v2

    .line 291
    .line 292
    move-object/from16 v20, v3

    .line 293
    .line 294
    move-object/from16 v19, v4

    .line 295
    .line 296
    goto :goto_5

    .line 297
    :cond_5
    move-object/from16 v17, v2

    .line 298
    .line 299
    move-object/from16 v20, v3

    .line 300
    .line 301
    move-object/from16 v19, v4

    .line 302
    .line 303
    sget-object v13, Lmx0/s;->d:Lmx0/s;

    .line 304
    .line 305
    :goto_5
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;->getDistanceInKm()Ljava/lang/Double;

    .line 306
    .line 307
    .line 308
    move-result-object v0

    .line 309
    if-eqz v0, :cond_6

    .line 310
    .line 311
    invoke-virtual {v0}, Ljava/lang/Double;->doubleValue()D

    .line 312
    .line 313
    .line 314
    move-result-wide v0

    .line 315
    invoke-static {v0, v1}, Lcy0/a;->h(D)I

    .line 316
    .line 317
    .line 318
    move-result v0

    .line 319
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 320
    .line 321
    .line 322
    move-result-object v0

    .line 323
    move-object v8, v0

    .line 324
    goto :goto_6

    .line 325
    :cond_6
    const/4 v8, 0x0

    .line 326
    :goto_6
    new-instance v1, Lcq0/n;

    .line 327
    .line 328
    move-object/from16 v2, v17

    .line 329
    .line 330
    move-object/from16 v4, v19

    .line 331
    .line 332
    move-object/from16 v3, v20

    .line 333
    .line 334
    invoke-direct/range {v1 .. v13}, Lcq0/n;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcq0/t;Lcq0/h;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 335
    .line 336
    .line 337
    return-object v1
.end method

.method public static g(III[B[B)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "destination"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sub-int/2addr p2, p1

    .line 12
    invoke-static {p3, p1, p4, p0, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public static g0([I)Ljava/util/ArrayList;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/util/ArrayList;

    .line 7
    .line 8
    array-length v1, p0

    .line 9
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 10
    .line 11
    .line 12
    array-length v1, p0

    .line 13
    const/4 v2, 0x0

    .line 14
    :goto_0
    if-ge v2, v1, :cond_0

    .line 15
    .line 16
    aget v3, p0, v2

    .line 17
    .line 18
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    add-int/lit8 v2, v2, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    return-object v0
.end method

.method public static h(III[I[I)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "destination"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sub-int/2addr p2, p1

    .line 12
    invoke-static {p3, p1, p4, p0, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public static h0([Ljava/lang/Object;)Ljava/util/Set;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-eq v0, v1, :cond_0

    .line 11
    .line 12
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 13
    .line 14
    array-length v1, p0

    .line 15
    invoke-static {v1}, Lmx0/x;->k(I)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-direct {v0, v1}, Ljava/util/LinkedHashSet;-><init>(I)V

    .line 20
    .line 21
    .line 22
    invoke-static {p0, v0}, Lmx0/n;->V([Ljava/lang/Object;Ljava/util/LinkedHashSet;)V

    .line 23
    .line 24
    .line 25
    return-object v0

    .line 26
    :cond_0
    const/4 v0, 0x0

    .line 27
    aget-object p0, p0, v0

    .line 28
    .line 29
    invoke-static {p0}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :cond_1
    sget-object p0, Lmx0/u;->d:Lmx0/u;

    .line 35
    .line 36
    return-object p0
.end method

.method public static i(III[Ljava/lang/Object;[Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "destination"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sub-int/2addr p2, p1

    .line 12
    invoke-static {p3, p1, p4, p0, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public static i0([Ljava/lang/Object;[Ljava/lang/Object;)Ljava/util/ArrayList;
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "other"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    array-length v0, p0

    .line 12
    array-length v1, p1

    .line 13
    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    new-instance v1, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 20
    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    :goto_0
    if-ge v2, v0, :cond_0

    .line 24
    .line 25
    aget-object v3, p0, v2

    .line 26
    .line 27
    aget-object v4, p1, v2

    .line 28
    .line 29
    new-instance v5, Llx0/l;

    .line 30
    .line 31
    invoke-direct {v5, v3, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    add-int/lit8 v2, v2, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    return-object v1
.end method

.method public static j([C[CIII)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sub-int/2addr p4, p3

    .line 7
    invoke-static {p0, p3, p1, p2, p4}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public static k([J[JIII)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "destination"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sub-int/2addr p4, p3

    .line 12
    invoke-static {p0, p3, p1, p2, p4}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public static synthetic l(III[I[I)V
    .locals 2

    .line 1
    and-int/lit8 v0, p2, 0x2

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move p0, v1

    .line 7
    :cond_0
    and-int/lit8 p2, p2, 0x8

    .line 8
    .line 9
    if-eqz p2, :cond_1

    .line 10
    .line 11
    array-length p1, p3

    .line 12
    :cond_1
    invoke-static {p0, v1, p1, p3, p4}, Lmx0/n;->h(III[I[I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public static synthetic m(III[Ljava/lang/Object;[Ljava/lang/Object;)V
    .locals 2

    .line 1
    and-int/lit8 v0, p2, 0x4

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move p0, v1

    .line 7
    :cond_0
    and-int/lit8 p2, p2, 0x8

    .line 8
    .line 9
    if-eqz p2, :cond_1

    .line 10
    .line 11
    array-length p1, p3

    .line 12
    :cond_1
    invoke-static {v1, p0, p1, p3, p4}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public static n([BII)[B
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    invoke-static {p2, v0}, Lmx0/n;->p(II)V

    .line 8
    .line 9
    .line 10
    invoke-static {p0, p1, p2}, Ljava/util/Arrays;->copyOfRange([BII)[B

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string p1, "copyOfRange(...)"

    .line 15
    .line 16
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-object p0
.end method

.method public static o(II[Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p2

    .line 7
    invoke-static {p1, v0}, Lmx0/n;->p(II)V

    .line 8
    .line 9
    .line 10
    invoke-static {p2, p0, p1}, Ljava/util/Arrays;->copyOfRange([Ljava/lang/Object;II)[Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string p1, "copyOfRange(...)"

    .line 15
    .line 16
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-object p0
.end method

.method public static final p(II)V
    .locals 4

    .line 1
    if-gt p0, p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    .line 5
    .line 6
    const-string v1, ") is greater than size ("

    .line 7
    .line 8
    const-string v2, ")."

    .line 9
    .line 10
    const-string v3, "toIndex ("

    .line 11
    .line 12
    invoke-static {p0, p1, v3, v1, v2}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw v0
.end method

.method public static q(IILjava/lang/Object;[Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p3, p0, p1, p2}, Ljava/util/Arrays;->fill([Ljava/lang/Object;IILjava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public static r(J[J)V
    .locals 2

    .line 1
    array-length v0, p2

    .line 2
    const-string v1, "<this>"

    .line 3
    .line 4
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-static {p2, v1, v0, p0, p1}, Ljava/util/Arrays;->fill([JIIJ)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public static synthetic s([Ljava/lang/Object;Lj51/i;)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    array-length v1, p0

    .line 3
    invoke-static {v0, v1, p1, p0}, Lmx0/n;->q(IILjava/lang/Object;[Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static t([Ljava/lang/Object;)Ljava/util/List;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    array-length v1, p0

    .line 12
    const/4 v2, 0x0

    .line 13
    :goto_0
    if-ge v2, v1, :cond_1

    .line 14
    .line 15
    aget-object v3, p0, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    invoke-interface {v0, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    return-object v0
.end method

.method public static u([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    aget-object p0, p0, v0

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 14
    .line 15
    const-string v0, "Array is empty."

    .line 16
    .line 17
    invoke-direct {p0, v0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static v([F)Ljava/lang/Float;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return-object p0

    .line 11
    :cond_0
    const/4 v0, 0x0

    .line 12
    aget p0, p0, v0

    .line 13
    .line 14
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public static w([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return-object p0

    .line 11
    :cond_0
    const/4 v0, 0x0

    .line 12
    aget-object p0, p0, v0

    .line 13
    .line 14
    return-object p0
.end method

.method public static final x(Lap0/a;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    new-instance p0, La8/r0;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :pswitch_0
    const p0, 0x7f120d3e

    .line 20
    .line 21
    .line 22
    return p0

    .line 23
    :pswitch_1
    const p0, 0x7f120d32

    .line 24
    .line 25
    .line 26
    return p0

    .line 27
    :pswitch_2
    const p0, 0x7f120d2e

    .line 28
    .line 29
    .line 30
    return p0

    .line 31
    :pswitch_3
    const p0, 0x7f120d3a

    .line 32
    .line 33
    .line 34
    return p0

    .line 35
    :pswitch_4
    const p0, 0x7f120d30

    .line 36
    .line 37
    .line 38
    return p0

    .line 39
    :pswitch_5
    const p0, 0x7f120d3c

    .line 40
    .line 41
    .line 42
    return p0

    .line 43
    :pswitch_6
    const p0, 0x7f120d34

    .line 44
    .line 45
    .line 46
    return p0

    .line 47
    :pswitch_7
    const p0, 0x7f120d38

    .line 48
    .line 49
    .line 50
    return p0

    .line 51
    :pswitch_8
    const p0, 0x7f120d36

    .line 52
    .line 53
    .line 54
    return p0

    .line 55
    :pswitch_9
    const p0, 0x7f120d1c

    .line 56
    .line 57
    .line 58
    return p0

    .line 59
    :pswitch_a
    const p0, 0x7f120d28

    .line 60
    .line 61
    .line 62
    return p0

    .line 63
    :pswitch_b
    const p0, 0x7f120d2c

    .line 64
    .line 65
    .line 66
    return p0

    .line 67
    :pswitch_c
    const p0, 0x7f120d2a

    .line 68
    .line 69
    .line 70
    return p0

    .line 71
    :pswitch_d
    const p0, 0x7f120d24

    .line 72
    .line 73
    .line 74
    return p0

    .line 75
    :pswitch_e
    const p0, 0x7f120d26

    .line 76
    .line 77
    .line 78
    return p0

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final y(Lap0/a;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    new-instance p0, La8/r0;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :pswitch_0
    const p0, 0x7f120d3f

    .line 20
    .line 21
    .line 22
    return p0

    .line 23
    :pswitch_1
    const p0, 0x7f120d33

    .line 24
    .line 25
    .line 26
    return p0

    .line 27
    :pswitch_2
    const p0, 0x7f120d2f

    .line 28
    .line 29
    .line 30
    return p0

    .line 31
    :pswitch_3
    const p0, 0x7f120d3b

    .line 32
    .line 33
    .line 34
    return p0

    .line 35
    :pswitch_4
    const p0, 0x7f120d31

    .line 36
    .line 37
    .line 38
    return p0

    .line 39
    :pswitch_5
    const p0, 0x7f120d3d

    .line 40
    .line 41
    .line 42
    return p0

    .line 43
    :pswitch_6
    const p0, 0x7f120d35

    .line 44
    .line 45
    .line 46
    return p0

    .line 47
    :pswitch_7
    const p0, 0x7f120d39

    .line 48
    .line 49
    .line 50
    return p0

    .line 51
    :pswitch_8
    const p0, 0x7f120d37

    .line 52
    .line 53
    .line 54
    return p0

    .line 55
    :pswitch_9
    const p0, 0x7f120d1d

    .line 56
    .line 57
    .line 58
    return p0

    .line 59
    :pswitch_a
    const p0, 0x7f120d29

    .line 60
    .line 61
    .line 62
    return p0

    .line 63
    :pswitch_b
    const p0, 0x7f120d2d

    .line 64
    .line 65
    .line 66
    return p0

    .line 67
    :pswitch_c
    const p0, 0x7f120d2b

    .line 68
    .line 69
    .line 70
    return p0

    .line 71
    :pswitch_d
    const p0, 0x7f120d25

    .line 72
    .line 73
    .line 74
    return p0

    .line 75
    :pswitch_e
    const p0, 0x7f120d27

    .line 76
    .line 77
    .line 78
    return p0

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static z([I)Lgy0/j;
    .locals 3

    .line 1
    new-instance v0, Lgy0/j;

    .line 2
    .line 3
    array-length p0, p0

    .line 4
    const/4 v1, 0x1

    .line 5
    sub-int/2addr p0, v1

    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-direct {v0, v2, p0, v1}, Lgy0/h;-><init>(III)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method
