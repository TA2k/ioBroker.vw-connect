.class public final Ls11/d;
.super Ln11/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final i:[J

.field public final j:[I

.field public final k:[I

.field public final l:[Ljava/lang/String;

.field public final m:Ls11/b;


# direct methods
.method public constructor <init>(Ljava/lang/String;[J[I[I[Ljava/lang/String;Ls11/b;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ln11/f;-><init>(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Ls11/d;->i:[J

    .line 5
    .line 6
    iput-object p3, p0, Ls11/d;->j:[I

    .line 7
    .line 8
    iput-object p4, p0, Ls11/d;->k:[I

    .line 9
    .line 10
    iput-object p5, p0, Ls11/d;->l:[Ljava/lang/String;

    .line 11
    .line 12
    iput-object p6, p0, Ls11/d;->m:Ls11/b;

    .line 13
    .line 14
    return-void
.end method

.method public static s(Ljava/io/DataInput;Ljava/lang/String;)Ls11/d;
    .locals 11

    .line 1
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedShort()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v1, v0, [Ljava/lang/String;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    move v3, v2

    .line 9
    :goto_0
    if-ge v3, v0, :cond_0

    .line 10
    .line 11
    invoke-interface {p0}, Ljava/io/DataInput;->readUTF()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    aput-object v4, v1, v3

    .line 16
    .line 17
    add-int/lit8 v3, v3, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    invoke-interface {p0}, Ljava/io/DataInput;->readInt()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    new-array v6, v3, [J

    .line 25
    .line 26
    new-array v7, v3, [I

    .line 27
    .line 28
    new-array v8, v3, [I

    .line 29
    .line 30
    new-array v9, v3, [Ljava/lang/String;

    .line 31
    .line 32
    :goto_1
    if-ge v2, v3, :cond_2

    .line 33
    .line 34
    invoke-static {p0}, Lkp/v6;->c(Ljava/io/DataInput;)J

    .line 35
    .line 36
    .line 37
    move-result-wide v4

    .line 38
    aput-wide v4, v6, v2

    .line 39
    .line 40
    invoke-static {p0}, Lkp/v6;->c(Ljava/io/DataInput;)J

    .line 41
    .line 42
    .line 43
    move-result-wide v4

    .line 44
    long-to-int v4, v4

    .line 45
    aput v4, v7, v2

    .line 46
    .line 47
    invoke-static {p0}, Lkp/v6;->c(Ljava/io/DataInput;)J

    .line 48
    .line 49
    .line 50
    move-result-wide v4

    .line 51
    long-to-int v4, v4

    .line 52
    aput v4, v8, v2

    .line 53
    .line 54
    const/16 v4, 0x100

    .line 55
    .line 56
    if-ge v0, v4, :cond_1

    .line 57
    .line 58
    :try_start_0
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    goto :goto_2

    .line 63
    :cond_1
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedShort()I

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    :goto_2
    aget-object v4, v1, v4

    .line 68
    .line 69
    aput-object v4, v9, v2
    :try_end_0
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 70
    .line 71
    add-int/lit8 v2, v2, 0x1

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :catch_0
    new-instance p0, Ljava/io/IOException;

    .line 75
    .line 76
    const-string p1, "Invalid encoding"

    .line 77
    .line 78
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    :cond_2
    invoke-interface {p0}, Ljava/io/DataInput;->readBoolean()Z

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    if-eqz v0, :cond_3

    .line 87
    .line 88
    new-instance v0, Ls11/b;

    .line 89
    .line 90
    invoke-static {p0}, Lkp/v6;->c(Ljava/io/DataInput;)J

    .line 91
    .line 92
    .line 93
    move-result-wide v1

    .line 94
    long-to-int v1, v1

    .line 95
    invoke-static {p0}, Ls11/e;->c(Ljava/io/DataInput;)Ls11/e;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    invoke-static {p0}, Ls11/e;->c(Ljava/io/DataInput;)Ls11/e;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    invoke-direct {v0, p1, v1, v2, p0}, Ls11/b;-><init>(Ljava/lang/String;ILs11/e;Ls11/e;)V

    .line 104
    .line 105
    .line 106
    :goto_3
    move-object v10, v0

    .line 107
    goto :goto_4

    .line 108
    :cond_3
    const/4 v0, 0x0

    .line 109
    goto :goto_3

    .line 110
    :goto_4
    new-instance v4, Ls11/d;

    .line 111
    .line 112
    move-object v5, p1

    .line 113
    invoke-direct/range {v4 .. v10}, Ls11/d;-><init>(Ljava/lang/String;[J[I[I[Ljava/lang/String;Ls11/b;)V

    .line 114
    .line 115
    .line 116
    return-object v4
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ls11/d;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_2

    .line 9
    .line 10
    check-cast p1, Ls11/d;

    .line 11
    .line 12
    iget-object v1, p1, Ls11/d;->m:Ls11/b;

    .line 13
    .line 14
    iget-object v3, p0, Ln11/f;->d:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v4, p1, Ln11/f;->d:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-eqz v3, :cond_2

    .line 23
    .line 24
    iget-object v3, p0, Ls11/d;->i:[J

    .line 25
    .line 26
    iget-object v4, p1, Ls11/d;->i:[J

    .line 27
    .line 28
    invoke-static {v3, v4}, Ljava/util/Arrays;->equals([J[J)Z

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    if-eqz v3, :cond_2

    .line 33
    .line 34
    iget-object v3, p0, Ls11/d;->l:[Ljava/lang/String;

    .line 35
    .line 36
    iget-object v4, p1, Ls11/d;->l:[Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {v3, v4}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    if-eqz v3, :cond_2

    .line 43
    .line 44
    iget-object v3, p0, Ls11/d;->j:[I

    .line 45
    .line 46
    iget-object v4, p1, Ls11/d;->j:[I

    .line 47
    .line 48
    invoke-static {v3, v4}, Ljava/util/Arrays;->equals([I[I)Z

    .line 49
    .line 50
    .line 51
    move-result v3

    .line 52
    if-eqz v3, :cond_2

    .line 53
    .line 54
    iget-object v3, p0, Ls11/d;->k:[I

    .line 55
    .line 56
    iget-object p1, p1, Ls11/d;->k:[I

    .line 57
    .line 58
    invoke-static {v3, p1}, Ljava/util/Arrays;->equals([I[I)Z

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    if-eqz p1, :cond_2

    .line 63
    .line 64
    iget-object p0, p0, Ls11/d;->m:Ls11/b;

    .line 65
    .line 66
    if-nez p0, :cond_1

    .line 67
    .line 68
    if-nez v1, :cond_2

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    invoke-virtual {p0, v1}, Ls11/b;->equals(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    if-eqz p0, :cond_2

    .line 76
    .line 77
    :goto_0
    return v0

    .line 78
    :cond_2
    return v2
.end method

.method public final g(J)Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Ls11/d;->i:[J

    .line 2
    .line 3
    invoke-static {v0, p1, p2}, Ljava/util/Arrays;->binarySearch([JJ)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    iget-object v2, p0, Ls11/d;->l:[Ljava/lang/String;

    .line 8
    .line 9
    if-ltz v1, :cond_0

    .line 10
    .line 11
    aget-object p0, v2, v1

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    not-int v1, v1

    .line 15
    array-length v0, v0

    .line 16
    if-ge v1, v0, :cond_2

    .line 17
    .line 18
    if-lez v1, :cond_1

    .line 19
    .line 20
    add-int/lit8 v1, v1, -0x1

    .line 21
    .line 22
    aget-object p0, v2, v1

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_1
    const-string p0, "UTC"

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_2
    iget-object p0, p0, Ls11/d;->m:Ls11/b;

    .line 29
    .line 30
    if-nez p0, :cond_3

    .line 31
    .line 32
    add-int/lit8 v1, v1, -0x1

    .line 33
    .line 34
    aget-object p0, v2, v1

    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_3
    invoke-virtual {p0, p1, p2}, Ls11/b;->s(J)Ls11/e;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    iget-object p0, p0, Ls11/e;->b:Ljava/lang/String;

    .line 42
    .line 43
    return-object p0
.end method

.method public final i(J)I
    .locals 3

    .line 1
    iget-object v0, p0, Ls11/d;->i:[J

    .line 2
    .line 3
    invoke-static {v0, p1, p2}, Ljava/util/Arrays;->binarySearch([JJ)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    iget-object v2, p0, Ls11/d;->j:[I

    .line 8
    .line 9
    if-ltz v1, :cond_0

    .line 10
    .line 11
    aget p0, v2, v1

    .line 12
    .line 13
    return p0

    .line 14
    :cond_0
    not-int v1, v1

    .line 15
    array-length v0, v0

    .line 16
    if-ge v1, v0, :cond_2

    .line 17
    .line 18
    if-lez v1, :cond_1

    .line 19
    .line 20
    add-int/lit8 v1, v1, -0x1

    .line 21
    .line 22
    aget p0, v2, v1

    .line 23
    .line 24
    return p0

    .line 25
    :cond_1
    const/4 p0, 0x0

    .line 26
    return p0

    .line 27
    :cond_2
    iget-object p0, p0, Ls11/d;->m:Ls11/b;

    .line 28
    .line 29
    if-nez p0, :cond_3

    .line 30
    .line 31
    add-int/lit8 v1, v1, -0x1

    .line 32
    .line 33
    aget p0, v2, v1

    .line 34
    .line 35
    return p0

    .line 36
    :cond_3
    invoke-virtual {p0, p1, p2}, Ls11/b;->i(J)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0
.end method

.method public final l(J)I
    .locals 1

    .line 1
    iget-object v0, p0, Ls11/d;->i:[J

    .line 2
    .line 3
    invoke-static {v0, p1, p2}, Ljava/util/Arrays;->binarySearch([JJ)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    iget-object p2, p0, Ls11/d;->k:[I

    .line 8
    .line 9
    if-ltz p1, :cond_0

    .line 10
    .line 11
    aget p0, p2, p1

    .line 12
    .line 13
    return p0

    .line 14
    :cond_0
    not-int p1, p1

    .line 15
    array-length v0, v0

    .line 16
    if-ge p1, v0, :cond_2

    .line 17
    .line 18
    if-lez p1, :cond_1

    .line 19
    .line 20
    add-int/lit8 p1, p1, -0x1

    .line 21
    .line 22
    aget p0, p2, p1

    .line 23
    .line 24
    return p0

    .line 25
    :cond_1
    const/4 p0, 0x0

    .line 26
    return p0

    .line 27
    :cond_2
    iget-object p0, p0, Ls11/d;->m:Ls11/b;

    .line 28
    .line 29
    if-nez p0, :cond_3

    .line 30
    .line 31
    add-int/lit8 p1, p1, -0x1

    .line 32
    .line 33
    aget p0, p2, p1

    .line 34
    .line 35
    return p0

    .line 36
    :cond_3
    iget p0, p0, Ls11/b;->i:I

    .line 37
    .line 38
    return p0
.end method

.method public final m()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final n(J)J
    .locals 3

    .line 1
    iget-object v0, p0, Ls11/d;->i:[J

    .line 2
    .line 3
    invoke-static {v0, p1, p2}, Ljava/util/Arrays;->binarySearch([JJ)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-ltz v1, :cond_0

    .line 8
    .line 9
    add-int/lit8 v1, v1, 0x1

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    not-int v1, v1

    .line 13
    :goto_0
    array-length v2, v0

    .line 14
    if-ge v1, v2, :cond_1

    .line 15
    .line 16
    aget-wide p0, v0, v1

    .line 17
    .line 18
    return-wide p0

    .line 19
    :cond_1
    iget-object p0, p0, Ls11/d;->m:Ls11/b;

    .line 20
    .line 21
    if-nez p0, :cond_2

    .line 22
    .line 23
    return-wide p1

    .line 24
    :cond_2
    array-length v1, v0

    .line 25
    add-int/lit8 v1, v1, -0x1

    .line 26
    .line 27
    aget-wide v0, v0, v1

    .line 28
    .line 29
    cmp-long v2, p1, v0

    .line 30
    .line 31
    if-gez v2, :cond_3

    .line 32
    .line 33
    move-wide p1, v0

    .line 34
    :cond_3
    invoke-virtual {p0, p1, p2}, Ls11/b;->n(J)J

    .line 35
    .line 36
    .line 37
    move-result-wide p0

    .line 38
    return-wide p0
.end method

.method public final p(J)J
    .locals 8

    .line 1
    iget-object v0, p0, Ls11/d;->i:[J

    .line 2
    .line 3
    invoke-static {v0, p1, p2}, Ljava/util/Arrays;->binarySearch([JJ)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const-wide/16 v2, 0x1

    .line 8
    .line 9
    const-wide/high16 v4, -0x8000000000000000L

    .line 10
    .line 11
    if-ltz v1, :cond_0

    .line 12
    .line 13
    cmp-long p0, p1, v4

    .line 14
    .line 15
    if-lez p0, :cond_3

    .line 16
    .line 17
    sub-long/2addr p1, v2

    .line 18
    return-wide p1

    .line 19
    :cond_0
    not-int v1, v1

    .line 20
    array-length v6, v0

    .line 21
    if-ge v1, v6, :cond_1

    .line 22
    .line 23
    if-lez v1, :cond_3

    .line 24
    .line 25
    add-int/lit8 v1, v1, -0x1

    .line 26
    .line 27
    aget-wide v0, v0, v1

    .line 28
    .line 29
    cmp-long p0, v0, v4

    .line 30
    .line 31
    if-lez p0, :cond_3

    .line 32
    .line 33
    sub-long/2addr v0, v2

    .line 34
    return-wide v0

    .line 35
    :cond_1
    iget-object p0, p0, Ls11/d;->m:Ls11/b;

    .line 36
    .line 37
    if-eqz p0, :cond_2

    .line 38
    .line 39
    invoke-virtual {p0, p1, p2}, Ls11/b;->p(J)J

    .line 40
    .line 41
    .line 42
    move-result-wide v6

    .line 43
    cmp-long p0, v6, p1

    .line 44
    .line 45
    if-gez p0, :cond_2

    .line 46
    .line 47
    return-wide v6

    .line 48
    :cond_2
    add-int/lit8 v1, v1, -0x1

    .line 49
    .line 50
    aget-wide v0, v0, v1

    .line 51
    .line 52
    cmp-long p0, v0, v4

    .line 53
    .line 54
    if-lez p0, :cond_3

    .line 55
    .line 56
    sub-long/2addr v0, v2

    .line 57
    return-wide v0

    .line 58
    :cond_3
    return-wide p1
.end method
