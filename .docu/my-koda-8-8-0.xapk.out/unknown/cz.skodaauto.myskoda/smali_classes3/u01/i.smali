.class public Lu01/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;
.implements Ljava/lang/Comparable;


# static fields
.field public static final g:Lu01/i;


# instance fields
.field public final d:[B

.field public transient e:I

.field public transient f:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lu01/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v1, v1, [B

    .line 5
    .line 6
    invoke-direct {v0, v1}, Lu01/i;-><init>([B)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lu01/i;->g:Lu01/i;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>([B)V
    .locals 1

    .line 1
    const-string v0, "data"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lu01/i;->d:[B

    .line 10
    .line 11
    return-void
.end method

.method public static g(Lu01/i;Lu01/i;)I
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const-string v0, "other"

    .line 5
    .line 6
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1}, Lu01/i;->h()[B

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    const/4 v0, 0x0

    .line 14
    invoke-virtual {p0, v0, p1}, Lu01/i;->f(I[B)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public static k(Lu01/i;Lu01/i;)I
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const-string v0, "other"

    .line 5
    .line 6
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1}, Lu01/i;->h()[B

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-virtual {p0, p1}, Lu01/i;->j([B)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public static synthetic p(Lu01/i;III)Lu01/i;
    .locals 1

    .line 1
    and-int/lit8 v0, p3, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 7
    .line 8
    if-eqz p3, :cond_1

    .line 9
    .line 10
    const p2, -0x499602d2

    .line 11
    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2}, Lu01/i;->o(II)Lu01/i;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method


# virtual methods
.method public a()Ljava/lang/String;
    .locals 12

    .line 1
    sget-object v0, Lu01/a;->a:[B

    .line 2
    .line 3
    const-string v1, "<this>"

    .line 4
    .line 5
    iget-object p0, p0, Lu01/i;->d:[B

    .line 6
    .line 7
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v1, "map"

    .line 11
    .line 12
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    array-length v1, p0

    .line 16
    const/4 v2, 0x2

    .line 17
    add-int/2addr v1, v2

    .line 18
    div-int/lit8 v1, v1, 0x3

    .line 19
    .line 20
    mul-int/lit8 v1, v1, 0x4

    .line 21
    .line 22
    new-array v1, v1, [B

    .line 23
    .line 24
    array-length v3, p0

    .line 25
    array-length v4, p0

    .line 26
    rem-int/lit8 v4, v4, 0x3

    .line 27
    .line 28
    sub-int/2addr v3, v4

    .line 29
    const/4 v4, 0x0

    .line 30
    move v5, v4

    .line 31
    :goto_0
    if-ge v4, v3, :cond_0

    .line 32
    .line 33
    add-int/lit8 v6, v4, 0x1

    .line 34
    .line 35
    aget-byte v7, p0, v4

    .line 36
    .line 37
    add-int/lit8 v8, v4, 0x2

    .line 38
    .line 39
    aget-byte v6, p0, v6

    .line 40
    .line 41
    add-int/lit8 v4, v4, 0x3

    .line 42
    .line 43
    aget-byte v8, p0, v8

    .line 44
    .line 45
    add-int/lit8 v9, v5, 0x1

    .line 46
    .line 47
    and-int/lit16 v10, v7, 0xff

    .line 48
    .line 49
    shr-int/2addr v10, v2

    .line 50
    aget-byte v10, v0, v10

    .line 51
    .line 52
    aput-byte v10, v1, v5

    .line 53
    .line 54
    add-int/lit8 v10, v5, 0x2

    .line 55
    .line 56
    and-int/lit8 v7, v7, 0x3

    .line 57
    .line 58
    shl-int/lit8 v7, v7, 0x4

    .line 59
    .line 60
    and-int/lit16 v11, v6, 0xff

    .line 61
    .line 62
    shr-int/lit8 v11, v11, 0x4

    .line 63
    .line 64
    or-int/2addr v7, v11

    .line 65
    aget-byte v7, v0, v7

    .line 66
    .line 67
    aput-byte v7, v1, v9

    .line 68
    .line 69
    add-int/lit8 v7, v5, 0x3

    .line 70
    .line 71
    and-int/lit8 v6, v6, 0xf

    .line 72
    .line 73
    shl-int/2addr v6, v2

    .line 74
    and-int/lit16 v9, v8, 0xff

    .line 75
    .line 76
    shr-int/lit8 v9, v9, 0x6

    .line 77
    .line 78
    or-int/2addr v6, v9

    .line 79
    aget-byte v6, v0, v6

    .line 80
    .line 81
    aput-byte v6, v1, v10

    .line 82
    .line 83
    add-int/lit8 v5, v5, 0x4

    .line 84
    .line 85
    and-int/lit8 v6, v8, 0x3f

    .line 86
    .line 87
    aget-byte v6, v0, v6

    .line 88
    .line 89
    aput-byte v6, v1, v7

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_0
    array-length v6, p0

    .line 93
    sub-int/2addr v6, v3

    .line 94
    const/4 v3, 0x1

    .line 95
    const/16 v7, 0x3d

    .line 96
    .line 97
    if-eq v6, v3, :cond_2

    .line 98
    .line 99
    if-eq v6, v2, :cond_1

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_1
    add-int/lit8 v3, v4, 0x1

    .line 103
    .line 104
    aget-byte v4, p0, v4

    .line 105
    .line 106
    aget-byte p0, p0, v3

    .line 107
    .line 108
    add-int/lit8 v3, v5, 0x1

    .line 109
    .line 110
    and-int/lit16 v6, v4, 0xff

    .line 111
    .line 112
    shr-int/2addr v6, v2

    .line 113
    aget-byte v6, v0, v6

    .line 114
    .line 115
    aput-byte v6, v1, v5

    .line 116
    .line 117
    add-int/lit8 v6, v5, 0x2

    .line 118
    .line 119
    and-int/lit8 v4, v4, 0x3

    .line 120
    .line 121
    shl-int/lit8 v4, v4, 0x4

    .line 122
    .line 123
    and-int/lit16 v8, p0, 0xff

    .line 124
    .line 125
    shr-int/lit8 v8, v8, 0x4

    .line 126
    .line 127
    or-int/2addr v4, v8

    .line 128
    aget-byte v4, v0, v4

    .line 129
    .line 130
    aput-byte v4, v1, v3

    .line 131
    .line 132
    add-int/lit8 v5, v5, 0x3

    .line 133
    .line 134
    and-int/lit8 p0, p0, 0xf

    .line 135
    .line 136
    shl-int/2addr p0, v2

    .line 137
    aget-byte p0, v0, p0

    .line 138
    .line 139
    aput-byte p0, v1, v6

    .line 140
    .line 141
    aput-byte v7, v1, v5

    .line 142
    .line 143
    goto :goto_1

    .line 144
    :cond_2
    aget-byte p0, p0, v4

    .line 145
    .line 146
    add-int/lit8 v3, v5, 0x1

    .line 147
    .line 148
    and-int/lit16 v4, p0, 0xff

    .line 149
    .line 150
    shr-int/lit8 v2, v4, 0x2

    .line 151
    .line 152
    aget-byte v2, v0, v2

    .line 153
    .line 154
    aput-byte v2, v1, v5

    .line 155
    .line 156
    add-int/lit8 v2, v5, 0x2

    .line 157
    .line 158
    and-int/lit8 p0, p0, 0x3

    .line 159
    .line 160
    shl-int/lit8 p0, p0, 0x4

    .line 161
    .line 162
    aget-byte p0, v0, p0

    .line 163
    .line 164
    aput-byte p0, v1, v3

    .line 165
    .line 166
    add-int/lit8 v5, v5, 0x3

    .line 167
    .line 168
    aput-byte v7, v1, v2

    .line 169
    .line 170
    aput-byte v7, v1, v5

    .line 171
    .line 172
    :goto_1
    new-instance p0, Ljava/lang/String;

    .line 173
    .line 174
    sget-object v0, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 175
    .line 176
    invoke-direct {p0, v1, v0}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 177
    .line 178
    .line 179
    return-object p0
.end method

.method public final b(Lu01/i;)I
    .locals 9

    .line 1
    const-string v0, "other"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lu01/i;->d()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p1}, Lu01/i;->d()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x0

    .line 19
    move v4, v3

    .line 20
    :goto_0
    const/4 v5, -0x1

    .line 21
    const/4 v6, 0x1

    .line 22
    if-ge v4, v2, :cond_2

    .line 23
    .line 24
    invoke-virtual {p0, v4}, Lu01/i;->i(I)B

    .line 25
    .line 26
    .line 27
    move-result v7

    .line 28
    and-int/lit16 v7, v7, 0xff

    .line 29
    .line 30
    invoke-virtual {p1, v4}, Lu01/i;->i(I)B

    .line 31
    .line 32
    .line 33
    move-result v8

    .line 34
    and-int/lit16 v8, v8, 0xff

    .line 35
    .line 36
    if-ne v7, v8, :cond_0

    .line 37
    .line 38
    add-int/lit8 v4, v4, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    if-ge v7, v8, :cond_1

    .line 42
    .line 43
    return v5

    .line 44
    :cond_1
    return v6

    .line 45
    :cond_2
    if-ne v0, v1, :cond_3

    .line 46
    .line 47
    return v3

    .line 48
    :cond_3
    if-ge v0, v1, :cond_4

    .line 49
    .line 50
    return v5

    .line 51
    :cond_4
    return v6
.end method

.method public c(Ljava/lang/String;)Lu01/i;
    .locals 2

    .line 1
    invoke-static {p1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0}, Lu01/i;->d()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    iget-object p0, p0, Lu01/i;->d:[B

    .line 11
    .line 12
    invoke-virtual {p1, p0, v0, v1}, Ljava/security/MessageDigest;->update([BII)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1}, Ljava/security/MessageDigest;->digest()[B

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    new-instance p1, Lu01/i;

    .line 20
    .line 21
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    invoke-direct {p1, p0}, Lu01/i;-><init>([B)V

    .line 25
    .line 26
    .line 27
    return-object p1
.end method

.method public final bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lu01/i;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lu01/i;->b(Lu01/i;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public d()I
    .locals 0

    .line 1
    iget-object p0, p0, Lu01/i;->d:[B

    .line 2
    .line 3
    array-length p0, p0

    .line 4
    return p0
.end method

.method public e()Ljava/lang/String;
    .locals 8

    .line 1
    iget-object p0, p0, Lu01/i;->d:[B

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    mul-int/lit8 v0, v0, 0x2

    .line 5
    .line 6
    new-array v0, v0, [C

    .line 7
    .line 8
    array-length v1, p0

    .line 9
    const/4 v2, 0x0

    .line 10
    move v3, v2

    .line 11
    :goto_0
    if-ge v2, v1, :cond_0

    .line 12
    .line 13
    aget-byte v4, p0, v2

    .line 14
    .line 15
    add-int/lit8 v5, v3, 0x1

    .line 16
    .line 17
    shr-int/lit8 v6, v4, 0x4

    .line 18
    .line 19
    and-int/lit8 v6, v6, 0xf

    .line 20
    .line 21
    sget-object v7, Lv01/b;->a:[C

    .line 22
    .line 23
    aget-char v6, v7, v6

    .line 24
    .line 25
    aput-char v6, v0, v3

    .line 26
    .line 27
    add-int/lit8 v3, v3, 0x2

    .line 28
    .line 29
    and-int/lit8 v4, v4, 0xf

    .line 30
    .line 31
    aget-char v4, v7, v4

    .line 32
    .line 33
    aput-char v4, v0, v5

    .line 34
    .line 35
    add-int/lit8 v2, v2, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    new-instance p0, Ljava/lang/String;

    .line 39
    .line 40
    invoke-direct {p0, v0}, Ljava/lang/String;-><init>([C)V

    .line 41
    .line 42
    .line 43
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    instance-of v0, p1, Lu01/i;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    check-cast p1, Lu01/i;

    .line 10
    .line 11
    invoke-virtual {p1}, Lu01/i;->d()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    iget-object p0, p0, Lu01/i;->d:[B

    .line 16
    .line 17
    array-length v2, p0

    .line 18
    if-ne v0, v2, :cond_1

    .line 19
    .line 20
    array-length v0, p0

    .line 21
    invoke-virtual {p1, v1, p0, v1, v0}, Lu01/i;->m(I[BII)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_1

    .line 26
    .line 27
    :goto_0
    const/4 p0, 0x1

    .line 28
    return p0

    .line 29
    :cond_1
    return v1
.end method

.method public f(I[B)I
    .locals 3

    .line 1
    const-string v0, "other"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu01/i;->d:[B

    .line 7
    .line 8
    array-length v0, p0

    .line 9
    array-length v1, p2

    .line 10
    sub-int/2addr v0, v1

    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-static {p1, v1}, Ljava/lang/Math;->max(II)I

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    if-gt p1, v0, :cond_1

    .line 17
    .line 18
    :goto_0
    array-length v2, p2

    .line 19
    invoke-static {p1, v1, v2, p0, p2}, Lu01/b;->a(III[B[B)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    return p1

    .line 26
    :cond_0
    if-eq p1, v0, :cond_1

    .line 27
    .line 28
    add-int/lit8 p1, p1, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    const/4 p0, -0x1

    .line 32
    return p0
.end method

.method public h()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lu01/i;->d:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Lu01/i;->e:I

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return v0

    .line 6
    :cond_0
    iget-object v0, p0, Lu01/i;->d:[B

    .line 7
    .line 8
    invoke-static {v0}, Ljava/util/Arrays;->hashCode([B)I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    iput v0, p0, Lu01/i;->e:I

    .line 13
    .line 14
    return v0
.end method

.method public i(I)B
    .locals 0

    .line 1
    iget-object p0, p0, Lu01/i;->d:[B

    .line 2
    .line 3
    aget-byte p0, p0, p1

    .line 4
    .line 5
    return p0
.end method

.method public j([B)I
    .locals 3

    .line 1
    const-string v0, "other"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lu01/i;->d()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    iget-object p0, p0, Lu01/i;->d:[B

    .line 11
    .line 12
    array-length v1, p0

    .line 13
    array-length v2, p1

    .line 14
    sub-int/2addr v1, v2

    .line 15
    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    :goto_0
    const/4 v1, -0x1

    .line 20
    if-ge v1, v0, :cond_1

    .line 21
    .line 22
    const/4 v1, 0x0

    .line 23
    array-length v2, p1

    .line 24
    invoke-static {v0, v1, v2, p0, p1}, Lu01/b;->a(III[B[B)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_0

    .line 29
    .line 30
    return v0

    .line 31
    :cond_0
    add-int/lit8 v0, v0, -0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    return v1
.end method

.method public l(ILu01/i;I)Z
    .locals 1

    .line 1
    const-string v0, "other"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu01/i;->d:[B

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-virtual {p2, v0, p0, p1, p3}, Lu01/i;->m(I[BII)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public m(I[BII)Z
    .locals 1

    .line 1
    const-string v0, "other"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-ltz p1, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lu01/i;->d:[B

    .line 9
    .line 10
    array-length v0, p0

    .line 11
    sub-int/2addr v0, p4

    .line 12
    if-gt p1, v0, :cond_0

    .line 13
    .line 14
    if-ltz p3, :cond_0

    .line 15
    .line 16
    array-length v0, p2

    .line 17
    sub-int/2addr v0, p4

    .line 18
    if-gt p3, v0, :cond_0

    .line 19
    .line 20
    invoke-static {p1, p3, p4, p0, p2}, Lu01/b;->a(III[B[B)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    if-eqz p0, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x1

    .line 27
    return p0

    .line 28
    :cond_0
    const/4 p0, 0x0

    .line 29
    return p0
.end method

.method public n(Ljava/nio/charset/Charset;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "charset"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/lang/String;

    .line 7
    .line 8
    iget-object p0, p0, Lu01/i;->d:[B

    .line 9
    .line 10
    invoke-direct {v0, p0, p1}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public o(II)Lu01/i;
    .locals 2

    .line 1
    const v0, -0x499602d2

    .line 2
    .line 3
    .line 4
    if-ne p2, v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0}, Lu01/i;->d()I

    .line 7
    .line 8
    .line 9
    move-result p2

    .line 10
    :cond_0
    if-ltz p1, :cond_4

    .line 11
    .line 12
    iget-object v0, p0, Lu01/i;->d:[B

    .line 13
    .line 14
    array-length v1, v0

    .line 15
    if-gt p2, v1, :cond_3

    .line 16
    .line 17
    sub-int v1, p2, p1

    .line 18
    .line 19
    if-ltz v1, :cond_2

    .line 20
    .line 21
    if-nez p1, :cond_1

    .line 22
    .line 23
    array-length v1, v0

    .line 24
    if-ne p2, v1, :cond_1

    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_1
    new-instance p0, Lu01/i;

    .line 28
    .line 29
    invoke-static {v0, p1, p2}, Lmx0/n;->n([BII)[B

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-direct {p0, p1}, Lu01/i;-><init>([B)V

    .line 34
    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 38
    .line 39
    const-string p1, "endIndex < beginIndex"

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :cond_3
    new-instance p0, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    const-string p1, "endIndex > length("

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    array-length p1, v0

    .line 53
    const/16 p2, 0x29

    .line 54
    .line 55
    invoke-static {p0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p1

    .line 69
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 70
    .line 71
    const-string p1, "beginIndex < 0"

    .line 72
    .line 73
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0
.end method

.method public q()Lu01/i;
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    iget-object v1, p0, Lu01/i;->d:[B

    .line 3
    .line 4
    array-length v2, v1

    .line 5
    if-ge v0, v2, :cond_5

    .line 6
    .line 7
    aget-byte v2, v1, v0

    .line 8
    .line 9
    const/16 v3, 0x41

    .line 10
    .line 11
    if-lt v2, v3, :cond_4

    .line 12
    .line 13
    const/16 v4, 0x5a

    .line 14
    .line 15
    if-le v2, v4, :cond_0

    .line 16
    .line 17
    goto :goto_3

    .line 18
    :cond_0
    array-length p0, v1

    .line 19
    invoke-static {v1, p0}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-string v1, "copyOf(...)"

    .line 24
    .line 25
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    add-int/lit8 v1, v0, 0x1

    .line 29
    .line 30
    add-int/lit8 v2, v2, 0x20

    .line 31
    .line 32
    int-to-byte v2, v2

    .line 33
    aput-byte v2, p0, v0

    .line 34
    .line 35
    :goto_1
    array-length v0, p0

    .line 36
    if-ge v1, v0, :cond_3

    .line 37
    .line 38
    aget-byte v0, p0, v1

    .line 39
    .line 40
    if-lt v0, v3, :cond_2

    .line 41
    .line 42
    if-le v0, v4, :cond_1

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_1
    add-int/lit8 v0, v0, 0x20

    .line 46
    .line 47
    int-to-byte v0, v0

    .line 48
    aput-byte v0, p0, v1

    .line 49
    .line 50
    :cond_2
    :goto_2
    add-int/lit8 v1, v1, 0x1

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_3
    new-instance v0, Lu01/i;

    .line 54
    .line 55
    invoke-direct {v0, p0}, Lu01/i;-><init>([B)V

    .line 56
    .line 57
    .line 58
    return-object v0

    .line 59
    :cond_4
    :goto_3
    add-int/lit8 v0, v0, 0x1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_5
    return-object p0
.end method

.method public final r()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Lu01/i;->f:Ljava/lang/String;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lu01/i;->h()[B

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const-string v1, "<this>"

    .line 10
    .line 11
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    new-instance v1, Ljava/lang/String;

    .line 15
    .line 16
    sget-object v2, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 17
    .line 18
    invoke-direct {v1, v0, v2}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 19
    .line 20
    .line 21
    iput-object v1, p0, Lu01/i;->f:Ljava/lang/String;

    .line 22
    .line 23
    return-object v1

    .line 24
    :cond_0
    return-object v0
.end method

.method public s(Lu01/f;I)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Lu01/i;->d:[B

    .line 3
    .line 4
    invoke-virtual {p1, p0, v0, p2}, Lu01/f;->write([BII)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lu01/i;->d:[B

    .line 4
    .line 5
    array-length v2, v1

    .line 6
    if-nez v2, :cond_0

    .line 7
    .line 8
    const-string v0, "[size=0]"

    .line 9
    .line 10
    return-object v0

    .line 11
    :cond_0
    array-length v2, v1

    .line 12
    const/4 v4, 0x0

    .line 13
    const/4 v5, 0x0

    .line 14
    const/4 v6, 0x0

    .line 15
    :cond_1
    :goto_0
    const/16 v8, 0x40

    .line 16
    .line 17
    if-ge v4, v2, :cond_2f

    .line 18
    .line 19
    aget-byte v9, v1, v4

    .line 20
    .line 21
    const v10, 0xfffd

    .line 22
    .line 23
    .line 24
    const/16 v11, 0xa0

    .line 25
    .line 26
    const/16 v12, 0x7f

    .line 27
    .line 28
    const/16 v13, 0x20

    .line 29
    .line 30
    const/16 v14, 0xd

    .line 31
    .line 32
    const/16 v15, 0xa

    .line 33
    .line 34
    const/high16 v3, 0x10000

    .line 35
    .line 36
    const/16 v16, 0x2

    .line 37
    .line 38
    const/16 v17, 0x1

    .line 39
    .line 40
    if-ltz v9, :cond_c

    .line 41
    .line 42
    add-int/lit8 v18, v6, 0x1

    .line 43
    .line 44
    if-ne v6, v8, :cond_2

    .line 45
    .line 46
    goto/16 :goto_6

    .line 47
    .line 48
    :cond_2
    if-eq v9, v15, :cond_4

    .line 49
    .line 50
    if-eq v9, v14, :cond_4

    .line 51
    .line 52
    if-ltz v9, :cond_3

    .line 53
    .line 54
    if-ge v9, v13, :cond_3

    .line 55
    .line 56
    goto/16 :goto_5

    .line 57
    .line 58
    :cond_3
    if-gt v12, v9, :cond_4

    .line 59
    .line 60
    if-ge v9, v11, :cond_4

    .line 61
    .line 62
    goto/16 :goto_5

    .line 63
    .line 64
    :cond_4
    if-ne v9, v10, :cond_5

    .line 65
    .line 66
    goto/16 :goto_5

    .line 67
    .line 68
    :cond_5
    if-ge v9, v3, :cond_6

    .line 69
    .line 70
    move/from16 v6, v17

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_6
    move/from16 v6, v16

    .line 74
    .line 75
    :goto_1
    add-int/2addr v5, v6

    .line 76
    add-int/lit8 v4, v4, 0x1

    .line 77
    .line 78
    :goto_2
    move/from16 v6, v18

    .line 79
    .line 80
    if-ge v4, v2, :cond_1

    .line 81
    .line 82
    aget-byte v9, v1, v4

    .line 83
    .line 84
    if-ltz v9, :cond_1

    .line 85
    .line 86
    add-int/lit8 v4, v4, 0x1

    .line 87
    .line 88
    add-int/lit8 v18, v6, 0x1

    .line 89
    .line 90
    if-ne v6, v8, :cond_7

    .line 91
    .line 92
    goto/16 :goto_6

    .line 93
    .line 94
    :cond_7
    if-eq v9, v15, :cond_9

    .line 95
    .line 96
    if-eq v9, v14, :cond_9

    .line 97
    .line 98
    if-ltz v9, :cond_8

    .line 99
    .line 100
    if-ge v9, v13, :cond_8

    .line 101
    .line 102
    goto/16 :goto_5

    .line 103
    .line 104
    :cond_8
    if-gt v12, v9, :cond_9

    .line 105
    .line 106
    if-ge v9, v11, :cond_9

    .line 107
    .line 108
    goto/16 :goto_5

    .line 109
    .line 110
    :cond_9
    if-ne v9, v10, :cond_a

    .line 111
    .line 112
    goto/16 :goto_5

    .line 113
    .line 114
    :cond_a
    if-ge v9, v3, :cond_b

    .line 115
    .line 116
    move/from16 v6, v17

    .line 117
    .line 118
    goto :goto_3

    .line 119
    :cond_b
    move/from16 v6, v16

    .line 120
    .line 121
    :goto_3
    add-int/2addr v5, v6

    .line 122
    goto :goto_2

    .line 123
    :cond_c
    shr-int/lit8 v7, v9, 0x5

    .line 124
    .line 125
    const/4 v3, -0x2

    .line 126
    const/16 v10, 0x80

    .line 127
    .line 128
    if-ne v7, v3, :cond_15

    .line 129
    .line 130
    add-int/lit8 v3, v4, 0x1

    .line 131
    .line 132
    if-gt v2, v3, :cond_d

    .line 133
    .line 134
    if-ne v6, v8, :cond_2e

    .line 135
    .line 136
    goto/16 :goto_6

    .line 137
    .line 138
    :cond_d
    aget-byte v3, v1, v3

    .line 139
    .line 140
    and-int/lit16 v7, v3, 0xc0

    .line 141
    .line 142
    if-ne v7, v10, :cond_14

    .line 143
    .line 144
    xor-int/lit16 v3, v3, 0xf80

    .line 145
    .line 146
    shl-int/lit8 v7, v9, 0x6

    .line 147
    .line 148
    xor-int/2addr v3, v7

    .line 149
    if-ge v3, v10, :cond_e

    .line 150
    .line 151
    if-ne v6, v8, :cond_2e

    .line 152
    .line 153
    goto/16 :goto_6

    .line 154
    .line 155
    :cond_e
    add-int/lit8 v7, v6, 0x1

    .line 156
    .line 157
    if-ne v6, v8, :cond_f

    .line 158
    .line 159
    goto/16 :goto_6

    .line 160
    .line 161
    :cond_f
    if-eq v3, v15, :cond_11

    .line 162
    .line 163
    if-eq v3, v14, :cond_11

    .line 164
    .line 165
    if-ltz v3, :cond_10

    .line 166
    .line 167
    if-ge v3, v13, :cond_10

    .line 168
    .line 169
    goto/16 :goto_5

    .line 170
    .line 171
    :cond_10
    if-gt v12, v3, :cond_11

    .line 172
    .line 173
    if-ge v3, v11, :cond_11

    .line 174
    .line 175
    goto/16 :goto_5

    .line 176
    .line 177
    :cond_11
    const v6, 0xfffd

    .line 178
    .line 179
    .line 180
    if-ne v3, v6, :cond_12

    .line 181
    .line 182
    goto/16 :goto_5

    .line 183
    .line 184
    :cond_12
    const/high16 v6, 0x10000

    .line 185
    .line 186
    if-ge v3, v6, :cond_13

    .line 187
    .line 188
    move/from16 v16, v17

    .line 189
    .line 190
    :cond_13
    add-int v5, v5, v16

    .line 191
    .line 192
    add-int/lit8 v4, v4, 0x2

    .line 193
    .line 194
    :goto_4
    move v6, v7

    .line 195
    goto/16 :goto_0

    .line 196
    .line 197
    :cond_14
    if-ne v6, v8, :cond_2e

    .line 198
    .line 199
    goto/16 :goto_6

    .line 200
    .line 201
    :cond_15
    shr-int/lit8 v7, v9, 0x4

    .line 202
    .line 203
    const v11, 0xe000

    .line 204
    .line 205
    .line 206
    const v12, 0xd800

    .line 207
    .line 208
    .line 209
    if-ne v7, v3, :cond_20

    .line 210
    .line 211
    add-int/lit8 v3, v4, 0x2

    .line 212
    .line 213
    if-gt v2, v3, :cond_16

    .line 214
    .line 215
    if-ne v6, v8, :cond_2e

    .line 216
    .line 217
    goto/16 :goto_6

    .line 218
    .line 219
    :cond_16
    add-int/lit8 v7, v4, 0x1

    .line 220
    .line 221
    aget-byte v7, v1, v7

    .line 222
    .line 223
    and-int/lit16 v13, v7, 0xc0

    .line 224
    .line 225
    if-ne v13, v10, :cond_1f

    .line 226
    .line 227
    aget-byte v3, v1, v3

    .line 228
    .line 229
    and-int/lit16 v13, v3, 0xc0

    .line 230
    .line 231
    if-ne v13, v10, :cond_1e

    .line 232
    .line 233
    const v10, -0x1e080

    .line 234
    .line 235
    .line 236
    xor-int/2addr v3, v10

    .line 237
    shl-int/lit8 v7, v7, 0x6

    .line 238
    .line 239
    xor-int/2addr v3, v7

    .line 240
    shl-int/lit8 v7, v9, 0xc

    .line 241
    .line 242
    xor-int/2addr v3, v7

    .line 243
    const/16 v7, 0x800

    .line 244
    .line 245
    if-ge v3, v7, :cond_17

    .line 246
    .line 247
    if-ne v6, v8, :cond_2e

    .line 248
    .line 249
    goto/16 :goto_6

    .line 250
    .line 251
    :cond_17
    if-gt v12, v3, :cond_18

    .line 252
    .line 253
    if-ge v3, v11, :cond_18

    .line 254
    .line 255
    if-ne v6, v8, :cond_2e

    .line 256
    .line 257
    goto/16 :goto_6

    .line 258
    .line 259
    :cond_18
    add-int/lit8 v7, v6, 0x1

    .line 260
    .line 261
    if-ne v6, v8, :cond_19

    .line 262
    .line 263
    goto/16 :goto_6

    .line 264
    .line 265
    :cond_19
    if-eq v3, v15, :cond_1b

    .line 266
    .line 267
    if-eq v3, v14, :cond_1b

    .line 268
    .line 269
    if-ltz v3, :cond_1a

    .line 270
    .line 271
    const/16 v6, 0x20

    .line 272
    .line 273
    if-ge v3, v6, :cond_1a

    .line 274
    .line 275
    goto/16 :goto_5

    .line 276
    .line 277
    :cond_1a
    const/16 v6, 0x7f

    .line 278
    .line 279
    if-gt v6, v3, :cond_1b

    .line 280
    .line 281
    const/16 v6, 0xa0

    .line 282
    .line 283
    if-ge v3, v6, :cond_1b

    .line 284
    .line 285
    goto/16 :goto_5

    .line 286
    .line 287
    :cond_1b
    const v6, 0xfffd

    .line 288
    .line 289
    .line 290
    if-ne v3, v6, :cond_1c

    .line 291
    .line 292
    goto/16 :goto_5

    .line 293
    .line 294
    :cond_1c
    const/high16 v6, 0x10000

    .line 295
    .line 296
    if-ge v3, v6, :cond_1d

    .line 297
    .line 298
    move/from16 v16, v17

    .line 299
    .line 300
    :cond_1d
    add-int v5, v5, v16

    .line 301
    .line 302
    add-int/lit8 v4, v4, 0x3

    .line 303
    .line 304
    goto :goto_4

    .line 305
    :cond_1e
    if-ne v6, v8, :cond_2e

    .line 306
    .line 307
    goto/16 :goto_6

    .line 308
    .line 309
    :cond_1f
    if-ne v6, v8, :cond_2e

    .line 310
    .line 311
    goto/16 :goto_6

    .line 312
    .line 313
    :cond_20
    shr-int/lit8 v7, v9, 0x3

    .line 314
    .line 315
    if-ne v7, v3, :cond_2d

    .line 316
    .line 317
    add-int/lit8 v3, v4, 0x3

    .line 318
    .line 319
    if-gt v2, v3, :cond_21

    .line 320
    .line 321
    if-ne v6, v8, :cond_2e

    .line 322
    .line 323
    goto/16 :goto_6

    .line 324
    .line 325
    :cond_21
    add-int/lit8 v7, v4, 0x1

    .line 326
    .line 327
    aget-byte v7, v1, v7

    .line 328
    .line 329
    and-int/lit16 v13, v7, 0xc0

    .line 330
    .line 331
    if-ne v13, v10, :cond_2c

    .line 332
    .line 333
    add-int/lit8 v13, v4, 0x2

    .line 334
    .line 335
    aget-byte v13, v1, v13

    .line 336
    .line 337
    and-int/lit16 v14, v13, 0xc0

    .line 338
    .line 339
    if-ne v14, v10, :cond_2b

    .line 340
    .line 341
    aget-byte v3, v1, v3

    .line 342
    .line 343
    and-int/lit16 v14, v3, 0xc0

    .line 344
    .line 345
    if-ne v14, v10, :cond_2a

    .line 346
    .line 347
    const v10, 0x381f80

    .line 348
    .line 349
    .line 350
    xor-int/2addr v3, v10

    .line 351
    shl-int/lit8 v10, v13, 0x6

    .line 352
    .line 353
    xor-int/2addr v3, v10

    .line 354
    shl-int/lit8 v7, v7, 0xc

    .line 355
    .line 356
    xor-int/2addr v3, v7

    .line 357
    shl-int/lit8 v7, v9, 0x12

    .line 358
    .line 359
    xor-int/2addr v3, v7

    .line 360
    const v7, 0x10ffff

    .line 361
    .line 362
    .line 363
    if-le v3, v7, :cond_22

    .line 364
    .line 365
    if-ne v6, v8, :cond_2e

    .line 366
    .line 367
    goto :goto_6

    .line 368
    :cond_22
    if-gt v12, v3, :cond_23

    .line 369
    .line 370
    if-ge v3, v11, :cond_23

    .line 371
    .line 372
    if-ne v6, v8, :cond_2e

    .line 373
    .line 374
    goto :goto_6

    .line 375
    :cond_23
    const/high16 v7, 0x10000

    .line 376
    .line 377
    if-ge v3, v7, :cond_24

    .line 378
    .line 379
    if-ne v6, v8, :cond_2e

    .line 380
    .line 381
    goto :goto_6

    .line 382
    :cond_24
    add-int/lit8 v7, v6, 0x1

    .line 383
    .line 384
    if-ne v6, v8, :cond_25

    .line 385
    .line 386
    goto :goto_6

    .line 387
    :cond_25
    if-eq v3, v15, :cond_27

    .line 388
    .line 389
    const/16 v6, 0xd

    .line 390
    .line 391
    if-eq v3, v6, :cond_27

    .line 392
    .line 393
    if-ltz v3, :cond_26

    .line 394
    .line 395
    const/16 v6, 0x20

    .line 396
    .line 397
    if-ge v3, v6, :cond_26

    .line 398
    .line 399
    goto :goto_5

    .line 400
    :cond_26
    const/16 v6, 0x7f

    .line 401
    .line 402
    if-gt v6, v3, :cond_27

    .line 403
    .line 404
    const/16 v6, 0xa0

    .line 405
    .line 406
    if-ge v3, v6, :cond_27

    .line 407
    .line 408
    goto :goto_5

    .line 409
    :cond_27
    const v6, 0xfffd

    .line 410
    .line 411
    .line 412
    if-ne v3, v6, :cond_28

    .line 413
    .line 414
    goto :goto_5

    .line 415
    :cond_28
    const/high16 v6, 0x10000

    .line 416
    .line 417
    if-ge v3, v6, :cond_29

    .line 418
    .line 419
    move/from16 v16, v17

    .line 420
    .line 421
    :cond_29
    add-int v5, v5, v16

    .line 422
    .line 423
    add-int/lit8 v4, v4, 0x4

    .line 424
    .line 425
    goto/16 :goto_4

    .line 426
    .line 427
    :cond_2a
    if-ne v6, v8, :cond_2e

    .line 428
    .line 429
    goto :goto_6

    .line 430
    :cond_2b
    if-ne v6, v8, :cond_2e

    .line 431
    .line 432
    goto :goto_6

    .line 433
    :cond_2c
    if-ne v6, v8, :cond_2e

    .line 434
    .line 435
    goto :goto_6

    .line 436
    :cond_2d
    if-ne v6, v8, :cond_2e

    .line 437
    .line 438
    goto :goto_6

    .line 439
    :cond_2e
    :goto_5
    const/4 v5, -0x1

    .line 440
    :cond_2f
    :goto_6
    const-string v2, "\u2026]"

    .line 441
    .line 442
    const-string v3, "[size="

    .line 443
    .line 444
    const/16 v4, 0x5d

    .line 445
    .line 446
    const/4 v6, -0x1

    .line 447
    if-ne v5, v6, :cond_33

    .line 448
    .line 449
    array-length v5, v1

    .line 450
    if-gt v5, v8, :cond_30

    .line 451
    .line 452
    new-instance v1, Ljava/lang/StringBuilder;

    .line 453
    .line 454
    const-string v2, "[hex="

    .line 455
    .line 456
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 457
    .line 458
    .line 459
    invoke-virtual {v0}, Lu01/i;->e()Ljava/lang/String;

    .line 460
    .line 461
    .line 462
    move-result-object v0

    .line 463
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 464
    .line 465
    .line 466
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 467
    .line 468
    .line 469
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 470
    .line 471
    .line 472
    move-result-object v0

    .line 473
    return-object v0

    .line 474
    :cond_30
    new-instance v4, Ljava/lang/StringBuilder;

    .line 475
    .line 476
    invoke-direct {v4, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 477
    .line 478
    .line 479
    array-length v3, v1

    .line 480
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 481
    .line 482
    .line 483
    const-string v3, " hex="

    .line 484
    .line 485
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 486
    .line 487
    .line 488
    array-length v3, v1

    .line 489
    if-gt v8, v3, :cond_32

    .line 490
    .line 491
    array-length v3, v1

    .line 492
    if-ne v8, v3, :cond_31

    .line 493
    .line 494
    goto :goto_7

    .line 495
    :cond_31
    new-instance v0, Lu01/i;

    .line 496
    .line 497
    const/4 v3, 0x0

    .line 498
    invoke-static {v1, v3, v8}, Lmx0/n;->n([BII)[B

    .line 499
    .line 500
    .line 501
    move-result-object v1

    .line 502
    invoke-direct {v0, v1}, Lu01/i;-><init>([B)V

    .line 503
    .line 504
    .line 505
    :goto_7
    invoke-virtual {v0}, Lu01/i;->e()Ljava/lang/String;

    .line 506
    .line 507
    .line 508
    move-result-object v0

    .line 509
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 510
    .line 511
    .line 512
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 513
    .line 514
    .line 515
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 516
    .line 517
    .line 518
    move-result-object v0

    .line 519
    return-object v0

    .line 520
    :cond_32
    new-instance v0, Ljava/lang/StringBuilder;

    .line 521
    .line 522
    const-string v2, "endIndex > length("

    .line 523
    .line 524
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 525
    .line 526
    .line 527
    array-length v1, v1

    .line 528
    const/16 v2, 0x29

    .line 529
    .line 530
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 531
    .line 532
    .line 533
    move-result-object v0

    .line 534
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 535
    .line 536
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 537
    .line 538
    .line 539
    move-result-object v0

    .line 540
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 541
    .line 542
    .line 543
    throw v1

    .line 544
    :cond_33
    invoke-virtual {v0}, Lu01/i;->r()Ljava/lang/String;

    .line 545
    .line 546
    .line 547
    move-result-object v0

    .line 548
    const/4 v6, 0x0

    .line 549
    invoke-virtual {v0, v6, v5}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 550
    .line 551
    .line 552
    move-result-object v7

    .line 553
    const-string v8, "substring(...)"

    .line 554
    .line 555
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 556
    .line 557
    .line 558
    const-string v8, "\\"

    .line 559
    .line 560
    const-string v9, "\\\\"

    .line 561
    .line 562
    invoke-static {v6, v7, v8, v9}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 563
    .line 564
    .line 565
    move-result-object v7

    .line 566
    const-string v8, "\n"

    .line 567
    .line 568
    const-string v9, "\\n"

    .line 569
    .line 570
    invoke-static {v6, v7, v8, v9}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 571
    .line 572
    .line 573
    move-result-object v7

    .line 574
    const-string v8, "\r"

    .line 575
    .line 576
    const-string v9, "\\r"

    .line 577
    .line 578
    invoke-static {v6, v7, v8, v9}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 579
    .line 580
    .line 581
    move-result-object v6

    .line 582
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 583
    .line 584
    .line 585
    move-result v0

    .line 586
    if-ge v5, v0, :cond_34

    .line 587
    .line 588
    new-instance v0, Ljava/lang/StringBuilder;

    .line 589
    .line 590
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 591
    .line 592
    .line 593
    array-length v1, v1

    .line 594
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 595
    .line 596
    .line 597
    const-string v1, " text="

    .line 598
    .line 599
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 600
    .line 601
    .line 602
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 603
    .line 604
    .line 605
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 606
    .line 607
    .line 608
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 609
    .line 610
    .line 611
    move-result-object v0

    .line 612
    return-object v0

    .line 613
    :cond_34
    const-string v0, "[text="

    .line 614
    .line 615
    invoke-static {v4, v0, v6}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 616
    .line 617
    .line 618
    move-result-object v0

    .line 619
    return-object v0
.end method
