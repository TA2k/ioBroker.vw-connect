.class public final Lm9/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:[B

.field public c:I

.field public d:I

.field public e:I


# direct methods
.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lm9/f;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Lw7/w;->b:[B

    iput-object v0, p0, Lm9/f;->b:[B

    return-void
.end method

.method public constructor <init>(II)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lm9/f;->a:I

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    iput p1, p0, Lm9/f;->c:I

    .line 17
    iput p2, p0, Lm9/f;->d:I

    mul-int/lit8 p2, p2, 0x2

    add-int/lit8 p2, p2, -0x1

    .line 18
    new-array p1, p2, [B

    iput-object p1, p0, Lm9/f;->b:[B

    const/4 p1, 0x0

    .line 19
    iput p1, p0, Lm9/f;->e:I

    return-void
.end method

.method public constructor <init>(I[B)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lm9/f;->a:I

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    iput-object p2, p0, Lm9/f;->b:[B

    .line 14
    iput p1, p0, Lm9/f;->e:I

    return-void
.end method

.method public constructor <init>([B)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lm9/f;->a:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Lm9/f;->b:[B

    .line 5
    array-length p1, p1

    iput p1, p0, Lm9/f;->c:I

    return-void
.end method

.method public constructor <init>([BII)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lm9/f;->a:I

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput-object p1, p0, Lm9/f;->b:[B

    .line 8
    iput p2, p0, Lm9/f;->d:I

    .line 9
    iput p3, p0, Lm9/f;->c:I

    const/4 p1, 0x0

    .line 10
    iput p1, p0, Lm9/f;->e:I

    .line 11
    invoke-virtual {p0}, Lm9/f;->a()V

    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 1
    iget v0, p0, Lm9/f;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lm9/f;->d:I

    .line 7
    .line 8
    if-ltz v0, :cond_1

    .line 9
    .line 10
    iget v1, p0, Lm9/f;->c:I

    .line 11
    .line 12
    if-lt v0, v1, :cond_0

    .line 13
    .line 14
    if-ne v0, v1, :cond_1

    .line 15
    .line 16
    iget p0, p0, Lm9/f;->e:I

    .line 17
    .line 18
    if-nez p0, :cond_1

    .line 19
    .line 20
    :cond_0
    const/4 p0, 0x1

    .line 21
    goto :goto_0

    .line 22
    :cond_1
    const/4 p0, 0x0

    .line 23
    :goto_0
    invoke-static {p0}, Lw7/a;->j(Z)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :pswitch_0
    iget v0, p0, Lm9/f;->c:I

    .line 28
    .line 29
    if-ltz v0, :cond_3

    .line 30
    .line 31
    iget v1, p0, Lm9/f;->e:I

    .line 32
    .line 33
    if-lt v0, v1, :cond_2

    .line 34
    .line 35
    if-ne v0, v1, :cond_3

    .line 36
    .line 37
    iget p0, p0, Lm9/f;->d:I

    .line 38
    .line 39
    if-nez p0, :cond_3

    .line 40
    .line 41
    :cond_2
    const/4 p0, 0x1

    .line 42
    goto :goto_1

    .line 43
    :cond_3
    const/4 p0, 0x0

    .line 44
    :goto_1
    invoke-static {p0}, Lw7/a;->j(Z)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public b()I
    .locals 2

    .line 1
    iget v0, p0, Lm9/f;->e:I

    .line 2
    .line 3
    iget v1, p0, Lm9/f;->c:I

    .line 4
    .line 5
    sub-int/2addr v0, v1

    .line 6
    mul-int/lit8 v0, v0, 0x8

    .line 7
    .line 8
    iget p0, p0, Lm9/f;->d:I

    .line 9
    .line 10
    sub-int/2addr v0, p0

    .line 11
    return v0
.end method

.method public c()V
    .locals 1

    .line 1
    iget v0, p0, Lm9/f;->d:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    const/4 v0, 0x0

    .line 7
    iput v0, p0, Lm9/f;->d:I

    .line 8
    .line 9
    iget v0, p0, Lm9/f;->c:I

    .line 10
    .line 11
    add-int/lit8 v0, v0, 0x1

    .line 12
    .line 13
    iput v0, p0, Lm9/f;->c:I

    .line 14
    .line 15
    invoke-virtual {p0}, Lm9/f;->a()V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public d(I)Z
    .locals 4

    .line 1
    iget v0, p0, Lm9/f;->d:I

    .line 2
    .line 3
    div-int/lit8 v1, p1, 0x8

    .line 4
    .line 5
    add-int v2, v0, v1

    .line 6
    .line 7
    iget v3, p0, Lm9/f;->e:I

    .line 8
    .line 9
    add-int/2addr v3, p1

    .line 10
    mul-int/lit8 v1, v1, 0x8

    .line 11
    .line 12
    sub-int/2addr v3, v1

    .line 13
    const/4 p1, 0x7

    .line 14
    if-le v3, p1, :cond_0

    .line 15
    .line 16
    add-int/lit8 v2, v2, 0x1

    .line 17
    .line 18
    add-int/lit8 v3, v3, -0x8

    .line 19
    .line 20
    :cond_0
    const/4 p1, 0x1

    .line 21
    :cond_1
    :goto_0
    add-int/2addr v0, p1

    .line 22
    if-gt v0, v2, :cond_2

    .line 23
    .line 24
    iget v1, p0, Lm9/f;->c:I

    .line 25
    .line 26
    if-ge v2, v1, :cond_2

    .line 27
    .line 28
    invoke-virtual {p0, v0}, Lm9/f;->r(I)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    add-int/lit8 v2, v2, 0x1

    .line 35
    .line 36
    add-int/lit8 v0, v0, 0x2

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_2
    iget p0, p0, Lm9/f;->c:I

    .line 40
    .line 41
    if-lt v2, p0, :cond_4

    .line 42
    .line 43
    if-ne v2, p0, :cond_3

    .line 44
    .line 45
    if-nez v3, :cond_3

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_3
    const/4 p0, 0x0

    .line 49
    return p0

    .line 50
    :cond_4
    :goto_1
    return p1
.end method

.method public e()Z
    .locals 7

    .line 1
    iget v0, p0, Lm9/f;->d:I

    .line 2
    .line 3
    iget v1, p0, Lm9/f;->e:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    move v3, v2

    .line 7
    :goto_0
    iget v4, p0, Lm9/f;->d:I

    .line 8
    .line 9
    iget v5, p0, Lm9/f;->c:I

    .line 10
    .line 11
    if-ge v4, v5, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Lm9/f;->h()Z

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    if-nez v4, :cond_0

    .line 18
    .line 19
    add-int/lit8 v3, v3, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    iget v4, p0, Lm9/f;->d:I

    .line 23
    .line 24
    iget v5, p0, Lm9/f;->c:I

    .line 25
    .line 26
    const/4 v6, 0x1

    .line 27
    if-ne v4, v5, :cond_1

    .line 28
    .line 29
    move v4, v6

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move v4, v2

    .line 32
    :goto_1
    iput v0, p0, Lm9/f;->d:I

    .line 33
    .line 34
    iput v1, p0, Lm9/f;->e:I

    .line 35
    .line 36
    if-nez v4, :cond_2

    .line 37
    .line 38
    mul-int/lit8 v3, v3, 0x2

    .line 39
    .line 40
    add-int/2addr v3, v6

    .line 41
    invoke-virtual {p0, v3}, Lm9/f;->d(I)Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-eqz p0, :cond_2

    .line 46
    .line 47
    return v6

    .line 48
    :cond_2
    return v2
.end method

.method public f()I
    .locals 1

    .line 1
    iget v0, p0, Lm9/f;->d:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    :goto_0
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 9
    .line 10
    .line 11
    iget p0, p0, Lm9/f;->c:I

    .line 12
    .line 13
    return p0
.end method

.method public g()I
    .locals 1

    .line 1
    iget v0, p0, Lm9/f;->c:I

    .line 2
    .line 3
    mul-int/lit8 v0, v0, 0x8

    .line 4
    .line 5
    iget p0, p0, Lm9/f;->d:I

    .line 6
    .line 7
    add-int/2addr v0, p0

    .line 8
    return v0
.end method

.method public h()Z
    .locals 3

    .line 1
    iget v0, p0, Lm9/f;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lm9/f;->b:[B

    .line 7
    .line 8
    iget v1, p0, Lm9/f;->d:I

    .line 9
    .line 10
    aget-byte v0, v0, v1

    .line 11
    .line 12
    const/16 v1, 0x80

    .line 13
    .line 14
    iget v2, p0, Lm9/f;->e:I

    .line 15
    .line 16
    shr-int/2addr v1, v2

    .line 17
    and-int/2addr v0, v1

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    invoke-virtual {p0}, Lm9/f;->s()V

    .line 24
    .line 25
    .line 26
    return v0

    .line 27
    :pswitch_0
    iget-object v0, p0, Lm9/f;->b:[B

    .line 28
    .line 29
    iget v1, p0, Lm9/f;->c:I

    .line 30
    .line 31
    aget-byte v0, v0, v1

    .line 32
    .line 33
    const/16 v1, 0x80

    .line 34
    .line 35
    iget v2, p0, Lm9/f;->d:I

    .line 36
    .line 37
    shr-int/2addr v1, v2

    .line 38
    and-int/2addr v0, v1

    .line 39
    if-eqz v0, :cond_1

    .line 40
    .line 41
    const/4 v0, 0x1

    .line 42
    goto :goto_1

    .line 43
    :cond_1
    const/4 v0, 0x0

    .line 44
    :goto_1
    invoke-virtual {p0}, Lm9/f;->s()V

    .line 45
    .line 46
    .line 47
    return v0

    .line 48
    :pswitch_1
    iget-object v0, p0, Lm9/f;->b:[B

    .line 49
    .line 50
    iget v1, p0, Lm9/f;->d:I

    .line 51
    .line 52
    aget-byte v0, v0, v1

    .line 53
    .line 54
    and-int/lit16 v0, v0, 0xff

    .line 55
    .line 56
    iget v1, p0, Lm9/f;->e:I

    .line 57
    .line 58
    shr-int/2addr v0, v1

    .line 59
    const/4 v1, 0x1

    .line 60
    and-int/2addr v0, v1

    .line 61
    if-ne v0, v1, :cond_2

    .line 62
    .line 63
    move v0, v1

    .line 64
    goto :goto_2

    .line 65
    :cond_2
    const/4 v0, 0x0

    .line 66
    :goto_2
    invoke-virtual {p0, v1}, Lm9/f;->t(I)V

    .line 67
    .line 68
    .line 69
    return v0

    .line 70
    nop

    .line 71
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public i(I)I
    .locals 9

    .line 1
    iget v0, p0, Lm9/f;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lm9/f;->e:I

    .line 7
    .line 8
    add-int/2addr v0, p1

    .line 9
    iput v0, p0, Lm9/f;->e:I

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    move v1, v0

    .line 13
    :goto_0
    iget v2, p0, Lm9/f;->e:I

    .line 14
    .line 15
    const/4 v3, 0x2

    .line 16
    const/4 v4, 0x1

    .line 17
    const/16 v5, 0x8

    .line 18
    .line 19
    if-le v2, v5, :cond_1

    .line 20
    .line 21
    add-int/lit8 v2, v2, -0x8

    .line 22
    .line 23
    iput v2, p0, Lm9/f;->e:I

    .line 24
    .line 25
    iget-object v5, p0, Lm9/f;->b:[B

    .line 26
    .line 27
    iget v6, p0, Lm9/f;->d:I

    .line 28
    .line 29
    aget-byte v5, v5, v6

    .line 30
    .line 31
    and-int/lit16 v5, v5, 0xff

    .line 32
    .line 33
    shl-int v2, v5, v2

    .line 34
    .line 35
    or-int/2addr v1, v2

    .line 36
    add-int/lit8 v2, v6, 0x1

    .line 37
    .line 38
    invoke-virtual {p0, v2}, Lm9/f;->r(I)Z

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    if-eqz v2, :cond_0

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_0
    move v3, v4

    .line 46
    :goto_1
    add-int/2addr v6, v3

    .line 47
    iput v6, p0, Lm9/f;->d:I

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    iget-object v6, p0, Lm9/f;->b:[B

    .line 51
    .line 52
    iget v7, p0, Lm9/f;->d:I

    .line 53
    .line 54
    aget-byte v6, v6, v7

    .line 55
    .line 56
    and-int/lit16 v6, v6, 0xff

    .line 57
    .line 58
    rsub-int/lit8 v8, v2, 0x8

    .line 59
    .line 60
    shr-int/2addr v6, v8

    .line 61
    or-int/2addr v1, v6

    .line 62
    rsub-int/lit8 p1, p1, 0x20

    .line 63
    .line 64
    const/4 v6, -0x1

    .line 65
    ushr-int p1, v6, p1

    .line 66
    .line 67
    and-int/2addr p1, v1

    .line 68
    if-ne v2, v5, :cond_3

    .line 69
    .line 70
    iput v0, p0, Lm9/f;->e:I

    .line 71
    .line 72
    add-int/lit8 v0, v7, 0x1

    .line 73
    .line 74
    invoke-virtual {p0, v0}, Lm9/f;->r(I)Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    if-eqz v0, :cond_2

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_2
    move v3, v4

    .line 82
    :goto_2
    add-int/2addr v7, v3

    .line 83
    iput v7, p0, Lm9/f;->d:I

    .line 84
    .line 85
    :cond_3
    invoke-virtual {p0}, Lm9/f;->a()V

    .line 86
    .line 87
    .line 88
    return p1

    .line 89
    :pswitch_0
    const/4 v0, 0x0

    .line 90
    if-nez p1, :cond_4

    .line 91
    .line 92
    goto :goto_4

    .line 93
    :cond_4
    iget v1, p0, Lm9/f;->d:I

    .line 94
    .line 95
    add-int/2addr v1, p1

    .line 96
    iput v1, p0, Lm9/f;->d:I

    .line 97
    .line 98
    move v1, v0

    .line 99
    :goto_3
    iget v2, p0, Lm9/f;->d:I

    .line 100
    .line 101
    const/16 v3, 0x8

    .line 102
    .line 103
    if-le v2, v3, :cond_5

    .line 104
    .line 105
    add-int/lit8 v2, v2, -0x8

    .line 106
    .line 107
    iput v2, p0, Lm9/f;->d:I

    .line 108
    .line 109
    iget-object v3, p0, Lm9/f;->b:[B

    .line 110
    .line 111
    iget v4, p0, Lm9/f;->c:I

    .line 112
    .line 113
    add-int/lit8 v5, v4, 0x1

    .line 114
    .line 115
    iput v5, p0, Lm9/f;->c:I

    .line 116
    .line 117
    aget-byte v3, v3, v4

    .line 118
    .line 119
    and-int/lit16 v3, v3, 0xff

    .line 120
    .line 121
    shl-int v2, v3, v2

    .line 122
    .line 123
    or-int/2addr v1, v2

    .line 124
    goto :goto_3

    .line 125
    :cond_5
    iget-object v4, p0, Lm9/f;->b:[B

    .line 126
    .line 127
    iget v5, p0, Lm9/f;->c:I

    .line 128
    .line 129
    aget-byte v4, v4, v5

    .line 130
    .line 131
    and-int/lit16 v4, v4, 0xff

    .line 132
    .line 133
    rsub-int/lit8 v6, v2, 0x8

    .line 134
    .line 135
    shr-int/2addr v4, v6

    .line 136
    or-int/2addr v1, v4

    .line 137
    rsub-int/lit8 p1, p1, 0x20

    .line 138
    .line 139
    const/4 v4, -0x1

    .line 140
    ushr-int p1, v4, p1

    .line 141
    .line 142
    and-int/2addr p1, v1

    .line 143
    if-ne v2, v3, :cond_6

    .line 144
    .line 145
    iput v0, p0, Lm9/f;->d:I

    .line 146
    .line 147
    add-int/lit8 v5, v5, 0x1

    .line 148
    .line 149
    iput v5, p0, Lm9/f;->c:I

    .line 150
    .line 151
    :cond_6
    invoke-virtual {p0}, Lm9/f;->a()V

    .line 152
    .line 153
    .line 154
    move v0, p1

    .line 155
    :goto_4
    return v0

    .line 156
    :pswitch_1
    iget v0, p0, Lm9/f;->d:I

    .line 157
    .line 158
    iget v1, p0, Lm9/f;->e:I

    .line 159
    .line 160
    rsub-int/lit8 v1, v1, 0x8

    .line 161
    .line 162
    invoke-static {p1, v1}, Ljava/lang/Math;->min(II)I

    .line 163
    .line 164
    .line 165
    move-result v1

    .line 166
    iget-object v2, p0, Lm9/f;->b:[B

    .line 167
    .line 168
    add-int/lit8 v3, v0, 0x1

    .line 169
    .line 170
    aget-byte v0, v2, v0

    .line 171
    .line 172
    const/16 v4, 0xff

    .line 173
    .line 174
    and-int/2addr v0, v4

    .line 175
    iget v5, p0, Lm9/f;->e:I

    .line 176
    .line 177
    shr-int/2addr v0, v5

    .line 178
    rsub-int/lit8 v5, v1, 0x8

    .line 179
    .line 180
    shr-int v5, v4, v5

    .line 181
    .line 182
    and-int/2addr v0, v5

    .line 183
    :goto_5
    if-ge v1, p1, :cond_7

    .line 184
    .line 185
    add-int/lit8 v5, v3, 0x1

    .line 186
    .line 187
    aget-byte v3, v2, v3

    .line 188
    .line 189
    and-int/2addr v3, v4

    .line 190
    shl-int/2addr v3, v1

    .line 191
    or-int/2addr v0, v3

    .line 192
    add-int/lit8 v1, v1, 0x8

    .line 193
    .line 194
    move v3, v5

    .line 195
    goto :goto_5

    .line 196
    :cond_7
    rsub-int/lit8 v1, p1, 0x20

    .line 197
    .line 198
    const/4 v2, -0x1

    .line 199
    ushr-int v1, v2, v1

    .line 200
    .line 201
    and-int/2addr v0, v1

    .line 202
    invoke-virtual {p0, p1}, Lm9/f;->t(I)V

    .line 203
    .line 204
    .line 205
    return v0

    .line 206
    nop

    .line 207
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public j(I[B)V
    .locals 9

    .line 1
    shr-int/lit8 v0, p1, 0x3

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    move v2, v1

    .line 5
    :goto_0
    const/16 v3, 0xff

    .line 6
    .line 7
    const/16 v4, 0x8

    .line 8
    .line 9
    if-ge v2, v0, :cond_0

    .line 10
    .line 11
    iget-object v5, p0, Lm9/f;->b:[B

    .line 12
    .line 13
    iget v6, p0, Lm9/f;->c:I

    .line 14
    .line 15
    add-int/lit8 v7, v6, 0x1

    .line 16
    .line 17
    iput v7, p0, Lm9/f;->c:I

    .line 18
    .line 19
    aget-byte v6, v5, v6

    .line 20
    .line 21
    iget v8, p0, Lm9/f;->d:I

    .line 22
    .line 23
    shl-int/2addr v6, v8

    .line 24
    int-to-byte v6, v6

    .line 25
    aput-byte v6, p2, v2

    .line 26
    .line 27
    aget-byte v5, v5, v7

    .line 28
    .line 29
    and-int/2addr v3, v5

    .line 30
    sub-int/2addr v4, v8

    .line 31
    shr-int/2addr v3, v4

    .line 32
    or-int/2addr v3, v6

    .line 33
    int-to-byte v3, v3

    .line 34
    aput-byte v3, p2, v2

    .line 35
    .line 36
    add-int/lit8 v2, v2, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    and-int/lit8 p1, p1, 0x7

    .line 40
    .line 41
    if-nez p1, :cond_1

    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    aget-byte v2, p2, v0

    .line 45
    .line 46
    shr-int v5, v3, p1

    .line 47
    .line 48
    and-int/2addr v2, v5

    .line 49
    int-to-byte v2, v2

    .line 50
    aput-byte v2, p2, v0

    .line 51
    .line 52
    iget v5, p0, Lm9/f;->d:I

    .line 53
    .line 54
    add-int v6, v5, p1

    .line 55
    .line 56
    if-le v6, v4, :cond_2

    .line 57
    .line 58
    iget-object v6, p0, Lm9/f;->b:[B

    .line 59
    .line 60
    iget v7, p0, Lm9/f;->c:I

    .line 61
    .line 62
    add-int/lit8 v8, v7, 0x1

    .line 63
    .line 64
    iput v8, p0, Lm9/f;->c:I

    .line 65
    .line 66
    aget-byte v6, v6, v7

    .line 67
    .line 68
    and-int/2addr v6, v3

    .line 69
    shl-int/2addr v6, v5

    .line 70
    or-int/2addr v2, v6

    .line 71
    int-to-byte v2, v2

    .line 72
    aput-byte v2, p2, v0

    .line 73
    .line 74
    sub-int/2addr v5, v4

    .line 75
    iput v5, p0, Lm9/f;->d:I

    .line 76
    .line 77
    :cond_2
    iget v2, p0, Lm9/f;->d:I

    .line 78
    .line 79
    add-int/2addr v2, p1

    .line 80
    iput v2, p0, Lm9/f;->d:I

    .line 81
    .line 82
    iget-object v5, p0, Lm9/f;->b:[B

    .line 83
    .line 84
    iget v6, p0, Lm9/f;->c:I

    .line 85
    .line 86
    aget-byte v5, v5, v6

    .line 87
    .line 88
    and-int/2addr v3, v5

    .line 89
    rsub-int/lit8 v5, v2, 0x8

    .line 90
    .line 91
    shr-int/2addr v3, v5

    .line 92
    aget-byte v5, p2, v0

    .line 93
    .line 94
    rsub-int/lit8 p1, p1, 0x8

    .line 95
    .line 96
    shl-int p1, v3, p1

    .line 97
    .line 98
    int-to-byte p1, p1

    .line 99
    or-int/2addr p1, v5

    .line 100
    int-to-byte p1, p1

    .line 101
    aput-byte p1, p2, v0

    .line 102
    .line 103
    if-ne v2, v4, :cond_3

    .line 104
    .line 105
    iput v1, p0, Lm9/f;->d:I

    .line 106
    .line 107
    add-int/lit8 v6, v6, 0x1

    .line 108
    .line 109
    iput v6, p0, Lm9/f;->c:I

    .line 110
    .line 111
    :cond_3
    invoke-virtual {p0}, Lm9/f;->a()V

    .line 112
    .line 113
    .line 114
    return-void
.end method

.method public k(I)J
    .locals 5

    .line 1
    const-wide v0, 0xffffffffL

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    const/16 v2, 0x20

    .line 7
    .line 8
    if-gt p1, v2, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Lm9/f;->i(I)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    sget-object p1, Lw7/w;->a:Ljava/lang/String;

    .line 15
    .line 16
    int-to-long p0, p0

    .line 17
    and-long/2addr p0, v0

    .line 18
    return-wide p0

    .line 19
    :cond_0
    sub-int/2addr p1, v2

    .line 20
    invoke-virtual {p0, p1}, Lm9/f;->i(I)I

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    invoke-virtual {p0, v2}, Lm9/f;->i(I)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    .line 29
    .line 30
    int-to-long v3, p1

    .line 31
    and-long/2addr v3, v0

    .line 32
    shl-long v2, v3, v2

    .line 33
    .line 34
    int-to-long p0, p0

    .line 35
    and-long/2addr p0, v0

    .line 36
    or-long/2addr p0, v2

    .line 37
    return-wide p0
.end method

.method public l(I[B)V
    .locals 3

    .line 1
    iget v0, p0, Lm9/f;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move v0, v1

    .line 9
    :goto_0
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, Lm9/f;->b:[B

    .line 13
    .line 14
    iget v2, p0, Lm9/f;->c:I

    .line 15
    .line 16
    invoke-static {v0, v2, p2, v1, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 17
    .line 18
    .line 19
    iget p2, p0, Lm9/f;->c:I

    .line 20
    .line 21
    add-int/2addr p2, p1

    .line 22
    iput p2, p0, Lm9/f;->c:I

    .line 23
    .line 24
    invoke-virtual {p0}, Lm9/f;->a()V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public m()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    invoke-virtual {p0}, Lm9/f;->h()Z

    .line 4
    .line 5
    .line 6
    move-result v2

    .line 7
    if-nez v2, :cond_0

    .line 8
    .line 9
    add-int/lit8 v1, v1, 0x1

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v2, 0x1

    .line 13
    shl-int v3, v2, v1

    .line 14
    .line 15
    sub-int/2addr v3, v2

    .line 16
    if-lez v1, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0, v1}, Lm9/f;->i(I)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    :cond_1
    add-int/2addr v3, v0

    .line 23
    return v3
.end method

.method public n()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lm9/f;->m()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    rem-int/lit8 v0, p0, 0x2

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    const/4 v0, -0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move v0, v1

    .line 13
    :goto_0
    add-int/2addr p0, v1

    .line 14
    div-int/lit8 p0, p0, 0x2

    .line 15
    .line 16
    mul-int/2addr p0, v0

    .line 17
    return p0
.end method

.method public o(I[B)V
    .locals 0

    .line 1
    iput-object p2, p0, Lm9/f;->b:[B

    .line 2
    .line 3
    const/4 p2, 0x0

    .line 4
    iput p2, p0, Lm9/f;->c:I

    .line 5
    .line 6
    iput p2, p0, Lm9/f;->d:I

    .line 7
    .line 8
    iput p1, p0, Lm9/f;->e:I

    .line 9
    .line 10
    return-void
.end method

.method public p(Lw7/p;)V
    .locals 2

    .line 1
    iget-object v0, p1, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p1, Lw7/p;->c:I

    .line 4
    .line 5
    invoke-virtual {p0, v1, v0}, Lm9/f;->o(I[B)V

    .line 6
    .line 7
    .line 8
    iget p1, p1, Lw7/p;->b:I

    .line 9
    .line 10
    mul-int/lit8 p1, p1, 0x8

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Lm9/f;->q(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public q(I)V
    .locals 1

    .line 1
    div-int/lit8 v0, p1, 0x8

    .line 2
    .line 3
    iput v0, p0, Lm9/f;->c:I

    .line 4
    .line 5
    mul-int/lit8 v0, v0, 0x8

    .line 6
    .line 7
    sub-int/2addr p1, v0

    .line 8
    iput p1, p0, Lm9/f;->d:I

    .line 9
    .line 10
    invoke-virtual {p0}, Lm9/f;->a()V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public r(I)Z
    .locals 2

    .line 1
    const/4 v0, 0x2

    .line 2
    if-gt v0, p1, :cond_0

    .line 3
    .line 4
    iget v0, p0, Lm9/f;->c:I

    .line 5
    .line 6
    if-ge p1, v0, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lm9/f;->b:[B

    .line 9
    .line 10
    aget-byte v0, p0, p1

    .line 11
    .line 12
    const/4 v1, 0x3

    .line 13
    if-ne v0, v1, :cond_0

    .line 14
    .line 15
    add-int/lit8 v0, p1, -0x2

    .line 16
    .line 17
    aget-byte v0, p0, v0

    .line 18
    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x1

    .line 22
    sub-int/2addr p1, v0

    .line 23
    aget-byte p0, p0, p1

    .line 24
    .line 25
    if-nez p0, :cond_0

    .line 26
    .line 27
    return v0

    .line 28
    :cond_0
    const/4 p0, 0x0

    .line 29
    return p0
.end method

.method public s()V
    .locals 3

    .line 1
    iget v0, p0, Lm9/f;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lm9/f;->e:I

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    add-int/2addr v0, v1

    .line 10
    iput v0, p0, Lm9/f;->e:I

    .line 11
    .line 12
    const/16 v2, 0x8

    .line 13
    .line 14
    if-ne v0, v2, :cond_1

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    iput v0, p0, Lm9/f;->e:I

    .line 18
    .line 19
    iget v0, p0, Lm9/f;->d:I

    .line 20
    .line 21
    add-int/lit8 v2, v0, 0x1

    .line 22
    .line 23
    invoke-virtual {p0, v2}, Lm9/f;->r(I)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    const/4 v1, 0x2

    .line 30
    :cond_0
    add-int/2addr v0, v1

    .line 31
    iput v0, p0, Lm9/f;->d:I

    .line 32
    .line 33
    :cond_1
    invoke-virtual {p0}, Lm9/f;->a()V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :pswitch_0
    iget v0, p0, Lm9/f;->d:I

    .line 38
    .line 39
    add-int/lit8 v0, v0, 0x1

    .line 40
    .line 41
    iput v0, p0, Lm9/f;->d:I

    .line 42
    .line 43
    const/16 v1, 0x8

    .line 44
    .line 45
    if-ne v0, v1, :cond_2

    .line 46
    .line 47
    const/4 v0, 0x0

    .line 48
    iput v0, p0, Lm9/f;->d:I

    .line 49
    .line 50
    iget v0, p0, Lm9/f;->c:I

    .line 51
    .line 52
    add-int/lit8 v0, v0, 0x1

    .line 53
    .line 54
    iput v0, p0, Lm9/f;->c:I

    .line 55
    .line 56
    :cond_2
    invoke-virtual {p0}, Lm9/f;->a()V

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public t(I)V
    .locals 4

    .line 1
    iget v0, p0, Lm9/f;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lm9/f;->d:I

    .line 7
    .line 8
    div-int/lit8 v1, p1, 0x8

    .line 9
    .line 10
    add-int v2, v0, v1

    .line 11
    .line 12
    iput v2, p0, Lm9/f;->d:I

    .line 13
    .line 14
    iget v3, p0, Lm9/f;->e:I

    .line 15
    .line 16
    mul-int/lit8 v1, v1, 0x8

    .line 17
    .line 18
    sub-int/2addr p1, v1

    .line 19
    add-int/2addr p1, v3

    .line 20
    iput p1, p0, Lm9/f;->e:I

    .line 21
    .line 22
    const/4 v1, 0x7

    .line 23
    if-le p1, v1, :cond_0

    .line 24
    .line 25
    add-int/lit8 v2, v2, 0x1

    .line 26
    .line 27
    iput v2, p0, Lm9/f;->d:I

    .line 28
    .line 29
    add-int/lit8 p1, p1, -0x8

    .line 30
    .line 31
    iput p1, p0, Lm9/f;->e:I

    .line 32
    .line 33
    :cond_0
    :goto_0
    add-int/lit8 v0, v0, 0x1

    .line 34
    .line 35
    iget p1, p0, Lm9/f;->d:I

    .line 36
    .line 37
    if-gt v0, p1, :cond_1

    .line 38
    .line 39
    invoke-virtual {p0, v0}, Lm9/f;->r(I)Z

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    if-eqz p1, :cond_0

    .line 44
    .line 45
    iget p1, p0, Lm9/f;->d:I

    .line 46
    .line 47
    add-int/lit8 p1, p1, 0x1

    .line 48
    .line 49
    iput p1, p0, Lm9/f;->d:I

    .line 50
    .line 51
    add-int/lit8 v0, v0, 0x2

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    invoke-virtual {p0}, Lm9/f;->a()V

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    :pswitch_0
    div-int/lit8 v0, p1, 0x8

    .line 59
    .line 60
    iget v1, p0, Lm9/f;->c:I

    .line 61
    .line 62
    add-int/2addr v1, v0

    .line 63
    iput v1, p0, Lm9/f;->c:I

    .line 64
    .line 65
    iget v2, p0, Lm9/f;->d:I

    .line 66
    .line 67
    mul-int/lit8 v0, v0, 0x8

    .line 68
    .line 69
    sub-int/2addr p1, v0

    .line 70
    add-int/2addr p1, v2

    .line 71
    iput p1, p0, Lm9/f;->d:I

    .line 72
    .line 73
    const/4 v0, 0x7

    .line 74
    if-le p1, v0, :cond_2

    .line 75
    .line 76
    add-int/lit8 v1, v1, 0x1

    .line 77
    .line 78
    iput v1, p0, Lm9/f;->c:I

    .line 79
    .line 80
    add-int/lit8 p1, p1, -0x8

    .line 81
    .line 82
    iput p1, p0, Lm9/f;->d:I

    .line 83
    .line 84
    :cond_2
    invoke-virtual {p0}, Lm9/f;->a()V

    .line 85
    .line 86
    .line 87
    return-void

    .line 88
    :pswitch_1
    div-int/lit8 v0, p1, 0x8

    .line 89
    .line 90
    iget v1, p0, Lm9/f;->d:I

    .line 91
    .line 92
    add-int/2addr v1, v0

    .line 93
    iput v1, p0, Lm9/f;->d:I

    .line 94
    .line 95
    iget v2, p0, Lm9/f;->e:I

    .line 96
    .line 97
    mul-int/lit8 v0, v0, 0x8

    .line 98
    .line 99
    sub-int/2addr p1, v0

    .line 100
    add-int/2addr p1, v2

    .line 101
    iput p1, p0, Lm9/f;->e:I

    .line 102
    .line 103
    const/4 v0, 0x7

    .line 104
    const/4 v2, 0x1

    .line 105
    if-le p1, v0, :cond_3

    .line 106
    .line 107
    add-int/2addr v1, v2

    .line 108
    iput v1, p0, Lm9/f;->d:I

    .line 109
    .line 110
    add-int/lit8 p1, p1, -0x8

    .line 111
    .line 112
    iput p1, p0, Lm9/f;->e:I

    .line 113
    .line 114
    :cond_3
    iget p1, p0, Lm9/f;->d:I

    .line 115
    .line 116
    if-ltz p1, :cond_4

    .line 117
    .line 118
    iget v0, p0, Lm9/f;->c:I

    .line 119
    .line 120
    if-lt p1, v0, :cond_5

    .line 121
    .line 122
    if-ne p1, v0, :cond_4

    .line 123
    .line 124
    iget p0, p0, Lm9/f;->e:I

    .line 125
    .line 126
    if-nez p0, :cond_4

    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_4
    const/4 v2, 0x0

    .line 130
    :cond_5
    :goto_1
    invoke-static {v2}, Lw7/a;->j(Z)V

    .line 131
    .line 132
    .line 133
    return-void

    .line 134
    nop

    .line 135
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public u(I)V
    .locals 1

    .line 1
    iget v0, p0, Lm9/f;->d:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    :goto_0
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 9
    .line 10
    .line 11
    iget v0, p0, Lm9/f;->c:I

    .line 12
    .line 13
    add-int/2addr v0, p1

    .line 14
    iput v0, p0, Lm9/f;->c:I

    .line 15
    .line 16
    invoke-virtual {p0}, Lm9/f;->a()V

    .line 17
    .line 18
    .line 19
    return-void
.end method
