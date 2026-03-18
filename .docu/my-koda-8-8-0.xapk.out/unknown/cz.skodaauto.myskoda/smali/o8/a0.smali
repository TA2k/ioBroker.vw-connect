.class public final Lo8/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public b:I

.field public c:I

.field public d:I

.field public e:I

.field public f:I

.field public g:Ljava/io/Serializable;


# virtual methods
.method public a(I)Z
    .locals 8

    .line 1
    const/high16 v0, -0x200000

    .line 2
    .line 3
    and-int v1, p1, v0

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-ne v1, v0, :cond_10

    .line 7
    .line 8
    ushr-int/lit8 v0, p1, 0x13

    .line 9
    .line 10
    const/4 v1, 0x3

    .line 11
    and-int/2addr v0, v1

    .line 12
    const/4 v3, 0x1

    .line 13
    if-ne v0, v3, :cond_0

    .line 14
    .line 15
    goto/16 :goto_5

    .line 16
    .line 17
    :cond_0
    ushr-int/lit8 v4, p1, 0x11

    .line 18
    .line 19
    and-int/2addr v4, v1

    .line 20
    if-nez v4, :cond_1

    .line 21
    .line 22
    goto/16 :goto_5

    .line 23
    .line 24
    :cond_1
    ushr-int/lit8 v5, p1, 0xc

    .line 25
    .line 26
    const/16 v6, 0xf

    .line 27
    .line 28
    and-int/2addr v5, v6

    .line 29
    if-eqz v5, :cond_10

    .line 30
    .line 31
    if-ne v5, v6, :cond_2

    .line 32
    .line 33
    goto/16 :goto_5

    .line 34
    .line 35
    :cond_2
    ushr-int/lit8 v6, p1, 0xa

    .line 36
    .line 37
    and-int/2addr v6, v1

    .line 38
    if-ne v6, v1, :cond_3

    .line 39
    .line 40
    goto/16 :goto_5

    .line 41
    .line 42
    :cond_3
    iput v0, p0, Lo8/a0;->a:I

    .line 43
    .line 44
    sget-object v2, Lo8/b;->s:[Ljava/lang/String;

    .line 45
    .line 46
    rsub-int/lit8 v7, v4, 0x3

    .line 47
    .line 48
    aget-object v2, v2, v7

    .line 49
    .line 50
    iput-object v2, p0, Lo8/a0;->g:Ljava/io/Serializable;

    .line 51
    .line 52
    sget-object v2, Lo8/b;->t:[I

    .line 53
    .line 54
    aget v2, v2, v6

    .line 55
    .line 56
    iput v2, p0, Lo8/a0;->c:I

    .line 57
    .line 58
    const/4 v6, 0x2

    .line 59
    if-ne v0, v6, :cond_4

    .line 60
    .line 61
    div-int/2addr v2, v6

    .line 62
    iput v2, p0, Lo8/a0;->c:I

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_4
    if-nez v0, :cond_5

    .line 66
    .line 67
    div-int/lit8 v2, v2, 0x4

    .line 68
    .line 69
    iput v2, p0, Lo8/a0;->c:I

    .line 70
    .line 71
    :cond_5
    :goto_0
    ushr-int/lit8 v2, p1, 0x9

    .line 72
    .line 73
    and-int/2addr v2, v3

    .line 74
    const/16 v7, 0x480

    .line 75
    .line 76
    if-eq v4, v3, :cond_7

    .line 77
    .line 78
    if-eq v4, v6, :cond_9

    .line 79
    .line 80
    if-ne v4, v1, :cond_6

    .line 81
    .line 82
    const/16 v7, 0x180

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 86
    .line 87
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 88
    .line 89
    .line 90
    throw p0

    .line 91
    :cond_7
    if-ne v0, v1, :cond_8

    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_8
    const/16 v7, 0x240

    .line 95
    .line 96
    :cond_9
    :goto_1
    iput v7, p0, Lo8/a0;->f:I

    .line 97
    .line 98
    if-ne v4, v1, :cond_b

    .line 99
    .line 100
    if-ne v0, v1, :cond_a

    .line 101
    .line 102
    sget-object v0, Lo8/b;->u:[I

    .line 103
    .line 104
    sub-int/2addr v5, v3

    .line 105
    aget v0, v0, v5

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_a
    sget-object v0, Lo8/b;->v:[I

    .line 109
    .line 110
    sub-int/2addr v5, v3

    .line 111
    aget v0, v0, v5

    .line 112
    .line 113
    :goto_2
    iput v0, p0, Lo8/a0;->e:I

    .line 114
    .line 115
    mul-int/lit8 v0, v0, 0xc

    .line 116
    .line 117
    iget v4, p0, Lo8/a0;->c:I

    .line 118
    .line 119
    div-int/2addr v0, v4

    .line 120
    add-int/2addr v0, v2

    .line 121
    mul-int/lit8 v0, v0, 0x4

    .line 122
    .line 123
    iput v0, p0, Lo8/a0;->b:I

    .line 124
    .line 125
    goto :goto_4

    .line 126
    :cond_b
    const/16 v7, 0x90

    .line 127
    .line 128
    if-ne v0, v1, :cond_d

    .line 129
    .line 130
    if-ne v4, v6, :cond_c

    .line 131
    .line 132
    sget-object v0, Lo8/b;->w:[I

    .line 133
    .line 134
    sub-int/2addr v5, v3

    .line 135
    aget v0, v0, v5

    .line 136
    .line 137
    goto :goto_3

    .line 138
    :cond_c
    sget-object v0, Lo8/b;->x:[I

    .line 139
    .line 140
    sub-int/2addr v5, v3

    .line 141
    aget v0, v0, v5

    .line 142
    .line 143
    :goto_3
    iput v0, p0, Lo8/a0;->e:I

    .line 144
    .line 145
    mul-int/2addr v0, v7

    .line 146
    iget v4, p0, Lo8/a0;->c:I

    .line 147
    .line 148
    div-int/2addr v0, v4

    .line 149
    add-int/2addr v0, v2

    .line 150
    iput v0, p0, Lo8/a0;->b:I

    .line 151
    .line 152
    goto :goto_4

    .line 153
    :cond_d
    sget-object v0, Lo8/b;->y:[I

    .line 154
    .line 155
    sub-int/2addr v5, v3

    .line 156
    aget v0, v0, v5

    .line 157
    .line 158
    iput v0, p0, Lo8/a0;->e:I

    .line 159
    .line 160
    if-ne v4, v3, :cond_e

    .line 161
    .line 162
    const/16 v7, 0x48

    .line 163
    .line 164
    :cond_e
    mul-int/2addr v7, v0

    .line 165
    iget v0, p0, Lo8/a0;->c:I

    .line 166
    .line 167
    div-int/2addr v7, v0

    .line 168
    add-int/2addr v7, v2

    .line 169
    iput v7, p0, Lo8/a0;->b:I

    .line 170
    .line 171
    :goto_4
    shr-int/lit8 p1, p1, 0x6

    .line 172
    .line 173
    and-int/2addr p1, v1

    .line 174
    if-ne p1, v1, :cond_f

    .line 175
    .line 176
    move v6, v3

    .line 177
    :cond_f
    iput v6, p0, Lo8/a0;->d:I

    .line 178
    .line 179
    return v3

    .line 180
    :cond_10
    :goto_5
    return v2
.end method
