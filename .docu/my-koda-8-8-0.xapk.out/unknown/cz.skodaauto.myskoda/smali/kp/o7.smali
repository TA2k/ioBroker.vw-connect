.class public abstract Lkp/o7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ly6/q;ILt2/b;Ll2/o;II)V
    .locals 8

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, -0x60766059

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p4

    .line 19
    or-int/lit8 v1, v0, 0x30

    .line 20
    .line 21
    and-int/lit8 v2, p5, 0x4

    .line 22
    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    or-int/lit16 v0, v0, 0x1b0

    .line 26
    .line 27
    goto :goto_2

    .line 28
    :cond_1
    invoke-virtual {p3, p1}, Ll2/t;->e(I)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_2

    .line 33
    .line 34
    const/16 v0, 0x100

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_2
    const/16 v0, 0x80

    .line 38
    .line 39
    :goto_1
    or-int/2addr v0, v1

    .line 40
    :goto_2
    and-int/lit16 v0, v0, 0x493

    .line 41
    .line 42
    const/16 v1, 0x492

    .line 43
    .line 44
    if-ne v0, v1, :cond_4

    .line 45
    .line 46
    invoke-virtual {p3}, Ll2/t;->A()Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-nez v0, :cond_3

    .line 51
    .line 52
    goto :goto_4

    .line 53
    :cond_3
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 54
    .line 55
    .line 56
    :goto_3
    move v4, p1

    .line 57
    goto :goto_6

    .line 58
    :cond_4
    :goto_4
    const/4 v0, 0x0

    .line 59
    if-eqz v2, :cond_5

    .line 60
    .line 61
    move p1, v0

    .line 62
    :cond_5
    sget-object v1, Lf7/q;->d:Lf7/q;

    .line 63
    .line 64
    const v2, 0x227c4e56

    .line 65
    .line 66
    .line 67
    invoke-virtual {p3, v2}, Ll2/t;->Z(I)V

    .line 68
    .line 69
    .line 70
    const v2, -0x20ad3f64

    .line 71
    .line 72
    .line 73
    invoke-virtual {p3, v2}, Ll2/t;->Z(I)V

    .line 74
    .line 75
    .line 76
    iget-object v2, p3, Ll2/t;->a:Leb/j0;

    .line 77
    .line 78
    instance-of v2, v2, Ly6/b;

    .line 79
    .line 80
    if-eqz v2, :cond_8

    .line 81
    .line 82
    invoke-virtual {p3}, Ll2/t;->W()V

    .line 83
    .line 84
    .line 85
    iget-boolean v2, p3, Ll2/t;->S:Z

    .line 86
    .line 87
    if-eqz v2, :cond_6

    .line 88
    .line 89
    invoke-virtual {p3, v1}, Ll2/t;->l(Lay0/a;)V

    .line 90
    .line 91
    .line 92
    goto :goto_5

    .line 93
    :cond_6
    invoke-virtual {p3}, Ll2/t;->m0()V

    .line 94
    .line 95
    .line 96
    :goto_5
    sget-object v1, Lf7/e;->l:Lf7/e;

    .line 97
    .line 98
    invoke-static {v1, p0, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 99
    .line 100
    .line 101
    new-instance v1, Lf7/b;

    .line 102
    .line 103
    invoke-direct {v1, p1}, Lf7/b;-><init>(I)V

    .line 104
    .line 105
    .line 106
    sget-object v2, Lf7/e;->m:Lf7/e;

    .line 107
    .line 108
    invoke-static {v2, v1, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 109
    .line 110
    .line 111
    new-instance v1, Lf7/a;

    .line 112
    .line 113
    invoke-direct {v1, v0}, Lf7/a;-><init>(I)V

    .line 114
    .line 115
    .line 116
    sget-object v2, Lf7/e;->n:Lf7/e;

    .line 117
    .line 118
    invoke-static {v2, v1, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 119
    .line 120
    .line 121
    const/16 v1, 0x36

    .line 122
    .line 123
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    sget-object v2, Lf7/s;->a:Lf7/s;

    .line 128
    .line 129
    invoke-virtual {p2, v2, p3, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    const/4 v1, 0x1

    .line 133
    invoke-virtual {p3, v1}, Ll2/t;->q(Z)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 140
    .line 141
    .line 142
    goto :goto_3

    .line 143
    :goto_6
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    if-eqz p1, :cond_7

    .line 148
    .line 149
    new-instance v2, Lf7/r;

    .line 150
    .line 151
    move-object v3, p0

    .line 152
    move-object v5, p2

    .line 153
    move v6, p4

    .line 154
    move v7, p5

    .line 155
    invoke-direct/range {v2 .. v7}, Lf7/r;-><init>(Ly6/q;ILt2/b;II)V

    .line 156
    .line 157
    .line 158
    iput-object v2, p1, Ll2/u1;->d:Lay0/n;

    .line 159
    .line 160
    :cond_7
    return-void

    .line 161
    :cond_8
    invoke-static {}, Ll2/b;->l()V

    .line 162
    .line 163
    .line 164
    const/4 p0, 0x0

    .line 165
    throw p0
.end method

.method public static b(Ljava/nio/MappedByteBuffer;)Lt6/b;
    .locals 13

    .line 1
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->duplicate()Ljava/nio/ByteBuffer;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object v0, Ljava/nio/ByteOrder;->BIG_ENDIAN:Ljava/nio/ByteOrder;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/nio/Buffer;->position()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    add-int/lit8 v0, v0, 0x4

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->getShort()S

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    const v1, 0xffff

    .line 24
    .line 25
    .line 26
    and-int/2addr v0, v1

    .line 27
    const/16 v1, 0x64

    .line 28
    .line 29
    const-string v2, "Cannot read metadata."

    .line 30
    .line 31
    if-gt v0, v1, :cond_5

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/nio/Buffer;->position()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    add-int/lit8 v1, v1, 0x6

    .line 38
    .line 39
    invoke-virtual {p0, v1}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 40
    .line 41
    .line 42
    const/4 v1, 0x0

    .line 43
    move v3, v1

    .line 44
    :goto_0
    const-wide v4, 0xffffffffL

    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    const-wide/16 v6, -0x1

    .line 50
    .line 51
    if-ge v3, v0, :cond_1

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->getInt()I

    .line 54
    .line 55
    .line 56
    move-result v8

    .line 57
    invoke-virtual {p0}, Ljava/nio/Buffer;->position()I

    .line 58
    .line 59
    .line 60
    move-result v9

    .line 61
    add-int/lit8 v9, v9, 0x4

    .line 62
    .line 63
    invoke-virtual {p0, v9}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->getInt()I

    .line 67
    .line 68
    .line 69
    move-result v9

    .line 70
    int-to-long v9, v9

    .line 71
    and-long/2addr v9, v4

    .line 72
    invoke-virtual {p0}, Ljava/nio/Buffer;->position()I

    .line 73
    .line 74
    .line 75
    move-result v11

    .line 76
    add-int/lit8 v11, v11, 0x4

    .line 77
    .line 78
    invoke-virtual {p0, v11}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 79
    .line 80
    .line 81
    const v11, 0x6d657461

    .line 82
    .line 83
    .line 84
    if-ne v11, v8, :cond_0

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_1
    move-wide v9, v6

    .line 91
    :goto_1
    cmp-long v0, v9, v6

    .line 92
    .line 93
    if-eqz v0, :cond_4

    .line 94
    .line 95
    invoke-virtual {p0}, Ljava/nio/Buffer;->position()I

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    int-to-long v6, v0

    .line 100
    sub-long v6, v9, v6

    .line 101
    .line 102
    long-to-int v0, v6

    .line 103
    invoke-virtual {p0}, Ljava/nio/Buffer;->position()I

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    add-int/2addr v3, v0

    .line 108
    invoke-virtual {p0, v3}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 109
    .line 110
    .line 111
    invoke-virtual {p0}, Ljava/nio/Buffer;->position()I

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    add-int/lit8 v0, v0, 0xc

    .line 116
    .line 117
    invoke-virtual {p0, v0}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 118
    .line 119
    .line 120
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->getInt()I

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    int-to-long v6, v0

    .line 125
    and-long/2addr v6, v4

    .line 126
    :goto_2
    int-to-long v11, v1

    .line 127
    cmp-long v0, v11, v6

    .line 128
    .line 129
    if-gez v0, :cond_4

    .line 130
    .line 131
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->getInt()I

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->getInt()I

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    int-to-long v11, v3

    .line 140
    and-long/2addr v11, v4

    .line 141
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->getInt()I

    .line 142
    .line 143
    .line 144
    const v3, 0x456d6a69

    .line 145
    .line 146
    .line 147
    if-eq v3, v0, :cond_3

    .line 148
    .line 149
    const v3, 0x656d6a69

    .line 150
    .line 151
    .line 152
    if-ne v3, v0, :cond_2

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 156
    .line 157
    goto :goto_2

    .line 158
    :cond_3
    :goto_3
    add-long/2addr v11, v9

    .line 159
    long-to-int v0, v11

    .line 160
    invoke-virtual {p0, v0}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 161
    .line 162
    .line 163
    new-instance v0, Lt6/b;

    .line 164
    .line 165
    invoke-direct {v0}, Ld6/h0;-><init>()V

    .line 166
    .line 167
    .line 168
    sget-object v1, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 169
    .line 170
    invoke-virtual {p0, v1}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 171
    .line 172
    .line 173
    invoke-virtual {p0}, Ljava/nio/Buffer;->position()I

    .line 174
    .line 175
    .line 176
    move-result v1

    .line 177
    invoke-virtual {p0, v1}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    invoke-virtual {p0}, Ljava/nio/Buffer;->position()I

    .line 182
    .line 183
    .line 184
    move-result v2

    .line 185
    add-int/2addr v2, v1

    .line 186
    iput-object p0, v0, Ld6/h0;->g:Ljava/lang/Object;

    .line 187
    .line 188
    iput v2, v0, Ld6/h0;->d:I

    .line 189
    .line 190
    invoke-virtual {p0, v2}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 191
    .line 192
    .line 193
    move-result p0

    .line 194
    sub-int/2addr v2, p0

    .line 195
    iput v2, v0, Ld6/h0;->e:I

    .line 196
    .line 197
    iget-object p0, v0, Ld6/h0;->g:Ljava/lang/Object;

    .line 198
    .line 199
    check-cast p0, Ljava/nio/ByteBuffer;

    .line 200
    .line 201
    invoke-virtual {p0, v2}, Ljava/nio/ByteBuffer;->getShort(I)S

    .line 202
    .line 203
    .line 204
    move-result p0

    .line 205
    iput p0, v0, Ld6/h0;->f:I

    .line 206
    .line 207
    return-object v0

    .line 208
    :cond_4
    new-instance p0, Ljava/io/IOException;

    .line 209
    .line 210
    invoke-direct {p0, v2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    throw p0

    .line 214
    :cond_5
    new-instance p0, Ljava/io/IOException;

    .line 215
    .line 216
    invoke-direct {p0, v2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    throw p0
.end method
