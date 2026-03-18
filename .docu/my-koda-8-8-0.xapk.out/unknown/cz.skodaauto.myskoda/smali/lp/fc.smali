.class public abstract Llp/fc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lvv/m0;ILt2/b;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move/from16 v3, p4

    .line 8
    .line 9
    const-string v4, "<this>"

    .line 10
    .line 11
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    move-object/from16 v4, p3

    .line 15
    .line 16
    check-cast v4, Ll2/t;

    .line 17
    .line 18
    const v5, 0x1d2e4017

    .line 19
    .line 20
    .line 21
    invoke-virtual {v4, v5}, Ll2/t;->a0(I)Ll2/t;

    .line 22
    .line 23
    .line 24
    and-int/lit8 v5, v3, 0xe

    .line 25
    .line 26
    if-nez v5, :cond_1

    .line 27
    .line 28
    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-eqz v5, :cond_0

    .line 33
    .line 34
    const/4 v5, 0x4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v5, 0x2

    .line 37
    :goto_0
    or-int/2addr v5, v3

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move v5, v3

    .line 40
    :goto_1
    and-int/lit8 v6, v3, 0x70

    .line 41
    .line 42
    if-nez v6, :cond_3

    .line 43
    .line 44
    invoke-virtual {v4, v1}, Ll2/t;->e(I)Z

    .line 45
    .line 46
    .line 47
    move-result v6

    .line 48
    if-eqz v6, :cond_2

    .line 49
    .line 50
    const/16 v6, 0x20

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v6, 0x10

    .line 54
    .line 55
    :goto_2
    or-int/2addr v5, v6

    .line 56
    :cond_3
    and-int/lit16 v6, v3, 0x380

    .line 57
    .line 58
    if-nez v6, :cond_5

    .line 59
    .line 60
    invoke-virtual {v4, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v6

    .line 64
    if-eqz v6, :cond_4

    .line 65
    .line 66
    const/16 v6, 0x100

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_4
    const/16 v6, 0x80

    .line 70
    .line 71
    :goto_3
    or-int/2addr v5, v6

    .line 72
    :cond_5
    and-int/lit16 v5, v5, 0x2db

    .line 73
    .line 74
    const/16 v6, 0x92

    .line 75
    .line 76
    if-ne v5, v6, :cond_7

    .line 77
    .line 78
    invoke-virtual {v4}, Ll2/t;->A()Z

    .line 79
    .line 80
    .line 81
    move-result v5

    .line 82
    if-nez v5, :cond_6

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_6
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 86
    .line 87
    .line 88
    goto :goto_6

    .line 89
    :cond_7
    :goto_4
    if-ltz v1, :cond_a

    .line 90
    .line 91
    const v5, -0x3d6c6215

    .line 92
    .line 93
    .line 94
    invoke-virtual {v4, v5}, Ll2/t;->Z(I)V

    .line 95
    .line 96
    .line 97
    invoke-static {v0, v4}, Lvv/l0;->e(Lvv/m0;Ll2/o;)Lg4/p0;

    .line 98
    .line 99
    .line 100
    move-result-object v6

    .line 101
    invoke-virtual {v6}, Lg4/p0;->b()J

    .line 102
    .line 103
    .line 104
    move-result-wide v7

    .line 105
    sget-wide v9, Le3/s;->i:J

    .line 106
    .line 107
    cmp-long v5, v7, v9

    .line 108
    .line 109
    if-eqz v5, :cond_8

    .line 110
    .line 111
    goto :goto_5

    .line 112
    :cond_8
    invoke-static {v0, v4}, Lvv/l0;->d(Lvv/m0;Ll2/o;)J

    .line 113
    .line 114
    .line 115
    move-result-wide v7

    .line 116
    new-instance v5, Le3/s;

    .line 117
    .line 118
    :goto_5
    const/16 v19, 0x0

    .line 119
    .line 120
    const v20, 0xfffffe

    .line 121
    .line 122
    .line 123
    const-wide/16 v9, 0x0

    .line 124
    .line 125
    const/4 v11, 0x0

    .line 126
    const/4 v12, 0x0

    .line 127
    const-wide/16 v13, 0x0

    .line 128
    .line 129
    const/4 v15, 0x0

    .line 130
    const-wide/16 v16, 0x0

    .line 131
    .line 132
    const/16 v18, 0x0

    .line 133
    .line 134
    invoke-static/range {v6 .. v20}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 135
    .line 136
    .line 137
    move-result-object v5

    .line 138
    const/4 v6, 0x0

    .line 139
    invoke-virtual {v4, v6}, Ll2/t;->q(Z)V

    .line 140
    .line 141
    .line 142
    sget-object v6, Lw3/h1;->n:Ll2/u2;

    .line 143
    .line 144
    invoke-virtual {v4, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v6

    .line 148
    check-cast v6, Lt4/m;

    .line 149
    .line 150
    invoke-static {v5, v6}, Lg4/f0;->h(Lg4/p0;Lt4/m;)Lg4/p0;

    .line 151
    .line 152
    .line 153
    move-result-object v5

    .line 154
    invoke-static {v0, v4}, Lvv/o0;->b(Lvv/m0;Ll2/o;)Lvv/n0;

    .line 155
    .line 156
    .line 157
    move-result-object v6

    .line 158
    invoke-static {v6}, Lvv/o0;->c(Lvv/n0;)Lvv/n0;

    .line 159
    .line 160
    .line 161
    move-result-object v6

    .line 162
    iget-object v6, v6, Lvv/n0;->b:Lay0/n;

    .line 163
    .line 164
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 168
    .line 169
    .line 170
    move-result-object v7

    .line 171
    invoke-interface {v6, v7, v5}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v6

    .line 175
    check-cast v6, Lg4/p0;

    .line 176
    .line 177
    invoke-virtual {v5, v6}, Lg4/p0;->d(Lg4/p0;)Lg4/p0;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    invoke-static {v0, v4}, Lvv/q0;->a(Lvv/m0;Ll2/o;)Lay0/p;

    .line 182
    .line 183
    .line 184
    move-result-object v6

    .line 185
    new-instance v7, Lvv/h;

    .line 186
    .line 187
    const/4 v8, 0x1

    .line 188
    invoke-direct {v7, v2, v0, v8}, Lvv/h;-><init>(Lt2/b;Lvv/m0;I)V

    .line 189
    .line 190
    .line 191
    const v8, 0x11328dfd

    .line 192
    .line 193
    .line 194
    invoke-static {v8, v4, v7}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 195
    .line 196
    .line 197
    move-result-object v7

    .line 198
    const/16 v8, 0x30

    .line 199
    .line 200
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 201
    .line 202
    .line 203
    move-result-object v8

    .line 204
    invoke-interface {v6, v5, v7, v4, v8}, Lay0/p;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    :goto_6
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 208
    .line 209
    .line 210
    move-result-object v4

    .line 211
    if-eqz v4, :cond_9

    .line 212
    .line 213
    new-instance v5, Lf7/r;

    .line 214
    .line 215
    invoke-direct {v5, v1, v3, v2, v0}, Lf7/r;-><init>(IILt2/b;Lvv/m0;)V

    .line 216
    .line 217
    .line 218
    iput-object v5, v4, Ll2/u1;->d:Lay0/n;

    .line 219
    .line 220
    :cond_9
    return-void

    .line 221
    :cond_a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 222
    .line 223
    const-string v1, "Level must be at least 0"

    .line 224
    .line 225
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    throw v0
.end method

.method public static b(I)I
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x2

    .line 3
    const/4 v2, 0x3

    .line 4
    filled-new-array {v0, v1, v2}, [I

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    const/4 v3, 0x0

    .line 9
    :goto_0
    if-ge v3, v2, :cond_2

    .line 10
    .line 11
    aget v4, v1, v3

    .line 12
    .line 13
    add-int/lit8 v5, v4, -0x1

    .line 14
    .line 15
    if-eqz v4, :cond_1

    .line 16
    .line 17
    if-ne v5, p0, :cond_0

    .line 18
    .line 19
    return v4

    .line 20
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    const/4 p0, 0x0

    .line 24
    throw p0

    .line 25
    :cond_2
    return v0
.end method
