.class public abstract Lh2/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lx4/x;->d:Lx4/x;

    .line 2
    .line 3
    sget-object v0, Lx4/i;->a:Ll2/e0;

    .line 4
    .line 5
    sget-object v0, Lx4/x;->d:Lx4/x;

    .line 6
    .line 7
    sget-object v0, Lx4/x;->d:Lx4/x;

    .line 8
    .line 9
    return-void
.end method

.method public static final a(Lt2/b;Lay0/a;Lx2/s;ZLh2/n5;Lk1/z0;Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v6, p6

    .line 2
    .line 3
    check-cast v6, Ll2/t;

    .line 4
    .line 5
    const v0, -0x1fc44f8d

    .line 6
    .line 7
    .line 8
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    move-object/from16 v9, p1

    .line 12
    .line 13
    invoke-virtual {v6, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/16 v0, 0x20

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/16 v0, 0x10

    .line 23
    .line 24
    :goto_0
    or-int v0, p7, v0

    .line 25
    .line 26
    move-object/from16 v10, p2

    .line 27
    .line 28
    invoke-virtual {v6, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    const/16 v1, 0x100

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v1, 0x80

    .line 38
    .line 39
    :goto_1
    or-int/2addr v0, v1

    .line 40
    const v1, 0x6cb6c00

    .line 41
    .line 42
    .line 43
    or-int/2addr v0, v1

    .line 44
    const v1, 0x2492493

    .line 45
    .line 46
    .line 47
    and-int/2addr v1, v0

    .line 48
    const v2, 0x2492492

    .line 49
    .line 50
    .line 51
    const/4 v3, 0x1

    .line 52
    if-eq v1, v2, :cond_2

    .line 53
    .line 54
    move v1, v3

    .line 55
    goto :goto_2

    .line 56
    :cond_2
    const/4 v1, 0x0

    .line 57
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 58
    .line 59
    invoke-virtual {v6, v2, v1}, Ll2/t;->O(IZ)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-eqz v1, :cond_6

    .line 64
    .line 65
    invoke-virtual {v6}, Ll2/t;->T()V

    .line 66
    .line 67
    .line 68
    and-int/lit8 v1, p7, 0x1

    .line 69
    .line 70
    const v2, -0x380001

    .line 71
    .line 72
    .line 73
    if-eqz v1, :cond_4

    .line 74
    .line 75
    invoke-virtual {v6}, Ll2/t;->y()Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-eqz v1, :cond_3

    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_3
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 83
    .line 84
    .line 85
    and-int/2addr v0, v2

    .line 86
    move/from16 v3, p3

    .line 87
    .line 88
    move-object/from16 v4, p4

    .line 89
    .line 90
    move-object/from16 v5, p5

    .line 91
    .line 92
    goto :goto_5

    .line 93
    :cond_4
    :goto_3
    sget v1, Lh2/m5;->a:F

    .line 94
    .line 95
    sget-object v1, Lh2/g1;->a:Ll2/u2;

    .line 96
    .line 97
    invoke-virtual {v6, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    check-cast v1, Lh2/f1;

    .line 102
    .line 103
    iget-object v4, v1, Lh2/f1;->c0:Lh2/n5;

    .line 104
    .line 105
    if-nez v4, :cond_5

    .line 106
    .line 107
    new-instance v11, Lh2/n5;

    .line 108
    .line 109
    sget-object v4, Lk2/u;->g:Lk2/l;

    .line 110
    .line 111
    invoke-static {v1, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 112
    .line 113
    .line 114
    move-result-wide v12

    .line 115
    sget-object v4, Lk2/u;->h:Lk2/l;

    .line 116
    .line 117
    invoke-static {v1, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 118
    .line 119
    .line 120
    move-result-wide v14

    .line 121
    sget-object v4, Lk2/u;->i:Lk2/l;

    .line 122
    .line 123
    invoke-static {v1, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 124
    .line 125
    .line 126
    move-result-wide v16

    .line 127
    sget-object v4, Lk2/u;->a:Lk2/l;

    .line 128
    .line 129
    invoke-static {v1, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 130
    .line 131
    .line 132
    move-result-wide v4

    .line 133
    sget v7, Lk2/u;->b:F

    .line 134
    .line 135
    invoke-static {v4, v5, v7}, Le3/s;->b(JF)J

    .line 136
    .line 137
    .line 138
    move-result-wide v18

    .line 139
    sget-object v4, Lk2/u;->c:Lk2/l;

    .line 140
    .line 141
    invoke-static {v1, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 142
    .line 143
    .line 144
    move-result-wide v4

    .line 145
    sget v7, Lk2/u;->d:F

    .line 146
    .line 147
    invoke-static {v4, v5, v7}, Le3/s;->b(JF)J

    .line 148
    .line 149
    .line 150
    move-result-wide v20

    .line 151
    sget-object v4, Lk2/u;->e:Lk2/l;

    .line 152
    .line 153
    invoke-static {v1, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 154
    .line 155
    .line 156
    move-result-wide v4

    .line 157
    sget v7, Lk2/u;->f:F

    .line 158
    .line 159
    invoke-static {v4, v5, v7}, Le3/s;->b(JF)J

    .line 160
    .line 161
    .line 162
    move-result-wide v22

    .line 163
    invoke-direct/range {v11 .. v23}, Lh2/n5;-><init>(JJJJJJ)V

    .line 164
    .line 165
    .line 166
    iput-object v11, v1, Lh2/f1;->c0:Lh2/n5;

    .line 167
    .line 168
    goto :goto_4

    .line 169
    :cond_5
    move-object v11, v4

    .line 170
    :goto_4
    and-int/2addr v0, v2

    .line 171
    sget-object v1, Lh2/m5;->c:Lk1/a1;

    .line 172
    .line 173
    move-object v5, v1

    .line 174
    move-object v4, v11

    .line 175
    :goto_5
    invoke-virtual {v6}, Ll2/t;->r()V

    .line 176
    .line 177
    .line 178
    const v1, 0xffffffe

    .line 179
    .line 180
    .line 181
    and-int v7, v0, v1

    .line 182
    .line 183
    move-object/from16 v0, p0

    .line 184
    .line 185
    move-object v1, v9

    .line 186
    move-object v2, v10

    .line 187
    invoke-static/range {v0 .. v7}, Lh2/q5;->b(Lt2/b;Lay0/a;Lx2/s;ZLh2/n5;Lk1/z0;Ll2/o;I)V

    .line 188
    .line 189
    .line 190
    move v11, v3

    .line 191
    move-object v12, v4

    .line 192
    move-object v13, v5

    .line 193
    goto :goto_6

    .line 194
    :cond_6
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 195
    .line 196
    .line 197
    move/from16 v11, p3

    .line 198
    .line 199
    move-object/from16 v12, p4

    .line 200
    .line 201
    move-object/from16 v13, p5

    .line 202
    .line 203
    :goto_6
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 204
    .line 205
    .line 206
    move-result-object v0

    .line 207
    if-eqz v0, :cond_7

    .line 208
    .line 209
    new-instance v7, Lh2/l;

    .line 210
    .line 211
    move-object/from16 v8, p0

    .line 212
    .line 213
    move-object/from16 v9, p1

    .line 214
    .line 215
    move-object/from16 v10, p2

    .line 216
    .line 217
    move/from16 v14, p7

    .line 218
    .line 219
    invoke-direct/range {v7 .. v14}, Lh2/l;-><init>(Lt2/b;Lay0/a;Lx2/s;ZLh2/n5;Lk1/z0;I)V

    .line 220
    .line 221
    .line 222
    iput-object v7, v0, Ll2/u1;->d:Lay0/n;

    .line 223
    .line 224
    :cond_7
    return-void
.end method
