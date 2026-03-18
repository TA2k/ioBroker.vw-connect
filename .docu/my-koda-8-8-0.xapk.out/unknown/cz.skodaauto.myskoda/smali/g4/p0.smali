.class public final Lg4/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lg4/p0;


# instance fields
.field public final a:Lg4/g0;

.field public final b:Lg4/t;

.field public final c:Lg4/y;


# direct methods
.method static constructor <clinit>()V
    .locals 14

    .line 1
    new-instance v0, Lg4/p0;

    .line 2
    .line 3
    const-wide/16 v11, 0x0

    .line 4
    .line 5
    const v13, 0xffffff

    .line 6
    .line 7
    .line 8
    const-wide/16 v1, 0x0

    .line 9
    .line 10
    const-wide/16 v3, 0x0

    .line 11
    .line 12
    const/4 v5, 0x0

    .line 13
    const/4 v6, 0x0

    .line 14
    const/4 v7, 0x0

    .line 15
    const-wide/16 v8, 0x0

    .line 16
    .line 17
    const/4 v10, 0x0

    .line 18
    invoke-direct/range {v0 .. v13}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 19
    .line 20
    .line 21
    sput-object v0, Lg4/p0;->d:Lg4/p0;

    .line 22
    .line 23
    return-void
.end method

.method public constructor <init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V
    .locals 25

    move/from16 v0, p13

    and-int/lit8 v1, v0, 0x1

    if-eqz v1, :cond_0

    .line 9
    sget-wide v1, Le3/s;->i:J

    move-wide v4, v1

    goto :goto_0

    :cond_0
    move-wide/from16 v4, p1

    :goto_0
    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_1

    .line 10
    sget-wide v1, Lt4/o;->c:J

    move-wide v6, v1

    goto :goto_1

    :cond_1
    move-wide/from16 v6, p3

    :goto_1
    and-int/lit8 v1, v0, 0x4

    const/16 v22, 0x0

    if-eqz v1, :cond_2

    move-object/from16 v8, v22

    goto :goto_2

    :cond_2
    move-object/from16 v8, p5

    :goto_2
    and-int/lit8 v1, v0, 0x8

    if-eqz v1, :cond_3

    move-object/from16 v9, v22

    goto :goto_3

    :cond_3
    move-object/from16 v9, p6

    :goto_3
    and-int/lit8 v1, v0, 0x20

    if-eqz v1, :cond_4

    move-object/from16 v11, v22

    goto :goto_4

    :cond_4
    move-object/from16 v11, p7

    :goto_4
    and-int/lit16 v1, v0, 0x80

    if-eqz v1, :cond_5

    .line 11
    sget-wide v1, Lt4/o;->c:J

    move-wide v13, v1

    goto :goto_5

    :cond_5
    move-wide/from16 v13, p8

    .line 12
    :goto_5
    sget-wide v18, Le3/s;->i:J

    and-int/lit16 v1, v0, 0x1000

    if-eqz v1, :cond_6

    move-object/from16 v20, v22

    goto :goto_6

    .line 13
    :cond_6
    sget-object v1, Lr4/l;->c:Lr4/l;

    move-object/from16 v20, v1

    :goto_6
    const v1, 0x8000

    and-int/2addr v1, v0

    if-eqz v1, :cond_7

    const/high16 v1, -0x80000000

    goto :goto_7

    :cond_7
    move/from16 v1, p10

    :goto_7
    const/high16 v2, 0x20000

    and-int/2addr v0, v2

    if-eqz v0, :cond_8

    .line 14
    sget-wide v2, Lt4/o;->c:J

    move-wide/from16 v23, v2

    goto :goto_8

    :cond_8
    move-wide/from16 v23, p11

    .line 15
    :goto_8
    new-instance v3, Lg4/g0;

    const/4 v10, 0x0

    const/4 v12, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v21, 0x0

    invoke-direct/range {v3 .. v22}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;Lg4/x;)V

    .line 16
    new-instance v0, Lg4/t;

    const/high16 v2, -0x80000000

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/high16 v7, -0x80000000

    const/4 v8, 0x0

    move-object/from16 p1, v0

    move/from16 p2, v1

    move/from16 p3, v2

    move-object/from16 p6, v4

    move-object/from16 p8, v5

    move/from16 p9, v6

    move/from16 p10, v7

    move-object/from16 p11, v8

    move-object/from16 p7, v22

    move-wide/from16 p4, v23

    invoke-direct/range {p1 .. p11}, Lg4/t;-><init>(IIJLr4/q;Lg4/w;Lr4/i;IILr4/s;)V

    const/4 v1, 0x0

    move-object/from16 v2, p0

    .line 17
    invoke-direct {v2, v3, v0, v1}, Lg4/p0;-><init>(Lg4/g0;Lg4/t;Lg4/y;)V

    return-void
.end method

.method public constructor <init>(Lg4/g0;Lg4/t;)V
    .locals 3

    .line 5
    iget-object v0, p1, Lg4/g0;->o:Lg4/x;

    .line 6
    iget-object v1, p2, Lg4/t;->e:Lg4/w;

    if-nez v0, :cond_0

    if-nez v1, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    .line 7
    :cond_0
    new-instance v2, Lg4/y;

    invoke-direct {v2, v0, v1}, Lg4/y;-><init>(Lg4/x;Lg4/w;)V

    move-object v0, v2

    .line 8
    :goto_0
    invoke-direct {p0, p1, p2, v0}, Lg4/p0;-><init>(Lg4/g0;Lg4/t;Lg4/y;)V

    return-void
.end method

.method public constructor <init>(Lg4/g0;Lg4/t;Lg4/y;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lg4/p0;->a:Lg4/g0;

    .line 3
    iput-object p2, p0, Lg4/p0;->b:Lg4/t;

    .line 4
    iput-object p3, p0, Lg4/p0;->c:Lg4/y;

    return-void
.end method

.method public static a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p14

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    iget-object v2, v0, Lg4/p0;->a:Lg4/g0;

    .line 10
    .line 11
    iget-object v2, v2, Lg4/g0;->a:Lr4/o;

    .line 12
    .line 13
    invoke-interface {v2}, Lr4/o;->a()J

    .line 14
    .line 15
    .line 16
    move-result-wide v2

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move-wide/from16 v2, p1

    .line 19
    .line 20
    :goto_0
    and-int/lit8 v4, v1, 0x2

    .line 21
    .line 22
    if-eqz v4, :cond_1

    .line 23
    .line 24
    iget-object v4, v0, Lg4/p0;->a:Lg4/g0;

    .line 25
    .line 26
    iget-wide v4, v4, Lg4/g0;->b:J

    .line 27
    .line 28
    move-wide v8, v4

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move-wide/from16 v8, p3

    .line 31
    .line 32
    :goto_1
    and-int/lit8 v4, v1, 0x4

    .line 33
    .line 34
    if-eqz v4, :cond_2

    .line 35
    .line 36
    iget-object v4, v0, Lg4/p0;->a:Lg4/g0;

    .line 37
    .line 38
    iget-object v4, v4, Lg4/g0;->c:Lk4/x;

    .line 39
    .line 40
    move-object v10, v4

    .line 41
    goto :goto_2

    .line 42
    :cond_2
    move-object/from16 v10, p5

    .line 43
    .line 44
    :goto_2
    iget-object v4, v0, Lg4/p0;->a:Lg4/g0;

    .line 45
    .line 46
    iget-object v11, v4, Lg4/g0;->d:Lk4/t;

    .line 47
    .line 48
    iget-object v12, v4, Lg4/g0;->e:Lk4/u;

    .line 49
    .line 50
    and-int/lit8 v5, v1, 0x20

    .line 51
    .line 52
    if-eqz v5, :cond_3

    .line 53
    .line 54
    iget-object v5, v4, Lg4/g0;->f:Lk4/n;

    .line 55
    .line 56
    move-object v13, v5

    .line 57
    goto :goto_3

    .line 58
    :cond_3
    move-object/from16 v13, p6

    .line 59
    .line 60
    :goto_3
    iget-object v14, v4, Lg4/g0;->g:Ljava/lang/String;

    .line 61
    .line 62
    and-int/lit16 v5, v1, 0x80

    .line 63
    .line 64
    if-eqz v5, :cond_4

    .line 65
    .line 66
    iget-wide v5, v4, Lg4/g0;->h:J

    .line 67
    .line 68
    move-wide v15, v5

    .line 69
    goto :goto_4

    .line 70
    :cond_4
    move-wide/from16 v15, p7

    .line 71
    .line 72
    :goto_4
    iget-object v5, v4, Lg4/g0;->i:Lr4/a;

    .line 73
    .line 74
    iget-object v6, v4, Lg4/g0;->j:Lr4/p;

    .line 75
    .line 76
    iget-object v7, v4, Lg4/g0;->k:Ln4/b;

    .line 77
    .line 78
    move-object/from16 v17, v5

    .line 79
    .line 80
    move-object/from16 v18, v6

    .line 81
    .line 82
    iget-wide v5, v4, Lg4/g0;->l:J

    .line 83
    .line 84
    move-wide/from16 v20, v5

    .line 85
    .line 86
    and-int/lit16 v5, v1, 0x1000

    .line 87
    .line 88
    if-eqz v5, :cond_5

    .line 89
    .line 90
    iget-object v5, v4, Lg4/g0;->m:Lr4/l;

    .line 91
    .line 92
    :goto_5
    move-object/from16 v22, v5

    .line 93
    .line 94
    goto :goto_6

    .line 95
    :cond_5
    sget-object v5, Lr4/l;->c:Lr4/l;

    .line 96
    .line 97
    goto :goto_5

    .line 98
    :goto_6
    iget-object v5, v4, Lg4/g0;->n:Le3/m0;

    .line 99
    .line 100
    iget-object v6, v4, Lg4/g0;->p:Lg3/e;

    .line 101
    .line 102
    const v19, 0x8000

    .line 103
    .line 104
    .line 105
    and-int v19, v1, v19

    .line 106
    .line 107
    if-eqz v19, :cond_6

    .line 108
    .line 109
    iget-object v1, v0, Lg4/p0;->b:Lg4/t;

    .line 110
    .line 111
    iget v1, v1, Lg4/t;->a:I

    .line 112
    .line 113
    move/from16 p1, v1

    .line 114
    .line 115
    goto :goto_7

    .line 116
    :cond_6
    move/from16 p1, p9

    .line 117
    .line 118
    :goto_7
    iget-object v1, v0, Lg4/p0;->b:Lg4/t;

    .line 119
    .line 120
    move-object/from16 v23, v5

    .line 121
    .line 122
    iget v5, v1, Lg4/t;->b:I

    .line 123
    .line 124
    const/high16 v19, 0x20000

    .line 125
    .line 126
    and-int v19, p14, v19

    .line 127
    .line 128
    move/from16 p2, v5

    .line 129
    .line 130
    move-object/from16 v25, v6

    .line 131
    .line 132
    if-eqz v19, :cond_7

    .line 133
    .line 134
    iget-wide v5, v1, Lg4/t;->c:J

    .line 135
    .line 136
    move-wide/from16 v26, v5

    .line 137
    .line 138
    goto :goto_8

    .line 139
    :cond_7
    move-wide/from16 v26, p10

    .line 140
    .line 141
    :goto_8
    iget-object v5, v1, Lg4/t;->d:Lr4/q;

    .line 142
    .line 143
    const/high16 v6, 0x80000

    .line 144
    .line 145
    and-int v6, p14, v6

    .line 146
    .line 147
    if-eqz v6, :cond_8

    .line 148
    .line 149
    iget-object v0, v0, Lg4/p0;->c:Lg4/y;

    .line 150
    .line 151
    goto :goto_9

    .line 152
    :cond_8
    move-object/from16 v0, p12

    .line 153
    .line 154
    :goto_9
    const/high16 v6, 0x100000

    .line 155
    .line 156
    and-int v6, p14, v6

    .line 157
    .line 158
    if-eqz v6, :cond_9

    .line 159
    .line 160
    iget-object v6, v1, Lg4/t;->f:Lr4/i;

    .line 161
    .line 162
    move-object/from16 v28, v6

    .line 163
    .line 164
    goto :goto_a

    .line 165
    :cond_9
    move-object/from16 v28, p13

    .line 166
    .line 167
    :goto_a
    iget v6, v1, Lg4/t;->g:I

    .line 168
    .line 169
    move-object/from16 p5, v5

    .line 170
    .line 171
    iget v5, v1, Lg4/t;->h:I

    .line 172
    .line 173
    iget-object v1, v1, Lg4/t;->i:Lr4/s;

    .line 174
    .line 175
    move-object/from16 p10, v1

    .line 176
    .line 177
    new-instance v1, Lg4/p0;

    .line 178
    .line 179
    move/from16 v19, v6

    .line 180
    .line 181
    new-instance v6, Lg4/g0;

    .line 182
    .line 183
    move/from16 p9, v5

    .line 184
    .line 185
    iget-object v5, v4, Lg4/g0;->a:Lr4/o;

    .line 186
    .line 187
    move-object/from16 p0, v6

    .line 188
    .line 189
    invoke-interface {v5}, Lr4/o;->a()J

    .line 190
    .line 191
    .line 192
    move-result-wide v5

    .line 193
    invoke-static {v2, v3, v5, v6}, Le3/s;->c(JJ)Z

    .line 194
    .line 195
    .line 196
    move-result v5

    .line 197
    if-eqz v5, :cond_a

    .line 198
    .line 199
    iget-object v2, v4, Lg4/g0;->a:Lr4/o;

    .line 200
    .line 201
    goto :goto_b

    .line 202
    :cond_a
    const-wide/16 v4, 0x10

    .line 203
    .line 204
    cmp-long v4, v2, v4

    .line 205
    .line 206
    if-eqz v4, :cond_b

    .line 207
    .line 208
    new-instance v4, Lr4/c;

    .line 209
    .line 210
    invoke-direct {v4, v2, v3}, Lr4/c;-><init>(J)V

    .line 211
    .line 212
    .line 213
    move-object v2, v4

    .line 214
    goto :goto_b

    .line 215
    :cond_b
    sget-object v2, Lr4/n;->a:Lr4/n;

    .line 216
    .line 217
    :goto_b
    const/4 v3, 0x0

    .line 218
    if-eqz v0, :cond_c

    .line 219
    .line 220
    iget-object v4, v0, Lg4/y;->a:Lg4/x;

    .line 221
    .line 222
    move-object/from16 v24, v4

    .line 223
    .line 224
    :goto_c
    move-object v6, v7

    .line 225
    move-object v7, v2

    .line 226
    move/from16 v2, v19

    .line 227
    .line 228
    move-object/from16 v19, v6

    .line 229
    .line 230
    move-object/from16 v6, p0

    .line 231
    .line 232
    goto :goto_d

    .line 233
    :cond_c
    move-object/from16 v24, v3

    .line 234
    .line 235
    goto :goto_c

    .line 236
    :goto_d
    invoke-direct/range {v6 .. v25}, Lg4/g0;-><init>(Lr4/o;JLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;Lg4/x;Lg3/e;)V

    .line 237
    .line 238
    .line 239
    new-instance v4, Lg4/t;

    .line 240
    .line 241
    if-eqz v0, :cond_d

    .line 242
    .line 243
    iget-object v3, v0, Lg4/y;->b:Lg4/w;

    .line 244
    .line 245
    :cond_d
    move/from16 p8, v2

    .line 246
    .line 247
    move-object/from16 p6, v3

    .line 248
    .line 249
    move-object/from16 p0, v4

    .line 250
    .line 251
    move-wide/from16 p3, v26

    .line 252
    .line 253
    move-object/from16 p7, v28

    .line 254
    .line 255
    invoke-direct/range {p0 .. p10}, Lg4/t;-><init>(IIJLr4/q;Lg4/w;Lr4/i;IILr4/s;)V

    .line 256
    .line 257
    .line 258
    move-object/from16 v2, p0

    .line 259
    .line 260
    invoke-direct {v1, v6, v2, v0}, Lg4/p0;-><init>(Lg4/g0;Lg4/t;Lg4/y;)V

    .line 261
    .line 262
    .line 263
    return-object v1
.end method

.method public static e(Lg4/p0;JJLk4/x;Lk4/t;JLr4/l;IJI)Lg4/p0;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p13

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    sget-wide v2, Le3/s;->i:J

    .line 10
    .line 11
    move-wide v5, v2

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-wide/from16 v5, p1

    .line 14
    .line 15
    :goto_0
    and-int/lit8 v2, v1, 0x2

    .line 16
    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    sget-wide v2, Lt4/o;->c:J

    .line 20
    .line 21
    move-wide v9, v2

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move-wide/from16 v9, p3

    .line 24
    .line 25
    :goto_1
    and-int/lit8 v2, v1, 0x4

    .line 26
    .line 27
    const/16 v25, 0x0

    .line 28
    .line 29
    if-eqz v2, :cond_2

    .line 30
    .line 31
    move-object/from16 v11, v25

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_2
    move-object/from16 v11, p5

    .line 35
    .line 36
    :goto_2
    and-int/lit8 v2, v1, 0x8

    .line 37
    .line 38
    if-eqz v2, :cond_3

    .line 39
    .line 40
    move-object/from16 v12, v25

    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_3
    move-object/from16 v12, p6

    .line 44
    .line 45
    :goto_3
    and-int/lit16 v2, v1, 0x80

    .line 46
    .line 47
    if-eqz v2, :cond_4

    .line 48
    .line 49
    sget-wide v2, Lt4/o;->c:J

    .line 50
    .line 51
    move-wide/from16 v16, v2

    .line 52
    .line 53
    goto :goto_4

    .line 54
    :cond_4
    move-wide/from16 v16, p7

    .line 55
    .line 56
    :goto_4
    sget-wide v21, Le3/s;->i:J

    .line 57
    .line 58
    and-int/lit16 v2, v1, 0x1000

    .line 59
    .line 60
    if-eqz v2, :cond_5

    .line 61
    .line 62
    move-object/from16 v23, v25

    .line 63
    .line 64
    goto :goto_5

    .line 65
    :cond_5
    move-object/from16 v23, p9

    .line 66
    .line 67
    :goto_5
    const v2, 0x8000

    .line 68
    .line 69
    .line 70
    and-int/2addr v2, v1

    .line 71
    if-eqz v2, :cond_6

    .line 72
    .line 73
    const/high16 v2, -0x80000000

    .line 74
    .line 75
    goto :goto_6

    .line 76
    :cond_6
    move/from16 v2, p10

    .line 77
    .line 78
    :goto_6
    const/high16 v3, 0x20000

    .line 79
    .line 80
    and-int/2addr v1, v3

    .line 81
    if-eqz v1, :cond_7

    .line 82
    .line 83
    sget-wide v3, Lt4/o;->c:J

    .line 84
    .line 85
    move-wide/from16 v27, v3

    .line 86
    .line 87
    goto :goto_7

    .line 88
    :cond_7
    move-wide/from16 v27, p11

    .line 89
    .line 90
    :goto_7
    iget-object v4, v0, Lg4/p0;->a:Lg4/g0;

    .line 91
    .line 92
    const/4 v7, 0x0

    .line 93
    const/high16 v8, 0x7fc00000    # Float.NaN

    .line 94
    .line 95
    const/4 v13, 0x0

    .line 96
    const/4 v14, 0x0

    .line 97
    const/4 v15, 0x0

    .line 98
    const/16 v18, 0x0

    .line 99
    .line 100
    const/16 v19, 0x0

    .line 101
    .line 102
    const/16 v20, 0x0

    .line 103
    .line 104
    const/16 v24, 0x0

    .line 105
    .line 106
    const/16 v26, 0x0

    .line 107
    .line 108
    invoke-static/range {v4 .. v26}, Lg4/h0;->a(Lg4/g0;JLe3/p;FJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;Lg4/x;Lg3/e;)Lg4/g0;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    iget-object v3, v0, Lg4/p0;->b:Lg4/t;

    .line 113
    .line 114
    const/high16 v4, -0x80000000

    .line 115
    .line 116
    const/4 v5, 0x0

    .line 117
    const/4 v6, 0x0

    .line 118
    const/4 v7, 0x0

    .line 119
    const/high16 v8, -0x80000000

    .line 120
    .line 121
    const/4 v9, 0x0

    .line 122
    move/from16 p2, v2

    .line 123
    .line 124
    move-object/from16 p1, v3

    .line 125
    .line 126
    move/from16 p3, v4

    .line 127
    .line 128
    move-object/from16 p6, v5

    .line 129
    .line 130
    move-object/from16 p8, v6

    .line 131
    .line 132
    move/from16 p9, v7

    .line 133
    .line 134
    move/from16 p10, v8

    .line 135
    .line 136
    move-object/from16 p11, v9

    .line 137
    .line 138
    move-object/from16 p7, v25

    .line 139
    .line 140
    move-wide/from16 p4, v27

    .line 141
    .line 142
    invoke-static/range {p1 .. p11}, Lg4/u;->a(Lg4/t;IIJLr4/q;Lg4/w;Lr4/i;IILr4/s;)Lg4/t;

    .line 143
    .line 144
    .line 145
    move-result-object v2

    .line 146
    iget-object v3, v0, Lg4/p0;->a:Lg4/g0;

    .line 147
    .line 148
    if-ne v3, v1, :cond_8

    .line 149
    .line 150
    iget-object v3, v0, Lg4/p0;->b:Lg4/t;

    .line 151
    .line 152
    if-ne v3, v2, :cond_8

    .line 153
    .line 154
    return-object v0

    .line 155
    :cond_8
    new-instance v0, Lg4/p0;

    .line 156
    .line 157
    invoke-direct {v0, v1, v2}, Lg4/p0;-><init>(Lg4/g0;Lg4/t;)V

    .line 158
    .line 159
    .line 160
    return-object v0
.end method


# virtual methods
.method public final b()J
    .locals 2

    .line 1
    iget-object p0, p0, Lg4/p0;->a:Lg4/g0;

    .line 2
    .line 3
    iget-object p0, p0, Lg4/g0;->a:Lr4/o;

    .line 4
    .line 5
    invoke-interface {p0}, Lr4/o;->a()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method

.method public final c(Lg4/p0;)Z
    .locals 2

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    iget-object v0, p0, Lg4/p0;->b:Lg4/t;

    .line 4
    .line 5
    iget-object v1, p1, Lg4/p0;->b:Lg4/t;

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, Lg4/p0;->a:Lg4/g0;

    .line 14
    .line 15
    iget-object p1, p1, Lg4/p0;->a:Lg4/g0;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lg4/g0;->b(Lg4/g0;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    return p0

    .line 26
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 27
    return p0
.end method

.method public final d(Lg4/p0;)Lg4/p0;
    .locals 3

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    sget-object v0, Lg4/p0;->d:Lg4/p0;

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Lg4/p0;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    new-instance v0, Lg4/p0;

    .line 13
    .line 14
    iget-object v1, p0, Lg4/p0;->a:Lg4/g0;

    .line 15
    .line 16
    iget-object v2, p1, Lg4/p0;->a:Lg4/g0;

    .line 17
    .line 18
    invoke-virtual {v1, v2}, Lg4/g0;->d(Lg4/g0;)Lg4/g0;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    iget-object p0, p0, Lg4/p0;->b:Lg4/t;

    .line 23
    .line 24
    iget-object p1, p1, Lg4/p0;->b:Lg4/t;

    .line 25
    .line 26
    invoke-virtual {p0, p1}, Lg4/t;->a(Lg4/t;)Lg4/t;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-direct {v0, v1, p0}, Lg4/p0;-><init>(Lg4/g0;Lg4/t;)V

    .line 31
    .line 32
    .line 33
    return-object v0

    .line 34
    :cond_1
    :goto_0
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lg4/p0;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lg4/p0;

    .line 12
    .line 13
    iget-object v1, p1, Lg4/p0;->a:Lg4/g0;

    .line 14
    .line 15
    iget-object v3, p0, Lg4/p0;->a:Lg4/g0;

    .line 16
    .line 17
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lg4/p0;->b:Lg4/t;

    .line 25
    .line 26
    iget-object v3, p1, Lg4/p0;->b:Lg4/t;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object p0, p0, Lg4/p0;->c:Lg4/y;

    .line 36
    .line 37
    iget-object p1, p1, Lg4/p0;->c:Lg4/y;

    .line 38
    .line 39
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    if-nez p0, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    return v0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lg4/p0;->a:Lg4/g0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lg4/g0;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lg4/p0;->b:Lg4/t;

    .line 10
    .line 11
    invoke-virtual {v1}, Lg4/t;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-object p0, p0, Lg4/p0;->c:Lg4/y;

    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    invoke-virtual {p0}, Lg4/y;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p0, 0x0

    .line 28
    :goto_0
    add-int/2addr v1, p0

    .line 29
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "TextStyle(color="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lg4/p0;->b()J

    .line 9
    .line 10
    .line 11
    move-result-wide v1

    .line 12
    invoke-static {v1, v2}, Le3/s;->i(J)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v1, ", brush="

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    iget-object v1, p0, Lg4/p0;->a:Lg4/g0;

    .line 25
    .line 26
    iget-object v2, v1, Lg4/g0;->a:Lr4/o;

    .line 27
    .line 28
    invoke-interface {v2}, Lr4/o;->c()Le3/p;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v2, ", alpha="

    .line 36
    .line 37
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    iget-object v2, v1, Lg4/g0;->a:Lr4/o;

    .line 41
    .line 42
    invoke-interface {v2}, Lr4/o;->b()F

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string v2, ", fontSize="

    .line 50
    .line 51
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    iget-wide v2, v1, Lg4/g0;->b:J

    .line 55
    .line 56
    invoke-static {v2, v3}, Lt4/o;->d(J)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v2, ", fontWeight="

    .line 64
    .line 65
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v2, v1, Lg4/g0;->c:Lk4/x;

    .line 69
    .line 70
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v2, ", fontStyle="

    .line 74
    .line 75
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v2, v1, Lg4/g0;->d:Lk4/t;

    .line 79
    .line 80
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v2, ", fontSynthesis="

    .line 84
    .line 85
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object v2, v1, Lg4/g0;->e:Lk4/u;

    .line 89
    .line 90
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v2, ", fontFamily="

    .line 94
    .line 95
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v2, v1, Lg4/g0;->f:Lk4/n;

    .line 99
    .line 100
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v2, ", fontFeatureSettings="

    .line 104
    .line 105
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-object v2, v1, Lg4/g0;->g:Ljava/lang/String;

    .line 109
    .line 110
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v2, ", letterSpacing="

    .line 114
    .line 115
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    iget-wide v2, v1, Lg4/g0;->h:J

    .line 119
    .line 120
    invoke-static {v2, v3}, Lt4/o;->d(J)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    const-string v2, ", baselineShift="

    .line 128
    .line 129
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    iget-object v2, v1, Lg4/g0;->i:Lr4/a;

    .line 133
    .line 134
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    const-string v2, ", textGeometricTransform="

    .line 138
    .line 139
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    iget-object v2, v1, Lg4/g0;->j:Lr4/p;

    .line 143
    .line 144
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    const-string v2, ", localeList="

    .line 148
    .line 149
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    iget-object v2, v1, Lg4/g0;->k:Ln4/b;

    .line 153
    .line 154
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    const-string v2, ", background="

    .line 158
    .line 159
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    iget-wide v2, v1, Lg4/g0;->l:J

    .line 163
    .line 164
    const-string v4, ", textDecoration="

    .line 165
    .line 166
    invoke-static {v2, v3, v4, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->x(JLjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 167
    .line 168
    .line 169
    iget-object v2, v1, Lg4/g0;->m:Lr4/l;

    .line 170
    .line 171
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 172
    .line 173
    .line 174
    const-string v2, ", shadow="

    .line 175
    .line 176
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 177
    .line 178
    .line 179
    iget-object v2, v1, Lg4/g0;->n:Le3/m0;

    .line 180
    .line 181
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    const-string v2, ", drawStyle="

    .line 185
    .line 186
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    iget-object v1, v1, Lg4/g0;->p:Lg3/e;

    .line 190
    .line 191
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 192
    .line 193
    .line 194
    const-string v1, ", textAlign="

    .line 195
    .line 196
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    iget-object v1, p0, Lg4/p0;->b:Lg4/t;

    .line 200
    .line 201
    iget v2, v1, Lg4/t;->a:I

    .line 202
    .line 203
    invoke-static {v2}, Lr4/k;->a(I)Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v2

    .line 207
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 208
    .line 209
    .line 210
    const-string v2, ", textDirection="

    .line 211
    .line 212
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 213
    .line 214
    .line 215
    iget v2, v1, Lg4/t;->b:I

    .line 216
    .line 217
    invoke-static {v2}, Lr4/m;->a(I)Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object v2

    .line 221
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 222
    .line 223
    .line 224
    const-string v2, ", lineHeight="

    .line 225
    .line 226
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 227
    .line 228
    .line 229
    iget-wide v2, v1, Lg4/t;->c:J

    .line 230
    .line 231
    invoke-static {v2, v3}, Lt4/o;->d(J)Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object v2

    .line 235
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 236
    .line 237
    .line 238
    const-string v2, ", textIndent="

    .line 239
    .line 240
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 241
    .line 242
    .line 243
    iget-object v2, v1, Lg4/t;->d:Lr4/q;

    .line 244
    .line 245
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 246
    .line 247
    .line 248
    const-string v2, ", platformStyle="

    .line 249
    .line 250
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 251
    .line 252
    .line 253
    iget-object p0, p0, Lg4/p0;->c:Lg4/y;

    .line 254
    .line 255
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 256
    .line 257
    .line 258
    const-string p0, ", lineHeightStyle="

    .line 259
    .line 260
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 261
    .line 262
    .line 263
    iget-object p0, v1, Lg4/t;->f:Lr4/i;

    .line 264
    .line 265
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 266
    .line 267
    .line 268
    const-string p0, ", lineBreak="

    .line 269
    .line 270
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 271
    .line 272
    .line 273
    iget p0, v1, Lg4/t;->g:I

    .line 274
    .line 275
    invoke-static {p0}, Lr4/e;->a(I)Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object p0

    .line 279
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 280
    .line 281
    .line 282
    const-string p0, ", hyphens="

    .line 283
    .line 284
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 285
    .line 286
    .line 287
    iget p0, v1, Lg4/t;->h:I

    .line 288
    .line 289
    invoke-static {p0}, Lr4/d;->a(I)Ljava/lang/String;

    .line 290
    .line 291
    .line 292
    move-result-object p0

    .line 293
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 294
    .line 295
    .line 296
    const-string p0, ", textMotion="

    .line 297
    .line 298
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 299
    .line 300
    .line 301
    iget-object p0, v1, Lg4/t;->i:Lr4/s;

    .line 302
    .line 303
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 304
    .line 305
    .line 306
    const/16 p0, 0x29

    .line 307
    .line 308
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 309
    .line 310
    .line 311
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object p0

    .line 315
    return-object p0
.end method
