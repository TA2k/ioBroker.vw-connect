.class public final Lb81/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/e;
.implements Li4/b;
.implements Lju/b;
.implements Lk0/c;
.implements Ll9/j;
.implements Luz0/m1;
.implements Lo8/i;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 9

    iput p1, p0, Lb81/a;->d:I

    sparse-switch p1, :sswitch_data_0

    .line 24
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 25
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 26
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    return-void

    .line 27
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    new-instance p1, Lw7/p;

    invoke-direct {p1}, Lw7/p;-><init>()V

    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 29
    new-instance p1, Lu9/a;

    invoke-direct {p1}, Lu9/a;-><init>()V

    iput-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    return-void

    .line 30
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 31
    sget-object v1, Lc1/d;->j:Lc1/b2;

    const/4 p1, 0x0

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    .line 32
    new-instance v0, Lc1/k;

    .line 33
    iget-object p1, v1, Lc1/b2;->a:Lay0/k;

    .line 34
    invoke-interface {p1, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    move-object v3, p1

    check-cast v3, Lc1/p;

    const-wide/high16 v4, -0x8000000000000000L

    const-wide/high16 v6, -0x8000000000000000L

    const/4 v8, 0x0

    .line 35
    invoke-direct/range {v0 .. v8}, Lc1/k;-><init>(Lc1/b2;Ljava/lang/Object;Lc1/p;JJZ)V

    .line 36
    iput-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    return-void

    .line 37
    :sswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 38
    new-instance p1, Landroid/util/SparseIntArray;

    invoke-direct {p1}, Landroid/util/SparseIntArray;-><init>()V

    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 39
    new-instance p1, Landroid/util/SparseIntArray;

    invoke-direct {p1}, Landroid/util/SparseIntArray;-><init>()V

    iput-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0xd -> :sswitch_2
        0x14 -> :sswitch_1
        0x19 -> :sswitch_0
    .end sparse-switch
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lb81/a;->d:I

    iput-object p2, p0, Lb81/a;->e:Ljava/lang/Object;

    iput-object p3, p0, Lb81/a;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 2
    iput p1, p0, Lb81/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    const/16 v0, 0x17

    iput v0, p0, Lb81/a;->d:I

    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 22
    iput-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 23
    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lay0/k;)V
    .locals 1

    const/16 v0, 0x1a

    iput v0, p0, Lb81/a;->d:I

    .line 40
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 41
    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    iput-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lfb/k;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Lb81/a;->d:I

    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 20
    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lgt/b;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Lb81/a;->d:I

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    invoke-static {v0}, Ljava/util/Collections;->synchronizedMap(Ljava/util/Map;)Ljava/util/Map;

    move-result-object v0

    iput-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 15
    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lhr/x0;[I)V
    .locals 1

    const/16 v0, 0x1d

    iput v0, p0, Lb81/a;->d:I

    .line 42
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 43
    invoke-static {p1}, Lhr/h0;->p(Ljava/util/Collection;)Lhr/h0;

    move-result-object p1

    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 44
    iput-object p2, p0, Lb81/a;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lil/g;)V
    .locals 1

    const/16 v0, 0x15

    iput v0, p0, Lb81/a;->d:I

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 3
    iput p2, p0, Lb81/a;->d:I

    iput-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V
    .locals 0

    .line 4
    iput p4, p0, Lb81/a;->d:I

    iput-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    iput-object p2, p0, Lb81/a;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ll71/w;Ll71/z;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lb81/a;->d:I

    const-string v0, "dependencies"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "trajectoryConfig"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 12
    iput-object p2, p0, Lb81/a;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lw7/u;)V
    .locals 1

    const/16 v0, 0x1b

    iput v0, p0, Lb81/a;->d:I

    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 18
    new-instance p1, Lw7/p;

    invoke-direct {p1}, Lw7/p;-><init>()V

    iput-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>([Ljava/lang/String;)V
    .locals 1

    const/16 v0, 0x12

    iput v0, p0, Lb81/a;->d:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    new-instance p1, Ljava/util/ArrayList;

    .line 6
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    new-instance p0, Ljava/util/HashMap;

    .line 7
    invoke-direct {p0}, Ljava/util/HashMap;-><init>()V

    return-void
.end method

.method public static o(II)I
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    move v2, v1

    .line 4
    move v3, v2

    .line 5
    :goto_0
    const/4 v4, 0x1

    .line 6
    if-ge v1, p0, :cond_2

    .line 7
    .line 8
    add-int/lit8 v2, v2, 0x1

    .line 9
    .line 10
    if-ne v2, p1, :cond_0

    .line 11
    .line 12
    add-int/lit8 v3, v3, 0x1

    .line 13
    .line 14
    move v2, v0

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    if-le v2, p1, :cond_1

    .line 17
    .line 18
    add-int/lit8 v3, v3, 0x1

    .line 19
    .line 20
    move v2, v4

    .line 21
    :cond_1
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_2
    add-int/2addr v2, v4

    .line 25
    if-le v2, p1, :cond_3

    .line 26
    .line 27
    add-int/2addr v3, v4

    .line 28
    :cond_3
    return v3
.end method


# virtual methods
.method public a(Lo8/p;J)Lo8/h;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-interface/range {p1 .. p1}, Lo8/p;->getPosition()J

    .line 4
    .line 5
    .line 6
    move-result-wide v4

    .line 7
    invoke-interface/range {p1 .. p1}, Lo8/p;->getLength()J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    sub-long/2addr v1, v4

    .line 12
    const-wide/16 v6, 0x4e20

    .line 13
    .line 14
    invoke-static {v6, v7, v1, v2}, Ljava/lang/Math;->min(JJ)J

    .line 15
    .line 16
    .line 17
    move-result-wide v1

    .line 18
    long-to-int v1, v1

    .line 19
    iget-object v2, v0, Lb81/a;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v2, Lw7/p;

    .line 22
    .line 23
    invoke-virtual {v2, v1}, Lw7/p;->F(I)V

    .line 24
    .line 25
    .line 26
    iget-object v3, v2, Lw7/p;->a:[B

    .line 27
    .line 28
    const/4 v6, 0x0

    .line 29
    move-object/from16 v7, p1

    .line 30
    .line 31
    invoke-interface {v7, v3, v6, v1}, Lo8/p;->o([BII)V

    .line 32
    .line 33
    .line 34
    const/4 v1, -0x1

    .line 35
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 36
    .line 37
    .line 38
    .line 39
    .line 40
    move v3, v1

    .line 41
    move-wide v10, v6

    .line 42
    :goto_0
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 43
    .line 44
    .line 45
    move-result v8

    .line 46
    const/4 v9, 0x4

    .line 47
    if-lt v8, v9, :cond_e

    .line 48
    .line 49
    iget-object v8, v2, Lw7/p;->a:[B

    .line 50
    .line 51
    iget v12, v2, Lw7/p;->b:I

    .line 52
    .line 53
    invoke-static {v12, v8}, Lt8/b;->G(I[B)I

    .line 54
    .line 55
    .line 56
    move-result v8

    .line 57
    const/4 v12, 0x1

    .line 58
    const/16 v13, 0x1ba

    .line 59
    .line 60
    if-eq v8, v13, :cond_0

    .line 61
    .line 62
    invoke-virtual {v2, v12}, Lw7/p;->J(I)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    invoke-virtual {v2, v9}, Lw7/p;->J(I)V

    .line 67
    .line 68
    .line 69
    invoke-static {v2}, Lv9/x;->c(Lw7/p;)J

    .line 70
    .line 71
    .line 72
    move-result-wide v14

    .line 73
    cmp-long v1, v14, v6

    .line 74
    .line 75
    if-eqz v1, :cond_4

    .line 76
    .line 77
    iget-object v1, v0, Lb81/a;->e:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v1, Lw7/u;

    .line 80
    .line 81
    invoke-virtual {v1, v14, v15}, Lw7/u;->b(J)J

    .line 82
    .line 83
    .line 84
    move-result-wide v14

    .line 85
    cmp-long v1, v14, p2

    .line 86
    .line 87
    if-lez v1, :cond_2

    .line 88
    .line 89
    cmp-long v0, v10, v6

    .line 90
    .line 91
    if-nez v0, :cond_1

    .line 92
    .line 93
    new-instance v0, Lo8/h;

    .line 94
    .line 95
    const/4 v1, -0x1

    .line 96
    move-wide v2, v14

    .line 97
    invoke-direct/range {v0 .. v5}, Lo8/h;-><init>(IJJ)V

    .line 98
    .line 99
    .line 100
    return-object v0

    .line 101
    :cond_1
    int-to-long v0, v3

    .line 102
    add-long v10, v4, v0

    .line 103
    .line 104
    new-instance v6, Lo8/h;

    .line 105
    .line 106
    const/4 v7, 0x0

    .line 107
    const-wide v8, -0x7fffffffffffffffL    # -4.9E-324

    .line 108
    .line 109
    .line 110
    .line 111
    .line 112
    invoke-direct/range {v6 .. v11}, Lo8/h;-><init>(IJJ)V

    .line 113
    .line 114
    .line 115
    return-object v6

    .line 116
    :cond_2
    move-wide v10, v14

    .line 117
    const-wide/32 v14, 0x186a0

    .line 118
    .line 119
    .line 120
    add-long/2addr v14, v10

    .line 121
    cmp-long v1, v14, p2

    .line 122
    .line 123
    if-lez v1, :cond_3

    .line 124
    .line 125
    iget v0, v2, Lw7/p;->b:I

    .line 126
    .line 127
    int-to-long v0, v0

    .line 128
    add-long v10, v4, v0

    .line 129
    .line 130
    new-instance v6, Lo8/h;

    .line 131
    .line 132
    const/4 v7, 0x0

    .line 133
    const-wide v8, -0x7fffffffffffffffL    # -4.9E-324

    .line 134
    .line 135
    .line 136
    .line 137
    .line 138
    invoke-direct/range {v6 .. v11}, Lo8/h;-><init>(IJJ)V

    .line 139
    .line 140
    .line 141
    return-object v6

    .line 142
    :cond_3
    iget v1, v2, Lw7/p;->b:I

    .line 143
    .line 144
    move v3, v1

    .line 145
    :cond_4
    iget v1, v2, Lw7/p;->c:I

    .line 146
    .line 147
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 148
    .line 149
    .line 150
    move-result v8

    .line 151
    const/16 v14, 0xa

    .line 152
    .line 153
    if-ge v8, v14, :cond_5

    .line 154
    .line 155
    invoke-virtual {v2, v1}, Lw7/p;->I(I)V

    .line 156
    .line 157
    .line 158
    goto/16 :goto_2

    .line 159
    .line 160
    :cond_5
    const/16 v8, 0x9

    .line 161
    .line 162
    invoke-virtual {v2, v8}, Lw7/p;->J(I)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 166
    .line 167
    .line 168
    move-result v8

    .line 169
    and-int/lit8 v8, v8, 0x7

    .line 170
    .line 171
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 172
    .line 173
    .line 174
    move-result v14

    .line 175
    if-ge v14, v8, :cond_6

    .line 176
    .line 177
    invoke-virtual {v2, v1}, Lw7/p;->I(I)V

    .line 178
    .line 179
    .line 180
    goto :goto_2

    .line 181
    :cond_6
    invoke-virtual {v2, v8}, Lw7/p;->J(I)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 185
    .line 186
    .line 187
    move-result v8

    .line 188
    if-ge v8, v9, :cond_7

    .line 189
    .line 190
    invoke-virtual {v2, v1}, Lw7/p;->I(I)V

    .line 191
    .line 192
    .line 193
    goto :goto_2

    .line 194
    :cond_7
    iget-object v8, v2, Lw7/p;->a:[B

    .line 195
    .line 196
    iget v14, v2, Lw7/p;->b:I

    .line 197
    .line 198
    invoke-static {v14, v8}, Lt8/b;->G(I[B)I

    .line 199
    .line 200
    .line 201
    move-result v8

    .line 202
    const/16 v14, 0x1bb

    .line 203
    .line 204
    if-ne v8, v14, :cond_9

    .line 205
    .line 206
    invoke-virtual {v2, v9}, Lw7/p;->J(I)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v2}, Lw7/p;->C()I

    .line 210
    .line 211
    .line 212
    move-result v8

    .line 213
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 214
    .line 215
    .line 216
    move-result v14

    .line 217
    if-ge v14, v8, :cond_8

    .line 218
    .line 219
    invoke-virtual {v2, v1}, Lw7/p;->I(I)V

    .line 220
    .line 221
    .line 222
    goto :goto_2

    .line 223
    :cond_8
    invoke-virtual {v2, v8}, Lw7/p;->J(I)V

    .line 224
    .line 225
    .line 226
    :cond_9
    :goto_1
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 227
    .line 228
    .line 229
    move-result v8

    .line 230
    if-lt v8, v9, :cond_d

    .line 231
    .line 232
    iget-object v8, v2, Lw7/p;->a:[B

    .line 233
    .line 234
    iget v14, v2, Lw7/p;->b:I

    .line 235
    .line 236
    invoke-static {v14, v8}, Lt8/b;->G(I[B)I

    .line 237
    .line 238
    .line 239
    move-result v8

    .line 240
    if-eq v8, v13, :cond_d

    .line 241
    .line 242
    const/16 v14, 0x1b9

    .line 243
    .line 244
    if-ne v8, v14, :cond_a

    .line 245
    .line 246
    goto :goto_2

    .line 247
    :cond_a
    ushr-int/lit8 v8, v8, 0x8

    .line 248
    .line 249
    if-eq v8, v12, :cond_b

    .line 250
    .line 251
    goto :goto_2

    .line 252
    :cond_b
    invoke-virtual {v2, v9}, Lw7/p;->J(I)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 256
    .line 257
    .line 258
    move-result v8

    .line 259
    const/4 v14, 0x2

    .line 260
    if-ge v8, v14, :cond_c

    .line 261
    .line 262
    invoke-virtual {v2, v1}, Lw7/p;->I(I)V

    .line 263
    .line 264
    .line 265
    goto :goto_2

    .line 266
    :cond_c
    invoke-virtual {v2}, Lw7/p;->C()I

    .line 267
    .line 268
    .line 269
    move-result v8

    .line 270
    iget v14, v2, Lw7/p;->c:I

    .line 271
    .line 272
    iget v15, v2, Lw7/p;->b:I

    .line 273
    .line 274
    add-int/2addr v15, v8

    .line 275
    invoke-static {v14, v15}, Ljava/lang/Math;->min(II)I

    .line 276
    .line 277
    .line 278
    move-result v8

    .line 279
    invoke-virtual {v2, v8}, Lw7/p;->I(I)V

    .line 280
    .line 281
    .line 282
    goto :goto_1

    .line 283
    :cond_d
    :goto_2
    iget v1, v2, Lw7/p;->b:I

    .line 284
    .line 285
    goto/16 :goto_0

    .line 286
    .line 287
    :cond_e
    cmp-long v0, v10, v6

    .line 288
    .line 289
    if-eqz v0, :cond_f

    .line 290
    .line 291
    int-to-long v0, v1

    .line 292
    add-long v12, v4, v0

    .line 293
    .line 294
    new-instance v8, Lo8/h;

    .line 295
    .line 296
    const/4 v9, -0x2

    .line 297
    invoke-direct/range {v8 .. v13}, Lo8/h;-><init>(IJJ)V

    .line 298
    .line 299
    .line 300
    return-object v8

    .line 301
    :cond_f
    sget-object v0, Lo8/h;->d:Lo8/h;

    .line 302
    .line 303
    return-object v0
.end method

.method public c(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lb81/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lb0/i;

    .line 7
    .line 8
    iget p1, p1, Lb0/i;->a:I

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    if-eq p1, v0, :cond_0

    .line 12
    .line 13
    const/4 p1, 0x1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 p1, 0x0

    .line 16
    :goto_0
    const-string v0, "Unexpected result from SurfaceRequest. Surface was provided twice."

    .line 17
    .line 18
    invoke-static {v0, p1}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 19
    .line 20
    .line 21
    const-string p1, "TextureViewImpl"

    .line 22
    .line 23
    const-string v0, "SurfaceTexture about to manually be destroyed"

    .line 24
    .line 25
    invoke-static {p1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p1, Landroid/graphics/SurfaceTexture;

    .line 31
    .line 32
    invoke-virtual {p1}, Landroid/graphics/SurfaceTexture;->release()V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Lw0/q;

    .line 38
    .line 39
    iget-object p0, p0, Lw0/q;->d:Lw0/r;

    .line 40
    .line 41
    iget-object p1, p0, Lw0/r;->j:Landroid/graphics/SurfaceTexture;

    .line 42
    .line 43
    if-eqz p1, :cond_1

    .line 44
    .line 45
    const/4 p1, 0x0

    .line 46
    iput-object p1, p0, Lw0/r;->j:Landroid/graphics/SurfaceTexture;

    .line 47
    .line 48
    :cond_1
    return-void

    .line 49
    :pswitch_0
    check-cast p1, Ljava/lang/Void;

    .line 50
    .line 51
    iget-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast p1, Lu/y;

    .line 54
    .line 55
    iget-object p1, p1, Lu/y;->v:Lz/a;

    .line 56
    .line 57
    invoke-virtual {p1}, Lz/a;->b()I

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    const/4 v0, 0x2

    .line 62
    if-ne p1, v0, :cond_2

    .line 63
    .line 64
    iget-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast p1, Lu/y;

    .line 67
    .line 68
    iget p1, p1, Lu/y;->O:I

    .line 69
    .line 70
    const/16 v0, 0xa

    .line 71
    .line 72
    if-ne p1, v0, :cond_2

    .line 73
    .line 74
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p0, Lu/y;

    .line 77
    .line 78
    const/16 p1, 0xb

    .line 79
    .line 80
    invoke-virtual {p0, p1}, Lu/y;->G(I)V

    .line 81
    .line 82
    .line 83
    :cond_2
    return-void

    .line 84
    nop

    .line 85
    :pswitch_data_0
    .packed-switch 0x18
        :pswitch_0
    .end packed-switch
.end method

.method public d(I)I
    .locals 9

    .line 1
    iget-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Landroid/text/TextPaint;

    .line 5
    .line 6
    iget-object v0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, v0

    .line 9
    check-cast v2, Ljava/lang/CharSequence;

    .line 10
    .line 11
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    const/4 v5, 0x0

    .line 16
    const/4 v7, 0x0

    .line 17
    const/4 v3, 0x0

    .line 18
    move v6, p1

    .line 19
    invoke-virtual/range {v1 .. v7}, Landroid/graphics/Paint;->getTextRunCursor(Ljava/lang/CharSequence;IIZII)I

    .line 20
    .line 21
    .line 22
    move-result v7

    .line 23
    const/4 p1, -0x1

    .line 24
    if-ne v7, p1, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Landroid/text/TextPaint;

    .line 30
    .line 31
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    const/4 v6, 0x0

    .line 36
    const/4 v8, 0x0

    .line 37
    const/4 v4, 0x0

    .line 38
    move-object v3, v2

    .line 39
    move-object v2, p0

    .line 40
    invoke-virtual/range {v2 .. v8}, Landroid/graphics/Paint;->getTextRunCursor(Ljava/lang/CharSequence;IIZII)I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-ne p0, p1, :cond_1

    .line 45
    .line 46
    :goto_0
    return p1

    .line 47
    :cond_1
    return v7
.end method

.method public e(I)I
    .locals 8

    .line 1
    iget-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Landroid/text/TextPaint;

    .line 5
    .line 6
    iget-object p0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, p0

    .line 9
    check-cast v2, Ljava/lang/CharSequence;

    .line 10
    .line 11
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    const/4 v5, 0x0

    .line 16
    const/4 v7, 0x2

    .line 17
    const/4 v3, 0x0

    .line 18
    move v6, p1

    .line 19
    invoke-virtual/range {v1 .. v7}, Landroid/graphics/Paint;->getTextRunCursor(Ljava/lang/CharSequence;IIZII)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0
.end method

.method public f(I)I
    .locals 8

    .line 1
    iget-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Landroid/text/TextPaint;

    .line 5
    .line 6
    iget-object p0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, p0

    .line 9
    check-cast v2, Ljava/lang/CharSequence;

    .line 10
    .line 11
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    const/4 v5, 0x0

    .line 16
    const/4 v7, 0x0

    .line 17
    const/4 v3, 0x0

    .line 18
    move v6, p1

    .line 19
    invoke-virtual/range {v1 .. v7}, Landroid/graphics/Paint;->getTextRunCursor(Ljava/lang/CharSequence;IIZII)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0
.end method

.method public g([BIILl9/i;Lw7/f;)V
    .locals 18

    move-object/from16 v0, p0

    move/from16 v1, p2

    .line 1
    iget-object v2, v0, Lb81/a;->e:Ljava/lang/Object;

    check-cast v2, Lw7/p;

    add-int v3, v1, p3

    move-object/from16 v4, p1

    invoke-virtual {v2, v3, v4}, Lw7/p;->G(I[B)V

    .line 2
    invoke-virtual {v2, v1}, Lw7/p;->I(I)V

    .line 3
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 4
    :try_start_0
    invoke-static {v2}, Lu9/i;->c(Lw7/p;)V
    :try_end_0
    .catch Lt7/e0; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    :goto_0
    sget-object v3, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v2, v3}, Lw7/p;->k(Ljava/nio/charset/Charset;)Ljava/lang/String;

    move-result-object v3

    .line 6
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_0

    goto :goto_0

    .line 7
    :cond_0
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    :cond_1
    :goto_1
    const/4 v4, 0x0

    const/4 v5, -0x1

    move v7, v4

    move v6, v5

    :goto_2
    const/4 v9, 0x1

    const/4 v10, 0x2

    if-ne v6, v5, :cond_5

    .line 8
    iget v7, v2, Lw7/p;->b:I

    .line 9
    sget-object v6, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v2, v6}, Lw7/p;->k(Ljava/nio/charset/Charset;)Ljava/lang/String;

    move-result-object v6

    if-nez v6, :cond_2

    move v6, v4

    goto :goto_2

    .line 10
    :cond_2
    const-string v11, "STYLE"

    invoke-virtual {v11, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_3

    move v6, v10

    goto :goto_2

    .line 11
    :cond_3
    const-string v10, "NOTE"

    invoke-virtual {v6, v10}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v6

    if-eqz v6, :cond_4

    move v6, v9

    goto :goto_2

    :cond_4
    const/4 v6, 0x3

    goto :goto_2

    .line 12
    :cond_5
    invoke-virtual {v2, v7}, Lw7/p;->I(I)V

    if-eqz v6, :cond_3d

    if-ne v6, v9, :cond_6

    .line 13
    :goto_3
    sget-object v4, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v2, v4}, Lw7/p;->k(Ljava/nio/charset/Charset;)Ljava/lang/String;

    move-result-object v4

    .line 14
    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v4

    if-nez v4, :cond_1

    goto :goto_3

    :cond_6
    const/4 v7, 0x0

    if-ne v6, v10, :cond_38

    .line 15
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v6

    if-eqz v6, :cond_37

    .line 16
    sget-object v6, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v2, v6}, Lw7/p;->k(Ljava/nio/charset/Charset;)Ljava/lang/String;

    .line 17
    iget-object v6, v0, Lb81/a;->f:Ljava/lang/Object;

    check-cast v6, Lu9/a;

    .line 18
    iget-object v11, v6, Lu9/a;->a:Lw7/p;

    .line 19
    iget-object v6, v6, Lu9/a;->b:Ljava/lang/StringBuilder;

    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 20
    iget v12, v2, Lw7/p;->b:I

    .line 21
    :goto_4
    sget-object v13, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v2, v13}, Lw7/p;->k(Ljava/nio/charset/Charset;)Ljava/lang/String;

    move-result-object v13

    .line 22
    invoke-static {v13}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v13

    if-eqz v13, :cond_36

    .line 23
    iget-object v13, v2, Lw7/p;->a:[B

    .line 24
    iget v14, v2, Lw7/p;->b:I

    .line 25
    invoke-virtual {v11, v14, v13}, Lw7/p;->G(I[B)V

    .line 26
    invoke-virtual {v11, v12}, Lw7/p;->I(I)V

    .line 27
    new-instance v12, Ljava/util/ArrayList;

    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 28
    :goto_5
    invoke-static {v11}, Lu9/a;->c(Lw7/p;)V

    .line 29
    invoke-virtual {v11}, Lw7/p;->a()I

    move-result v13

    const-string v14, ""

    const-string v15, "{"

    const/4 v8, 0x5

    if-ge v13, v8, :cond_7

    :goto_6
    move-object v8, v7

    goto/16 :goto_a

    .line 30
    :cond_7
    sget-object v13, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v11, v8, v13}, Lw7/p;->u(ILjava/nio/charset/Charset;)Ljava/lang/String;

    move-result-object v8

    .line 31
    const-string v13, "::cue"

    invoke-virtual {v13, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_8

    goto :goto_6

    .line 32
    :cond_8
    iget v8, v11, Lw7/p;->b:I

    .line 33
    invoke-static {v11, v6}, Lu9/a;->b(Lw7/p;Ljava/lang/StringBuilder;)Ljava/lang/String;

    move-result-object v13

    if-nez v13, :cond_9

    goto :goto_6

    .line 34
    :cond_9
    invoke-virtual {v15, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_a

    .line 35
    invoke-virtual {v11, v8}, Lw7/p;->I(I)V

    move-object v8, v14

    goto :goto_a

    .line 36
    :cond_a
    const-string v8, "("

    invoke-virtual {v8, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_d

    .line 37
    iget v8, v11, Lw7/p;->b:I

    .line 38
    iget v13, v11, Lw7/p;->c:I

    move/from16 v16, v4

    :goto_7
    if-ge v8, v13, :cond_c

    if-nez v16, :cond_c

    .line 39
    iget-object v10, v11, Lw7/p;->a:[B

    add-int/lit8 v16, v8, 0x1

    .line 40
    aget-byte v8, v10, v8

    int-to-char v8, v8

    const/16 v10, 0x29

    if-ne v8, v10, :cond_b

    move v8, v9

    goto :goto_8

    :cond_b
    move v8, v4

    :goto_8
    move/from16 v10, v16

    move/from16 v16, v8

    move v8, v10

    const/4 v10, 0x2

    goto :goto_7

    :cond_c
    add-int/lit8 v8, v8, -0x1

    .line 41
    iget v10, v11, Lw7/p;->b:I

    sub-int/2addr v8, v10

    .line 42
    sget-object v10, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v11, v8, v10}, Lw7/p;->u(ILjava/nio/charset/Charset;)Ljava/lang/String;

    move-result-object v8

    .line 43
    invoke-virtual {v8}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v8

    goto :goto_9

    :cond_d
    move-object v8, v7

    .line 44
    :goto_9
    invoke-static {v11, v6}, Lu9/a;->b(Lw7/p;Ljava/lang/StringBuilder;)Ljava/lang/String;

    move-result-object v10

    .line 45
    const-string v13, ")"

    invoke-virtual {v13, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_e

    goto :goto_6

    :cond_e
    :goto_a
    if-eqz v8, :cond_34

    .line 46
    invoke-static {v11, v6}, Lu9/a;->b(Lw7/p;Ljava/lang/StringBuilder;)Ljava/lang/String;

    move-result-object v10

    invoke-virtual {v15, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_f

    goto/16 :goto_20

    .line 47
    :cond_f
    new-instance v10, Lu9/b;

    .line 48
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 49
    iput-object v14, v10, Lu9/b;->a:Ljava/lang/String;

    .line 50
    iput-object v14, v10, Lu9/b;->b:Ljava/lang/String;

    .line 51
    sget-object v13, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    iput-object v13, v10, Lu9/b;->c:Ljava/util/Set;

    .line 52
    iput-object v14, v10, Lu9/b;->d:Ljava/lang/String;

    .line 53
    iput-object v7, v10, Lu9/b;->e:Ljava/lang/String;

    .line 54
    iput-boolean v4, v10, Lu9/b;->g:Z

    .line 55
    iput-boolean v4, v10, Lu9/b;->i:Z

    .line 56
    iput v5, v10, Lu9/b;->j:I

    .line 57
    iput v5, v10, Lu9/b;->k:I

    .line 58
    iput v5, v10, Lu9/b;->l:I

    .line 59
    iput v5, v10, Lu9/b;->m:I

    .line 60
    iput v5, v10, Lu9/b;->n:I

    .line 61
    iput v5, v10, Lu9/b;->p:I

    .line 62
    iput-boolean v4, v10, Lu9/b;->q:Z

    .line 63
    invoke-virtual {v8}, Ljava/lang/String;->isEmpty()Z

    move-result v13

    if-eqz v13, :cond_10

    goto :goto_d

    :cond_10
    const/16 v13, 0x5b

    .line 64
    invoke-virtual {v8, v13}, Ljava/lang/String;->indexOf(I)I

    move-result v13

    if-eq v13, v5, :cond_12

    .line 65
    sget-object v14, Lu9/a;->c:Ljava/util/regex/Pattern;

    invoke-virtual {v8, v13}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v15

    invoke-virtual {v14, v15}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    move-result-object v14

    .line 66
    invoke-virtual {v14}, Ljava/util/regex/Matcher;->matches()Z

    move-result v15

    if-eqz v15, :cond_11

    .line 67
    invoke-virtual {v14, v9}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    move-result-object v14

    .line 68
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    iput-object v14, v10, Lu9/b;->d:Ljava/lang/String;

    .line 70
    :cond_11
    invoke-virtual {v8, v4, v13}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v8

    .line 71
    :cond_12
    sget-object v13, Lw7/w;->a:Ljava/lang/String;

    .line 72
    const-string v13, "\\."

    invoke-virtual {v8, v13, v5}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    move-result-object v8

    .line 73
    aget-object v13, v8, v4

    const/16 v14, 0x23

    .line 74
    invoke-virtual {v13, v14}, Ljava/lang/String;->indexOf(I)I

    move-result v14

    if-eq v14, v5, :cond_13

    .line 75
    invoke-virtual {v13, v4, v14}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v15

    .line 76
    iput-object v15, v10, Lu9/b;->b:Ljava/lang/String;

    add-int/lit8 v14, v14, 0x1

    .line 77
    invoke-virtual {v13, v14}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v13

    .line 78
    iput-object v13, v10, Lu9/b;->a:Ljava/lang/String;

    goto :goto_b

    .line 79
    :cond_13
    iput-object v13, v10, Lu9/b;->b:Ljava/lang/String;

    .line 80
    :goto_b
    array-length v13, v8

    if-le v13, v9, :cond_15

    .line 81
    array-length v13, v8

    .line 82
    array-length v14, v8

    if-gt v13, v14, :cond_14

    move v14, v9

    goto :goto_c

    :cond_14
    move v14, v4

    :goto_c
    invoke-static {v14}, Lw7/a;->c(Z)V

    .line 83
    invoke-static {v8, v9, v13}, Ljava/util/Arrays;->copyOfRange([Ljava/lang/Object;II)[Ljava/lang/Object;

    move-result-object v8

    .line 84
    check-cast v8, [Ljava/lang/String;

    .line 85
    new-instance v13, Ljava/util/HashSet;

    invoke-static {v8}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v8

    invoke-direct {v13, v8}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    iput-object v13, v10, Lu9/b;->c:Ljava/util/Set;

    :cond_15
    :goto_d
    move v8, v4

    move-object v13, v7

    .line 86
    :goto_e
    const-string v14, "}"

    if-nez v8, :cond_32

    .line 87
    iget v8, v11, Lw7/p;->b:I

    .line 88
    invoke-static {v11, v6}, Lu9/a;->b(Lw7/p;Ljava/lang/StringBuilder;)Ljava/lang/String;

    move-result-object v13

    if-eqz v13, :cond_17

    .line 89
    invoke-virtual {v14, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_16

    goto :goto_f

    :cond_16
    move v15, v4

    goto :goto_10

    :cond_17
    :goto_f
    move v15, v9

    :goto_10
    if-nez v15, :cond_31

    .line 90
    invoke-virtual {v11, v8}, Lw7/p;->I(I)V

    .line 91
    invoke-static {v11}, Lu9/a;->c(Lw7/p;)V

    .line 92
    invoke-static {v11, v6}, Lu9/a;->a(Lw7/p;Ljava/lang/StringBuilder;)Ljava/lang/String;

    move-result-object v8

    .line 93
    invoke-virtual {v8}, Ljava/lang/String;->isEmpty()Z

    move-result v16

    if-eqz v16, :cond_18

    goto/16 :goto_1d

    .line 94
    :cond_18
    const-string v4, ":"

    invoke-static {v11, v6}, Lu9/a;->b(Lw7/p;Ljava/lang/StringBuilder;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_19

    goto/16 :goto_1d

    .line 95
    :cond_19
    invoke-static {v11}, Lu9/a;->c(Lw7/p;)V

    .line 96
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const/4 v5, 0x0

    .line 97
    :goto_11
    const-string v7, ";"

    if-nez v5, :cond_1d

    .line 98
    iget v9, v11, Lw7/p;->b:I

    .line 99
    invoke-static {v11, v6}, Lu9/a;->b(Lw7/p;Ljava/lang/StringBuilder;)Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_1a

    const/4 v0, 0x0

    goto :goto_14

    .line 100
    :cond_1a
    invoke-virtual {v14, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v17

    if-nez v17, :cond_1c

    invoke-virtual {v7, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_1b

    goto :goto_13

    .line 101
    :cond_1b
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :goto_12
    move-object/from16 v0, p0

    const/4 v9, 0x1

    goto :goto_11

    .line 102
    :cond_1c
    :goto_13
    invoke-virtual {v11, v9}, Lw7/p;->I(I)V

    const/4 v5, 0x1

    goto :goto_12

    .line 103
    :cond_1d
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    :goto_14
    if-eqz v0, :cond_1e

    .line 104
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v4

    if-eqz v4, :cond_1f

    :cond_1e
    :goto_15
    const/4 v0, 0x1

    goto/16 :goto_1e

    .line 105
    :cond_1f
    iget v4, v11, Lw7/p;->b:I

    .line 106
    invoke-static {v11, v6}, Lu9/a;->b(Lw7/p;Ljava/lang/StringBuilder;)Ljava/lang/String;

    move-result-object v5

    .line 107
    invoke-virtual {v7, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_20

    goto :goto_16

    .line 108
    :cond_20
    invoke-virtual {v14, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1e

    .line 109
    invoke-virtual {v11, v4}, Lw7/p;->I(I)V

    .line 110
    :goto_16
    const-string v4, "color"

    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_21

    const/4 v4, 0x1

    .line 111
    invoke-static {v0, v4}, Lw7/d;->a(Ljava/lang/String;Z)I

    move-result v0

    .line 112
    iput v0, v10, Lu9/b;->f:I

    .line 113
    iput-boolean v4, v10, Lu9/b;->g:Z

    goto/16 :goto_19

    :cond_21
    const/4 v4, 0x1

    .line 114
    const-string v5, "background-color"

    invoke-virtual {v5, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_22

    .line 115
    invoke-static {v0, v4}, Lw7/d;->a(Ljava/lang/String;Z)I

    move-result v0

    .line 116
    iput v0, v10, Lu9/b;->h:I

    .line 117
    iput-boolean v4, v10, Lu9/b;->i:Z

    goto/16 :goto_19

    .line 118
    :cond_22
    const-string v5, "ruby-position"

    invoke-virtual {v5, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_24

    .line 119
    const-string v5, "over"

    invoke-virtual {v5, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_23

    .line 120
    iput v4, v10, Lu9/b;->p:I

    goto/16 :goto_19

    .line 121
    :cond_23
    const-string v4, "under"

    invoke-virtual {v4, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1e

    const/4 v0, 0x2

    .line 122
    iput v0, v10, Lu9/b;->p:I

    move v5, v0

    const/4 v0, 0x1

    goto/16 :goto_1f

    .line 123
    :cond_24
    const-string v4, "text-combine-upright"

    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_27

    .line 124
    const-string v4, "all"

    invoke-virtual {v4, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_26

    const-string v4, "digits"

    invoke-virtual {v0, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_25

    goto :goto_17

    :cond_25
    const/4 v0, 0x0

    goto :goto_18

    :cond_26
    :goto_17
    const/4 v0, 0x1

    .line 125
    :goto_18
    iput-boolean v0, v10, Lu9/b;->q:Z

    goto/16 :goto_15

    .line 126
    :cond_27
    const-string v4, "text-decoration"

    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_28

    .line 127
    const-string v4, "underline"

    invoke-virtual {v4, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1e

    const/4 v4, 0x1

    .line 128
    iput v4, v10, Lu9/b;->k:I

    goto :goto_19

    .line 129
    :cond_28
    const-string v4, "font-family"

    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_29

    .line 130
    invoke-static {v0}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 131
    iput-object v0, v10, Lu9/b;->e:Ljava/lang/String;

    goto/16 :goto_15

    .line 132
    :cond_29
    const-string v4, "font-weight"

    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_2a

    .line 133
    const-string v4, "bold"

    invoke-virtual {v4, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1e

    const/4 v4, 0x1

    .line 134
    iput v4, v10, Lu9/b;->l:I

    goto :goto_19

    :cond_2a
    const/4 v4, 0x1

    .line 135
    const-string v5, "font-style"

    invoke-virtual {v5, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2c

    .line 136
    const-string v5, "italic"

    invoke-virtual {v5, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2b

    .line 137
    iput v4, v10, Lu9/b;->m:I

    :cond_2b
    :goto_19
    move v0, v4

    goto/16 :goto_1e

    .line 138
    :cond_2c
    const-string v4, "font-size"

    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1e

    .line 139
    sget-object v4, Lu9/a;->d:Ljava/util/regex/Pattern;

    invoke-static {v0}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    move-result-object v4

    .line 140
    invoke-virtual {v4}, Ljava/util/regex/Matcher;->matches()Z

    move-result v5

    if-nez v5, :cond_2d

    .line 141
    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "Invalid font-size: \'"

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, "\'."

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v4, "WebvttCssParser"

    invoke-static {v4, v0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    goto/16 :goto_15

    :cond_2d
    const/4 v0, 0x2

    .line 142
    invoke-virtual {v4, v0}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    move-result-object v5

    .line 143
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 144
    invoke-virtual {v5}, Ljava/lang/String;->hashCode()I

    move-result v0

    sparse-switch v0, :sswitch_data_0

    :goto_1a
    const/4 v0, -0x1

    goto :goto_1b

    :sswitch_0
    const-string v0, "px"

    invoke-virtual {v5, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2e

    goto :goto_1a

    :cond_2e
    const/4 v0, 0x2

    goto :goto_1b

    :sswitch_1
    const-string v0, "em"

    invoke-virtual {v5, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2f

    goto :goto_1a

    :cond_2f
    const/4 v0, 0x1

    goto :goto_1b

    :sswitch_2
    const-string v0, "%"

    invoke-virtual {v5, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_30

    goto :goto_1a

    :cond_30
    const/4 v0, 0x0

    :goto_1b
    packed-switch v0, :pswitch_data_0

    .line 145
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    throw v0

    :pswitch_0
    const/4 v0, 0x1

    .line 146
    iput v0, v10, Lu9/b;->n:I

    const/4 v5, 0x2

    goto :goto_1c

    :pswitch_1
    const/4 v0, 0x1

    const/4 v5, 0x2

    .line 147
    iput v5, v10, Lu9/b;->n:I

    goto :goto_1c

    :pswitch_2
    const/4 v0, 0x1

    const/4 v5, 0x2

    const/4 v7, 0x3

    .line 148
    iput v7, v10, Lu9/b;->n:I

    .line 149
    :goto_1c
    invoke-virtual {v4, v0}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    move-result-object v4

    .line 150
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 151
    invoke-static {v4}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v4

    .line 152
    iput v4, v10, Lu9/b;->o:F

    goto :goto_1f

    :cond_31
    :goto_1d
    move v0, v9

    :goto_1e
    const/4 v5, 0x2

    :goto_1f
    move v9, v0

    move v8, v15

    const/4 v4, 0x0

    const/4 v5, -0x1

    const/4 v7, 0x0

    move-object/from16 v0, p0

    goto/16 :goto_e

    :cond_32
    move v0, v9

    const/4 v5, 0x2

    .line 153
    invoke-virtual {v14, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_33

    .line 154
    invoke-virtual {v12, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_33
    move v9, v0

    move v10, v5

    const/4 v4, 0x0

    const/4 v5, -0x1

    const/4 v7, 0x0

    move-object/from16 v0, p0

    goto/16 :goto_5

    .line 155
    :cond_34
    :goto_20
    invoke-virtual {v1, v12}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    :cond_35
    :goto_21
    move-object/from16 v0, p0

    goto/16 :goto_1

    :cond_36
    move-object/from16 v0, p0

    goto/16 :goto_4

    .line 156
    :cond_37
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "A style block was found after the first cue."

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_38
    const/4 v7, 0x3

    if-ne v6, v7, :cond_35

    .line 157
    sget-object v0, Lu9/h;->a:Ljava/util/regex/Pattern;

    .line 158
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v2, v0}, Lw7/p;->k(Ljava/nio/charset/Charset;)Ljava/lang/String;

    move-result-object v4

    if-nez v4, :cond_39

    const/4 v7, 0x0

    goto :goto_22

    .line 159
    :cond_39
    sget-object v5, Lu9/h;->a:Ljava/util/regex/Pattern;

    invoke-virtual {v5, v4}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    move-result-object v6

    .line 160
    invoke-virtual {v6}, Ljava/util/regex/Matcher;->matches()Z

    move-result v7

    if-eqz v7, :cond_3a

    const/4 v7, 0x0

    .line 161
    invoke-static {v7, v6, v2, v1}, Lu9/h;->d(Ljava/lang/String;Ljava/util/regex/Matcher;Lw7/p;Ljava/util/ArrayList;)Lu9/c;

    move-result-object v7

    goto :goto_22

    :cond_3a
    const/4 v7, 0x0

    .line 162
    invoke-virtual {v2, v0}, Lw7/p;->k(Ljava/nio/charset/Charset;)Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_3b

    goto :goto_22

    .line 163
    :cond_3b
    invoke-virtual {v5, v0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    move-result-object v0

    .line 164
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->matches()Z

    move-result v5

    if-eqz v5, :cond_3c

    .line 165
    invoke-virtual {v4}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v4

    invoke-static {v4, v0, v2, v1}, Lu9/h;->d(Ljava/lang/String;Ljava/util/regex/Matcher;Lw7/p;Ljava/util/ArrayList;)Lu9/c;

    move-result-object v7

    :cond_3c
    :goto_22
    if-eqz v7, :cond_35

    .line 166
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_21

    .line 167
    :cond_3d
    new-instance v0, Lrn/i;

    invoke-direct {v0, v3}, Lrn/i;-><init>(Ljava/util/ArrayList;)V

    move-object/from16 v1, p4

    move-object/from16 v2, p5

    .line 168
    invoke-static {v0, v1, v2}, Llp/cf;->c(Ll9/d;Ll9/i;Lw7/f;)V

    return-void

    :catch_0
    move-exception v0

    .line 169
    new-instance v1, Ljava/lang/IllegalArgumentException;

    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    throw v1

    nop

    :sswitch_data_0
    .sparse-switch
        0x25 -> :sswitch_2
        0xca8 -> :sswitch_1
        0xe08 -> :sswitch_0
    .end sparse-switch

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public get()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lkx0/a;

    .line 4
    .line 5
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lhu/b;

    .line 10
    .line 11
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lj1/a;

    .line 14
    .line 15
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lpx0/g;

    .line 18
    .line 19
    new-instance v1, Lku/d;

    .line 20
    .line 21
    invoke-direct {v1, v0, p0}, Lku/d;-><init>(Lhu/b;Lpx0/g;)V

    .line 22
    .line 23
    .line 24
    return-object v1
.end method

.method public h(Lhy0/d;)Lqz0/a;
    .locals 3

    .line 1
    iget-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 4
    .line 5
    invoke-static {p1}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v0, v1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    if-nez v2, :cond_1

    .line 14
    .line 15
    new-instance v2, Luz0/k;

    .line 16
    .line 17
    iget-object p0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lay0/k;

    .line 20
    .line 21
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lqz0/a;

    .line 26
    .line 27
    invoke-direct {v2, p0}, Luz0/k;-><init>(Lqz0/a;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    if-nez p0, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move-object v2, p0

    .line 38
    :cond_1
    :goto_0
    check-cast v2, Luz0/k;

    .line 39
    .line 40
    iget-object p0, v2, Luz0/k;->a:Lqz0/a;

    .line 41
    .line 42
    return-object p0
.end method

.method public i(I)I
    .locals 9

    .line 1
    iget-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Landroid/text/TextPaint;

    .line 5
    .line 6
    iget-object v0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, v0

    .line 9
    check-cast v2, Ljava/lang/CharSequence;

    .line 10
    .line 11
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    const/4 v5, 0x0

    .line 16
    const/4 v7, 0x2

    .line 17
    const/4 v3, 0x0

    .line 18
    move v6, p1

    .line 19
    invoke-virtual/range {v1 .. v7}, Landroid/graphics/Paint;->getTextRunCursor(Ljava/lang/CharSequence;IIZII)I

    .line 20
    .line 21
    .line 22
    move-result v7

    .line 23
    const/4 p1, -0x1

    .line 24
    if-ne v7, p1, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Landroid/text/TextPaint;

    .line 30
    .line 31
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    const/4 v6, 0x0

    .line 36
    const/4 v8, 0x2

    .line 37
    const/4 v4, 0x0

    .line 38
    move-object v3, v2

    .line 39
    move-object v2, p0

    .line 40
    invoke-virtual/range {v2 .. v8}, Landroid/graphics/Paint;->getTextRunCursor(Ljava/lang/CharSequence;IIZII)I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-ne p0, p1, :cond_1

    .line 45
    .line 46
    :goto_0
    return p1

    .line 47
    :cond_1
    return v7
.end method

.method public j()V
    .locals 2

    .line 1
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lw7/p;

    .line 4
    .line 5
    sget-object v0, Lw7/w;->b:[B

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    array-length v1, v0

    .line 11
    invoke-virtual {p0, v1, v0}, Lw7/p;->G(I[B)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public k(Ljava/util/List;)Ll4/v;
    .locals 10

    .line 1
    const/4 v1, 0x0

    .line 2
    :try_start_0
    move-object v0, p1

    .line 3
    check-cast v0, Ljava/util/Collection;

    .line 4
    .line 5
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 6
    .line 7
    .line 8
    move-result v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_2

    .line 9
    const/4 v2, 0x0

    .line 10
    move-object v3, v1

    .line 11
    :goto_0
    if-ge v2, v0, :cond_0

    .line 12
    .line 13
    :try_start_1
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    check-cast v4, Ll4/g;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 18
    .line 19
    :try_start_2
    iget-object v3, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v3, Lcom/google/android/material/datepicker/w;

    .line 22
    .line 23
    invoke-interface {v4, v3}, Ll4/g;->a(Lcom/google/android/material/datepicker/w;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 24
    .line 25
    .line 26
    add-int/lit8 v2, v2, 0x1

    .line 27
    .line 28
    move-object v3, v4

    .line 29
    goto :goto_0

    .line 30
    :catch_0
    move-exception v0

    .line 31
    move-object v1, v4

    .line 32
    goto :goto_2

    .line 33
    :catch_1
    move-exception v0

    .line 34
    move-object v1, v3

    .line 35
    goto :goto_2

    .line 36
    :cond_0
    iget-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p1, Lcom/google/android/material/datepicker/w;

    .line 39
    .line 40
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 41
    .line 42
    .line 43
    new-instance v0, Lg4/g;

    .line 44
    .line 45
    iget-object p1, p1, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p1, Li4/c;

    .line 48
    .line 49
    invoke-virtual {p1}, Li4/c;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-direct {v0, p1}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p1, Lcom/google/android/material/datepicker/w;

    .line 59
    .line 60
    iget v2, p1, Lcom/google/android/material/datepicker/w;->e:I

    .line 61
    .line 62
    iget p1, p1, Lcom/google/android/material/datepicker/w;->f:I

    .line 63
    .line 64
    invoke-static {v2, p1}, Lg4/f0;->b(II)J

    .line 65
    .line 66
    .line 67
    move-result-wide v2

    .line 68
    new-instance p1, Lg4/o0;

    .line 69
    .line 70
    invoke-direct {p1, v2, v3}, Lg4/o0;-><init>(J)V

    .line 71
    .line 72
    .line 73
    iget-object v4, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v4, Ll4/v;

    .line 76
    .line 77
    iget-wide v4, v4, Ll4/v;->b:J

    .line 78
    .line 79
    invoke-static {v4, v5}, Lg4/o0;->g(J)Z

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    if-nez v4, :cond_1

    .line 84
    .line 85
    move-object v1, p1

    .line 86
    :cond_1
    if-eqz v1, :cond_2

    .line 87
    .line 88
    iget-wide v1, v1, Lg4/o0;->a:J

    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_2
    invoke-static {v2, v3}, Lg4/o0;->e(J)I

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    invoke-static {v2, v3}, Lg4/o0;->f(J)I

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    invoke-static {p1, v1}, Lg4/f0;->b(II)J

    .line 100
    .line 101
    .line 102
    move-result-wide v1

    .line 103
    :goto_1
    iget-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast p1, Lcom/google/android/material/datepicker/w;

    .line 106
    .line 107
    invoke-virtual {p1}, Lcom/google/android/material/datepicker/w;->c()Lg4/o0;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    new-instance v3, Ll4/v;

    .line 112
    .line 113
    invoke-direct {v3, v0, v1, v2, p1}, Ll4/v;-><init>(Lg4/g;JLg4/o0;)V

    .line 114
    .line 115
    .line 116
    iput-object v3, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 117
    .line 118
    return-object v3

    .line 119
    :catch_2
    move-exception v0

    .line 120
    :goto_2
    new-instance v2, Ljava/lang/RuntimeException;

    .line 121
    .line 122
    new-instance v4, Ljava/lang/StringBuilder;

    .line 123
    .line 124
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 125
    .line 126
    .line 127
    new-instance v3, Ljava/lang/StringBuilder;

    .line 128
    .line 129
    const-string v5, "Error while applying EditCommand batch to buffer (length="

    .line 130
    .line 131
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    iget-object v5, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v5, Lcom/google/android/material/datepicker/w;

    .line 137
    .line 138
    iget-object v5, v5, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 139
    .line 140
    check-cast v5, Li4/c;

    .line 141
    .line 142
    invoke-virtual {v5}, Li4/c;->s()I

    .line 143
    .line 144
    .line 145
    move-result v5

    .line 146
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    const-string v5, ", composition="

    .line 150
    .line 151
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 152
    .line 153
    .line 154
    iget-object v5, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast v5, Lcom/google/android/material/datepicker/w;

    .line 157
    .line 158
    invoke-virtual {v5}, Lcom/google/android/material/datepicker/w;->c()Lg4/o0;

    .line 159
    .line 160
    .line 161
    move-result-object v5

    .line 162
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    const-string v5, ", selection="

    .line 166
    .line 167
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    iget-object v5, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast v5, Lcom/google/android/material/datepicker/w;

    .line 173
    .line 174
    iget v6, v5, Lcom/google/android/material/datepicker/w;->e:I

    .line 175
    .line 176
    iget v5, v5, Lcom/google/android/material/datepicker/w;->f:I

    .line 177
    .line 178
    invoke-static {v6, v5}, Lg4/f0;->b(II)J

    .line 179
    .line 180
    .line 181
    move-result-wide v5

    .line 182
    invoke-static {v5, v6}, Lg4/o0;->h(J)Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v5

    .line 186
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    const-string v5, "):"

    .line 190
    .line 191
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 192
    .line 193
    .line 194
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object v3

    .line 198
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    const/16 v3, 0xa

    .line 202
    .line 203
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    move-object v3, p1

    .line 207
    check-cast v3, Ljava/lang/Iterable;

    .line 208
    .line 209
    new-instance v8, Li40/e1;

    .line 210
    .line 211
    invoke-direct {v8, v1, p0}, Li40/e1;-><init>(Ll4/g;Lb81/a;)V

    .line 212
    .line 213
    .line 214
    const/16 v9, 0x3c

    .line 215
    .line 216
    const-string v5, "\n"

    .line 217
    .line 218
    const/4 v6, 0x0

    .line 219
    const/4 v7, 0x0

    .line 220
    invoke-static/range {v3 .. v9}, Lmx0/q;->Q(Ljava/lang/Iterable;Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    const-string p1, "toString(...)"

    .line 228
    .line 229
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    invoke-direct {v2, p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 233
    .line 234
    .line 235
    throw v2
.end method

.method public l(Lmb/i;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lfb/k;

    .line 7
    .line 8
    iget-object p0, p0, Lfb/k;->a:Ljava/util/LinkedHashMap;

    .line 9
    .line 10
    invoke-interface {p0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    monitor-exit v0

    .line 15
    return p0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    monitor-exit v0

    .line 18
    throw p0
.end method

.method public m()Ljava/util/ArrayList;
    .locals 6

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Laq/a;

    .line 9
    .line 10
    iget-object p0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Landroid/content/Context;

    .line 13
    .line 14
    iget-object v1, v1, Laq/a;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Ljava/lang/Class;

    .line 17
    .line 18
    const-string v2, "ComponentDiscovery"

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    if-nez v4, :cond_0

    .line 26
    .line 27
    const-string p0, "Context has no PackageManager."

    .line 28
    .line 29
    invoke-static {v2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    new-instance v5, Landroid/content/ComponentName;

    .line 34
    .line 35
    invoke-direct {v5, p0, v1}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 36
    .line 37
    .line 38
    const/16 p0, 0x80

    .line 39
    .line 40
    invoke-virtual {v4, v5, p0}, Landroid/content/pm/PackageManager;->getServiceInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ServiceInfo;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    if-nez p0, :cond_1

    .line 45
    .line 46
    new-instance p0, Ljava/lang/StringBuilder;

    .line 47
    .line 48
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, " has no service info."

    .line 55
    .line 56
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-static {v2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_1
    iget-object v3, p0, Landroid/content/pm/ServiceInfo;->metaData:Landroid/os/Bundle;
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :catch_0
    const-string p0, "Application info not found."

    .line 71
    .line 72
    invoke-static {v2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 73
    .line 74
    .line 75
    :goto_0
    if-nez v3, :cond_2

    .line 76
    .line 77
    const-string p0, "Could not retrieve metadata, returning empty list of registrars."

    .line 78
    .line 79
    invoke-static {v2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 80
    .line 81
    .line 82
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_2
    new-instance p0, Ljava/util/ArrayList;

    .line 86
    .line 87
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v3}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    :cond_3
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    if-eqz v2, :cond_4

    .line 103
    .line 104
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    check-cast v2, Ljava/lang/String;

    .line 109
    .line 110
    invoke-virtual {v3, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v4

    .line 114
    const-string v5, "com.google.firebase.components.ComponentRegistrar"

    .line 115
    .line 116
    invoke-virtual {v5, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v4

    .line 120
    if-eqz v4, :cond_3

    .line 121
    .line 122
    const-string v4, "com.google.firebase.components:"

    .line 123
    .line 124
    invoke-virtual {v2, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 125
    .line 126
    .line 127
    move-result v4

    .line 128
    if-eqz v4, :cond_3

    .line 129
    .line 130
    const/16 v4, 0x1f

    .line 131
    .line 132
    invoke-virtual {v2, v4}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v2

    .line 136
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    goto :goto_1

    .line 140
    :cond_4
    :goto_2
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    if-eqz v1, :cond_5

    .line 149
    .line 150
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v1

    .line 154
    check-cast v1, Ljava/lang/String;

    .line 155
    .line 156
    new-instance v2, Lgs/d;

    .line 157
    .line 158
    const/4 v3, 0x0

    .line 159
    invoke-direct {v2, v1, v3}, Lgs/d;-><init>(Ljava/lang/Object;I)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    goto :goto_3

    .line 166
    :cond_5
    return-object v0
.end method

.method public n(Ljava/lang/String;)Lcom/google/android/datatransport/cct/CctBackendFactory;
    .locals 13

    .line 1
    const-string v0, "."

    .line 2
    .line 3
    const-string v1, "Could not instantiate "

    .line 4
    .line 5
    iget-object v2, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Ljava/util/Map;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const-string v4, "BackendRegistry"

    .line 11
    .line 12
    if-nez v2, :cond_6

    .line 13
    .line 14
    iget-object v2, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Landroid/content/Context;

    .line 17
    .line 18
    :try_start_0
    invoke-virtual {v2}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 19
    .line 20
    .line 21
    move-result-object v5

    .line 22
    if-nez v5, :cond_0

    .line 23
    .line 24
    const-string v2, "Context has no PackageManager."

    .line 25
    .line 26
    invoke-static {v4, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    :goto_0
    move-object v2, v3

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    new-instance v6, Landroid/content/ComponentName;

    .line 32
    .line 33
    const-class v7, Lcom/google/android/datatransport/runtime/backends/TransportBackendDiscovery;

    .line 34
    .line 35
    invoke-direct {v6, v2, v7}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 36
    .line 37
    .line 38
    const/16 v2, 0x80

    .line 39
    .line 40
    invoke-virtual {v5, v6, v2}, Landroid/content/pm/PackageManager;->getServiceInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ServiceInfo;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    if-nez v2, :cond_1

    .line 45
    .line 46
    const-string v2, "TransportBackendDiscovery has no service info."

    .line 47
    .line 48
    invoke-static {v4, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    iget-object v2, v2, Landroid/content/pm/ServiceInfo;->metaData:Landroid/os/Bundle;
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :catch_0
    const-string v2, "Application info not found."

    .line 56
    .line 57
    invoke-static {v4, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :goto_1
    if-nez v2, :cond_2

    .line 62
    .line 63
    const-string v2, "Could not retrieve metadata, returning empty list of transport backends."

    .line 64
    .line 65
    invoke-static {v4, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 66
    .line 67
    .line 68
    sget-object v2, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 69
    .line 70
    goto :goto_4

    .line 71
    :cond_2
    new-instance v5, Ljava/util/HashMap;

    .line 72
    .line 73
    invoke-direct {v5}, Ljava/util/HashMap;-><init>()V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v2}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    invoke-interface {v6}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 81
    .line 82
    .line 83
    move-result-object v6

    .line 84
    :cond_3
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 85
    .line 86
    .line 87
    move-result v7

    .line 88
    if-eqz v7, :cond_5

    .line 89
    .line 90
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v7

    .line 94
    check-cast v7, Ljava/lang/String;

    .line 95
    .line 96
    invoke-virtual {v2, v7}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v8

    .line 100
    instance-of v9, v8, Ljava/lang/String;

    .line 101
    .line 102
    if-eqz v9, :cond_3

    .line 103
    .line 104
    const-string v9, "backend:"

    .line 105
    .line 106
    invoke-virtual {v7, v9}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 107
    .line 108
    .line 109
    move-result v9

    .line 110
    if-eqz v9, :cond_3

    .line 111
    .line 112
    check-cast v8, Ljava/lang/String;

    .line 113
    .line 114
    const-string v9, ","

    .line 115
    .line 116
    const/4 v10, -0x1

    .line 117
    invoke-virtual {v8, v9, v10}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v8

    .line 121
    array-length v9, v8

    .line 122
    const/4 v10, 0x0

    .line 123
    :goto_2
    if-ge v10, v9, :cond_3

    .line 124
    .line 125
    aget-object v11, v8, v10

    .line 126
    .line 127
    invoke-virtual {v11}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v11

    .line 131
    invoke-virtual {v11}, Ljava/lang/String;->isEmpty()Z

    .line 132
    .line 133
    .line 134
    move-result v12

    .line 135
    if-eqz v12, :cond_4

    .line 136
    .line 137
    goto :goto_3

    .line 138
    :cond_4
    const/16 v12, 0x8

    .line 139
    .line 140
    invoke-virtual {v7, v12}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v12

    .line 144
    invoke-virtual {v5, v11, v12}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    :goto_3
    add-int/lit8 v10, v10, 0x1

    .line 148
    .line 149
    goto :goto_2

    .line 150
    :cond_5
    move-object v2, v5

    .line 151
    :goto_4
    iput-object v2, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 152
    .line 153
    :cond_6
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 154
    .line 155
    check-cast p0, Ljava/util/Map;

    .line 156
    .line 157
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    check-cast p0, Ljava/lang/String;

    .line 162
    .line 163
    if-nez p0, :cond_7

    .line 164
    .line 165
    return-object v3

    .line 166
    :cond_7
    :try_start_1
    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    const-class v2, Lcom/google/android/datatransport/cct/CctBackendFactory;

    .line 171
    .line 172
    invoke-virtual {p1, v2}, Ljava/lang/Class;->asSubclass(Ljava/lang/Class;)Ljava/lang/Class;

    .line 173
    .line 174
    .line 175
    move-result-object p1

    .line 176
    invoke-virtual {p1, v3}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 177
    .line 178
    .line 179
    move-result-object p1

    .line 180
    invoke-virtual {p1, v3}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    check-cast p1, Lcom/google/android/datatransport/cct/CctBackendFactory;
    :try_end_1
    .catch Ljava/lang/ClassNotFoundException; {:try_start_1 .. :try_end_1} :catch_5
    .catch Ljava/lang/IllegalAccessException; {:try_start_1 .. :try_end_1} :catch_4
    .catch Ljava/lang/InstantiationException; {:try_start_1 .. :try_end_1} :catch_3
    .catch Ljava/lang/NoSuchMethodException; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_1 .. :try_end_1} :catch_1

    .line 185
    .line 186
    return-object p1

    .line 187
    :catch_1
    move-exception p1

    .line 188
    goto :goto_5

    .line 189
    :catch_2
    move-exception p1

    .line 190
    goto :goto_6

    .line 191
    :catch_3
    move-exception p1

    .line 192
    goto :goto_7

    .line 193
    :catch_4
    move-exception p1

    .line 194
    goto :goto_8

    .line 195
    :catch_5
    move-exception p1

    .line 196
    goto :goto_9

    .line 197
    :goto_5
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    invoke-static {v4, p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 202
    .line 203
    .line 204
    goto :goto_a

    .line 205
    :goto_6
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    invoke-static {v4, p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 210
    .line 211
    .line 212
    goto :goto_a

    .line 213
    :goto_7
    new-instance v2, Ljava/lang/StringBuilder;

    .line 214
    .line 215
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 219
    .line 220
    .line 221
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 222
    .line 223
    .line 224
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object p0

    .line 228
    invoke-static {v4, p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 229
    .line 230
    .line 231
    goto :goto_a

    .line 232
    :goto_8
    new-instance v2, Ljava/lang/StringBuilder;

    .line 233
    .line 234
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 238
    .line 239
    .line 240
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 241
    .line 242
    .line 243
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object p0

    .line 247
    invoke-static {v4, p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 248
    .line 249
    .line 250
    goto :goto_a

    .line 251
    :goto_9
    new-instance v0, Ljava/lang/StringBuilder;

    .line 252
    .line 253
    const-string v1, "Class "

    .line 254
    .line 255
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 259
    .line 260
    .line 261
    const-string p0, " is not found."

    .line 262
    .line 263
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 264
    .line 265
    .line 266
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object p0

    .line 270
    invoke-static {v4, p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 271
    .line 272
    .line 273
    :goto_a
    return-object v3
.end method

.method public onComplete(Laq/j;)V
    .locals 1

    .line 1
    iget-object p1, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Ler/d;

    .line 4
    .line 5
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Laq/k;

    .line 8
    .line 9
    iget-object v0, p1, Ler/d;->f:Ljava/lang/Object;

    .line 10
    .line 11
    monitor-enter v0

    .line 12
    :try_start_0
    iget-object p1, p1, Ler/d;->e:Ljava/util/HashSet;

    .line 13
    .line 14
    invoke-virtual {p1, p0}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    monitor-exit v0

    .line 18
    return-void

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    throw p0
.end method

.method public p()V
    .locals 0

    .line 1
    iget-object p0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/util/SparseIntArray;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/util/SparseIntArray;->clear()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public q(ILandroid/os/Bundle;)V
    .locals 2

    .line 1
    sget-object v0, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "Analytics listener received message. ID: "

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p1, ", Extras: "

    .line 14
    .line 15
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    const-string v0, "FirebaseCrashlytics"

    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    invoke-static {v0, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_0

    .line 33
    .line 34
    const/4 v1, 0x0

    .line 35
    invoke-static {v0, p1, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 36
    .line 37
    .line 38
    :cond_0
    const-string p1, "name"

    .line 39
    .line 40
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    if-eqz p1, :cond_4

    .line 45
    .line 46
    const-string v0, "params"

    .line 47
    .line 48
    invoke-virtual {p2, v0}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    if-nez p2, :cond_1

    .line 53
    .line 54
    new-instance p2, Landroid/os/Bundle;

    .line 55
    .line 56
    invoke-direct {p2}, Landroid/os/Bundle;-><init>()V

    .line 57
    .line 58
    .line 59
    :cond_1
    const-string v0, "_o"

    .line 60
    .line 61
    invoke-virtual {p2, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    const-string v1, "clx"

    .line 66
    .line 67
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-eqz v0, :cond_2

    .line 72
    .line 73
    iget-object p0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast p0, Lil/g;

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_2
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p0, Lh6/e;

    .line 81
    .line 82
    :goto_0
    if-nez p0, :cond_3

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_3
    invoke-interface {p0, p1, p2}, Lks/b;->t(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 86
    .line 87
    .line 88
    :cond_4
    :goto_1
    return-void
.end method

.method public r(Lmb/i;)Lfb/j;
    .locals 1

    .line 1
    const-string v0, "id"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 7
    .line 8
    monitor-enter v0

    .line 9
    :try_start_0
    iget-object p0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lfb/k;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lfb/k;->e(Lmb/i;)Lfb/j;

    .line 14
    .line 15
    .line 16
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    monitor-exit v0

    .line 18
    return-object p0

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    monitor-exit v0

    .line 21
    throw p0
.end method

.method public s(Lmb/i;)Lfb/j;
    .locals 1

    .line 1
    iget-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lfb/k;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lfb/k;->g(Lmb/i;)Lfb/j;

    .line 9
    .line 10
    .line 11
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    monitor-exit v0

    .line 13
    return-object p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0

    .line 16
    throw p0
.end method

.method public t(Ljava/lang/String;Lrx0/c;)Ljava/io/Serializable;
    .locals 7

    .line 1
    instance-of v0, p2, Lh51/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lh51/a;

    .line 7
    .line 8
    iget v1, v0, Lh51/a;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lh51/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lh51/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lh51/a;-><init>(Lb81/a;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lh51/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lh51/a;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x0

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v3, :cond_2

    .line 37
    .line 38
    if-ne v2, v4, :cond_1

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_4

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    check-cast p2, Llx0/o;

    .line 56
    .line 57
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iget-object p2, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast p2, Lzv0/c;

    .line 66
    .line 67
    new-instance v2, Let/g;

    .line 68
    .line 69
    const/16 v6, 0x17

    .line 70
    .line 71
    invoke-direct {v2, v6, p0, p1}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 75
    .line 76
    const-class p1, Llx0/b0;

    .line 77
    .line 78
    invoke-virtual {p0, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    :try_start_0
    invoke-static {p1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 83
    .line 84
    .line 85
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 86
    goto :goto_1

    .line 87
    :catchall_0
    move-object p1, v5

    .line 88
    :goto_1
    new-instance v6, Lzw0/a;

    .line 89
    .line 90
    invoke-direct {v6, p0, p1}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 91
    .line 92
    .line 93
    new-instance p0, Lal0/m0;

    .line 94
    .line 95
    const/16 p1, 0x8

    .line 96
    .line 97
    invoke-direct {p0, v4, v5, p1}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 98
    .line 99
    .line 100
    iput v3, v0, Lh51/a;->f:I

    .line 101
    .line 102
    invoke-static {p2, v6, v2, p0, v0}, Lkp/h7;->i(Lzv0/c;Lzw0/a;Lay0/k;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    if-ne p0, v1, :cond_4

    .line 107
    .line 108
    goto :goto_3

    .line 109
    :cond_4
    :goto_2
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    if-eqz p0, :cond_6

    .line 114
    .line 115
    check-cast p0, Ls51/b;

    .line 116
    .line 117
    iput v4, v0, Lh51/a;->f:I

    .line 118
    .line 119
    invoke-static {p0, v0}, Lim/g;->h(Ls51/b;Lrx0/c;)Ljava/io/Serializable;

    .line 120
    .line 121
    .line 122
    move-result-object p2

    .line 123
    if-ne p2, v1, :cond_5

    .line 124
    .line 125
    :goto_3
    return-object v1

    .line 126
    :cond_5
    :goto_4
    move-object v5, p2

    .line 127
    check-cast v5, Lz41/b;

    .line 128
    .line 129
    :cond_6
    return-object v5
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget v0, p0, Lb81/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object v0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, La5/h;

    .line 14
    .line 15
    const-string v1, "[ "

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    :goto_0
    const/16 v2, 0x9

    .line 21
    .line 22
    if-ge v0, v2, :cond_0

    .line 23
    .line 24
    invoke-static {v1}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    iget-object v2, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v2, La5/h;

    .line 31
    .line 32
    iget-object v2, v2, La5/h;->k:[F

    .line 33
    .line 34
    aget v2, v2, v0

    .line 35
    .line 36
    const-string v3, " "

    .line 37
    .line 38
    invoke-static {v2, v3, v1}, Lkx/a;->g(FLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    add-int/lit8 v0, v0, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    const-string v0, "] "

    .line 46
    .line 47
    invoke-static {v1, v0}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    iget-object p0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast p0, La5/h;

    .line 54
    .line 55
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0

    .line 63
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public u(FLt4/c;Lvy0/b0;)V
    .locals 6

    .line 1
    sget v0, Lo1/n0;->a:F

    .line 2
    .line 3
    invoke-interface {p2, v0}, Lt4/c;->w0(F)F

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    cmpg-float p2, p1, p2

    .line 8
    .line 9
    if-gtz p2, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    const/4 v0, 0x0

    .line 17
    if-eqz p2, :cond_1

    .line 18
    .line 19
    invoke-virtual {p2}, Lv2/f;->e()Lay0/k;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    goto :goto_0

    .line 24
    :cond_1
    move-object v1, v0

    .line 25
    :goto_0
    invoke-static {p2}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    :try_start_0
    iget-object v3, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v3, Lc1/k;

    .line 32
    .line 33
    iget-object v3, v3, Lc1/k;->e:Ll2/j1;

    .line 34
    .line 35
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    check-cast v3, Ljava/lang/Number;

    .line 40
    .line 41
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    iget-object v4, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v4, Lvy0/x1;

    .line 48
    .line 49
    if-eqz v4, :cond_2

    .line 50
    .line 51
    invoke-virtual {v4, v0}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :catchall_0
    move-exception p0

    .line 56
    goto :goto_3

    .line 57
    :cond_2
    :goto_1
    iget-object v4, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v4, Lc1/k;

    .line 60
    .line 61
    iget-boolean v5, v4, Lc1/k;->i:Z

    .line 62
    .line 63
    if-eqz v5, :cond_3

    .line 64
    .line 65
    sub-float/2addr v3, p1

    .line 66
    const/4 p1, 0x0

    .line 67
    const/16 v5, 0x1e

    .line 68
    .line 69
    invoke-static {v4, v3, p1, v5}, Lc1/d;->m(Lc1/k;FFI)Lc1/k;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    iput-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_3
    new-instance v3, Lc1/k;

    .line 77
    .line 78
    sget-object v4, Lc1/d;->j:Lc1/b2;

    .line 79
    .line 80
    neg-float p1, p1

    .line 81
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    const/16 v5, 0x3c

    .line 86
    .line 87
    invoke-direct {v3, v4, p1, v0, v5}, Lc1/k;-><init>(Lc1/b2;Ljava/lang/Object;Lc1/p;I)V

    .line 88
    .line 89
    .line 90
    iput-object v3, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 91
    .line 92
    :goto_2
    new-instance p1, Ln00/f;

    .line 93
    .line 94
    const/4 v3, 0x7

    .line 95
    invoke-direct {p1, p0, v0, v3}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 96
    .line 97
    .line 98
    const/4 v3, 0x3

    .line 99
    invoke-static {p3, v0, v0, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    iput-object p1, p0, Lb81/a;->e:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 104
    .line 105
    invoke-static {p2, v2, v1}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 106
    .line 107
    .line 108
    return-void

    .line 109
    :goto_3
    invoke-static {p2, v2, v1}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 110
    .line 111
    .line 112
    throw p0
.end method

.method public y(Ljava/lang/Throwable;)V
    .locals 4

    .line 1
    iget v0, p0, Lb81/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    const-string v0, "SurfaceReleaseFuture did not complete nicely."

    .line 9
    .line 10
    invoke-direct {p0, v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    instance-of v0, p1, Lh0/s0;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    iget-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Lu/y;

    .line 22
    .line 23
    check-cast p1, Lh0/s0;

    .line 24
    .line 25
    iget-object p1, p1, Lh0/s0;->d:Lh0/t0;

    .line 26
    .line 27
    iget-object v0, v0, Lu/y;->d:Lb81/c;

    .line 28
    .line 29
    invoke-virtual {v0}, Lb81/c;->p()Ljava/util/Collection;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_1

    .line 42
    .line 43
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    check-cast v2, Lh0/z1;

    .line 48
    .line 49
    invoke-virtual {v2}, Lh0/z1;->b()Ljava/util/List;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    invoke-interface {v3, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    if-eqz v3, :cond_0

    .line 58
    .line 59
    move-object v1, v2

    .line 60
    :cond_1
    if-eqz v1, :cond_5

    .line 61
    .line 62
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast p0, Lu/y;

    .line 65
    .line 66
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    iget-object v0, v1, Lh0/z1;->f:Lh0/x1;

    .line 71
    .line 72
    if-eqz v0, :cond_5

    .line 73
    .line 74
    new-instance v2, Ljava/lang/Throwable;

    .line 75
    .line 76
    invoke-direct {v2}, Ljava/lang/Throwable;-><init>()V

    .line 77
    .line 78
    .line 79
    const-string v3, "Posting surface closed"

    .line 80
    .line 81
    invoke-virtual {p0, v3, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 82
    .line 83
    .line 84
    new-instance p0, Lno/nordicsemi/android/ble/o0;

    .line 85
    .line 86
    const/16 v2, 0x11

    .line 87
    .line 88
    invoke-direct {p0, v2, v0, v1}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p1, p0}, Lj0/c;->execute(Ljava/lang/Runnable;)V

    .line 92
    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_2
    instance-of v0, p1, Ljava/util/concurrent/CancellationException;

    .line 96
    .line 97
    if-eqz v0, :cond_3

    .line 98
    .line 99
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast p0, Lu/y;

    .line 102
    .line 103
    const-string p1, "Unable to configure camera cancelled"

    .line 104
    .line 105
    invoke-virtual {p0, p1, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 106
    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_3
    iget-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v0, Lu/y;

    .line 112
    .line 113
    iget v0, v0, Lu/y;->O:I

    .line 114
    .line 115
    const/16 v1, 0xa

    .line 116
    .line 117
    if-ne v0, v1, :cond_4

    .line 118
    .line 119
    iget-object v0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v0, Lu/y;

    .line 122
    .line 123
    new-instance v2, Lb0/e;

    .line 124
    .line 125
    const/4 v3, 0x4

    .line 126
    invoke-direct {v2, v3, p1}, Lb0/e;-><init>(ILjava/lang/Throwable;)V

    .line 127
    .line 128
    .line 129
    const/4 v3, 0x1

    .line 130
    invoke-virtual {v0, v1, v2, v3}, Lu/y;->H(ILb0/e;Z)V

    .line 131
    .line 132
    .line 133
    :cond_4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 134
    .line 135
    const-string v1, "Unable to configure camera "

    .line 136
    .line 137
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    iget-object v1, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v1, Lu/y;

    .line 143
    .line 144
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    const-string v1, "Camera2CameraImpl"

    .line 152
    .line 153
    invoke-static {v1, v0, p1}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 154
    .line 155
    .line 156
    iget-object p1, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast p1, Lu/y;

    .line 159
    .line 160
    iget-object v0, p1, Lu/y;->o:Lu/p0;

    .line 161
    .line 162
    iget-object p0, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast p0, Lu/p0;

    .line 165
    .line 166
    if-ne v0, p0, :cond_5

    .line 167
    .line 168
    invoke-virtual {p1}, Lu/y;->F()V

    .line 169
    .line 170
    .line 171
    :cond_5
    :goto_0
    return-void

    .line 172
    nop

    .line 173
    :pswitch_data_0
    .packed-switch 0x18
        :pswitch_0
    .end packed-switch
.end method
