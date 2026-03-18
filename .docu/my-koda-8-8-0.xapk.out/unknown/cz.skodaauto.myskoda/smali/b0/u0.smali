.class public final Lb0/u0;
.super Lb0/z1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final y:Lb0/r0;


# instance fields
.field public final p:I

.field public final q:Ljava/util/concurrent/atomic/AtomicReference;

.field public final r:I

.field public final s:Ll0/i;

.field public t:Lh0/v1;

.field public u:Lcom/google/firebase/messaging/w;

.field public v:Lg0/e;

.field public w:Lh0/w1;

.field public final x:Let/d;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lb0/r0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lb0/u0;->y:Lb0/r0;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Lh0/y0;)V
    .locals 3

    .line 1
    invoke-direct {p0, p1}, Lb0/z1;-><init>(Lh0/o2;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lb0/u0;->q:Ljava/util/concurrent/atomic/AtomicReference;

    .line 11
    .line 12
    const/4 p1, -0x1

    .line 13
    iput p1, p0, Lb0/u0;->r:I

    .line 14
    .line 15
    new-instance p1, Let/d;

    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    invoke-direct {p1, p0, v1}, Let/d;-><init>(Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lb0/u0;->x:Let/d;

    .line 22
    .line 23
    iget-object p1, p0, Lb0/z1;->g:Lh0/o2;

    .line 24
    .line 25
    check-cast p1, Lh0/y0;

    .line 26
    .line 27
    sget-object v1, Lh0/y0;->e:Lh0/g;

    .line 28
    .line 29
    invoke-interface {p1, v1}, Lh0/t1;->j(Lh0/g;)Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_0

    .line 34
    .line 35
    invoke-interface {p1, v1}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    check-cast v1, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    iput v1, p0, Lb0/u0;->p:I

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    const/4 v1, 0x1

    .line 49
    iput v1, p0, Lb0/u0;->p:I

    .line 50
    .line 51
    :goto_0
    sget-object v1, Lh0/y0;->k:Lh0/g;

    .line 52
    .line 53
    const/4 v2, 0x0

    .line 54
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    invoke-interface {p1, v1, v2}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    check-cast v1, Ljava/lang/Integer;

    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    sget-object v1, Lh0/y0;->l:Lh0/g;

    .line 68
    .line 69
    invoke-interface {p1, v1, v0}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    check-cast p1, Lb0/s0;

    .line 74
    .line 75
    new-instance v0, Ll0/i;

    .line 76
    .line 77
    invoke-direct {v0, p1}, Ll0/i;-><init>(Lb0/s0;)V

    .line 78
    .line 79
    .line 80
    iput-object v0, p0, Lb0/u0;->s:Ll0/i;

    .line 81
    .line 82
    return-void
.end method

.method public static G(ILjava/util/List;)Z
    .locals 2

    .line 1
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Landroid/util/Pair;

    .line 16
    .line 17
    iget-object v0, v0, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    const/4 p0, 0x1

    .line 32
    return p0

    .line 33
    :cond_1
    const/4 p0, 0x0

    .line 34
    return p0
.end method


# virtual methods
.method public final D(Z)V
    .locals 2

    .line 1
    const-string v0, "ImageCapture"

    .line 2
    .line 3
    const-string v1, "clearPipeline"

    .line 4
    .line 5
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 6
    .line 7
    .line 8
    invoke-static {}, Llp/k1;->a()V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lb0/u0;->w:Lh0/w1;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {v0}, Lh0/w1;->b()V

    .line 17
    .line 18
    .line 19
    iput-object v1, p0, Lb0/u0;->w:Lh0/w1;

    .line 20
    .line 21
    :cond_0
    iget-object v0, p0, Lb0/u0;->u:Lcom/google/firebase/messaging/w;

    .line 22
    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    invoke-virtual {v0}, Lcom/google/firebase/messaging/w;->d()V

    .line 26
    .line 27
    .line 28
    iput-object v1, p0, Lb0/u0;->u:Lcom/google/firebase/messaging/w;

    .line 29
    .line 30
    :cond_1
    if-nez p1, :cond_2

    .line 31
    .line 32
    iget-object p1, p0, Lb0/u0;->v:Lg0/e;

    .line 33
    .line 34
    if-eqz p1, :cond_2

    .line 35
    .line 36
    invoke-virtual {p1}, Lg0/e;->b()V

    .line 37
    .line 38
    .line 39
    iput-object v1, p0, Lb0/u0;->v:Lg0/e;

    .line 40
    .line 41
    :cond_2
    invoke-virtual {p0}, Lb0/z1;->d()Lh0/y;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-interface {p0}, Lh0/y;->d()V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public final E(Ljava/lang/String;Lh0/y0;Lh0/k;)Lh0/v1;
    .locals 12

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    invoke-static {}, Llp/k1;->a()V

    .line 7
    .line 8
    .line 9
    const-string v2, "ImageCapture"

    .line 10
    .line 11
    new-instance v3, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v4, "createPipeline(cameraId: "

    .line 14
    .line 15
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string p1, ", streamSpec: "

    .line 22
    .line 23
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v3, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string p1, ")"

    .line 30
    .line 31
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-static {v2, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 39
    .line 40
    .line 41
    iget-object p1, p3, Lh0/k;->a:Landroid/util/Size;

    .line 42
    .line 43
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    invoke-interface {v2}, Lh0/b0;->p()Z

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    const/4 v3, 0x1

    .line 55
    xor-int/2addr v2, v3

    .line 56
    iget-object v4, p0, Lb0/u0;->u:Lcom/google/firebase/messaging/w;

    .line 57
    .line 58
    const/4 v5, 0x0

    .line 59
    if-eqz v4, :cond_0

    .line 60
    .line 61
    invoke-static {v5, v2}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 62
    .line 63
    .line 64
    iget-object v4, p0, Lb0/u0;->u:Lcom/google/firebase/messaging/w;

    .line 65
    .line 66
    invoke-virtual {v4}, Lcom/google/firebase/messaging/w;->d()V

    .line 67
    .line 68
    .line 69
    :cond_0
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    invoke-interface {v4}, Lh0/b0;->a()Lh0/z;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    const/4 v6, 0x3

    .line 78
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 79
    .line 80
    .line 81
    move-result-object v6

    .line 82
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 83
    .line 84
    .line 85
    move-result-object v7

    .line 86
    instance-of v8, v4, Lh0/c;

    .line 87
    .line 88
    const/16 v9, 0x1005

    .line 89
    .line 90
    if-nez v8, :cond_2

    .line 91
    .line 92
    :cond_1
    :goto_0
    move-object v11, v5

    .line 93
    goto :goto_1

    .line 94
    :cond_2
    move-object v8, v4

    .line 95
    check-cast v8, Lh0/c;

    .line 96
    .line 97
    iget-object v8, v8, Lh0/c;->c:Lh0/t;

    .line 98
    .line 99
    sget-object v10, Lh0/t;->x0:Lh0/g;

    .line 100
    .line 101
    sget-object v11, Lh0/r2;->a:Lh0/p2;

    .line 102
    .line 103
    invoke-interface {v8, v10, v11}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v8

    .line 107
    check-cast v8, Lh0/r2;

    .line 108
    .line 109
    sget-object v10, Lh0/q2;->d:Lh0/q2;

    .line 110
    .line 111
    invoke-interface {v8, v10, v3}, Lh0/r2;->a(Lh0/q2;I)Lh0/q0;

    .line 112
    .line 113
    .line 114
    move-result-object v8

    .line 115
    if-eqz v8, :cond_1

    .line 116
    .line 117
    sget-object v10, Lh0/a1;->M0:Lh0/g;

    .line 118
    .line 119
    check-cast v8, Lh0/n1;

    .line 120
    .line 121
    iget-object v11, v8, Lh0/n1;->d:Ljava/util/TreeMap;

    .line 122
    .line 123
    invoke-virtual {v11, v10}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v11

    .line 127
    if-nez v11, :cond_3

    .line 128
    .line 129
    goto :goto_0

    .line 130
    :cond_3
    new-instance v11, Ljava/util/HashSet;

    .line 131
    .line 132
    invoke-direct {v11}, Ljava/util/HashSet;-><init>()V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v11, v1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    invoke-virtual {v8, v10}, Lh0/n1;->f(Lh0/g;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v8

    .line 142
    check-cast v8, Ljava/util/List;

    .line 143
    .line 144
    invoke-interface {v8}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 145
    .line 146
    .line 147
    move-result-object v8

    .line 148
    :cond_4
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 149
    .line 150
    .line 151
    move-result v10

    .line 152
    if-eqz v10, :cond_5

    .line 153
    .line 154
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v10

    .line 158
    check-cast v10, Landroid/util/Pair;

    .line 159
    .line 160
    iget-object v10, v10, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast v10, Ljava/lang/Integer;

    .line 163
    .line 164
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 165
    .line 166
    .line 167
    move-result v10

    .line 168
    if-ne v10, v9, :cond_4

    .line 169
    .line 170
    invoke-virtual {v11, v7}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    :cond_5
    :goto_1
    const/4 v8, 0x2

    .line 174
    if-eqz v11, :cond_6

    .line 175
    .line 176
    goto :goto_4

    .line 177
    :cond_6
    new-instance v11, Ljava/util/HashSet;

    .line 178
    .line 179
    invoke-direct {v11}, Ljava/util/HashSet;-><init>()V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v11, v1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    if-eqz v4, :cond_7

    .line 186
    .line 187
    move-object v10, v4

    .line 188
    check-cast v10, Lh0/z;

    .line 189
    .line 190
    invoke-interface {v10}, Lh0/z;->s()Ljava/util/Set;

    .line 191
    .line 192
    .line 193
    move-result-object v10

    .line 194
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 195
    .line 196
    .line 197
    move-result-object v9

    .line 198
    invoke-interface {v10, v9}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    move-result v9

    .line 202
    goto :goto_2

    .line 203
    :cond_7
    move v9, v0

    .line 204
    :goto_2
    if-eqz v9, :cond_8

    .line 205
    .line 206
    invoke-virtual {v11, v7}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    :cond_8
    if-eqz v4, :cond_9

    .line 210
    .line 211
    check-cast v4, Lh0/z;

    .line 212
    .line 213
    invoke-interface {v4}, Lh0/z;->m()Ljava/util/Set;

    .line 214
    .line 215
    .line 216
    move-result-object v7

    .line 217
    invoke-interface {v7, v6}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    move-result v7

    .line 221
    if-nez v7, :cond_a

    .line 222
    .line 223
    :cond_9
    move v4, v0

    .line 224
    goto :goto_3

    .line 225
    :cond_a
    invoke-interface {v4}, Lh0/z;->s()Ljava/util/Set;

    .line 226
    .line 227
    .line 228
    move-result-object v4

    .line 229
    const/16 v7, 0x20

    .line 230
    .line 231
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 232
    .line 233
    .line 234
    move-result-object v7

    .line 235
    invoke-interface {v4, v7}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 236
    .line 237
    .line 238
    move-result v4

    .line 239
    :goto_3
    if-eqz v4, :cond_b

    .line 240
    .line 241
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 242
    .line 243
    .line 244
    move-result-object v4

    .line 245
    invoke-virtual {v11, v4}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    invoke-virtual {v11, v6}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 249
    .line 250
    .line 251
    :cond_b
    :goto_4
    iget-object v4, p0, Lb0/z1;->g:Lh0/o2;

    .line 252
    .line 253
    sget-object v6, Lh0/y0;->h:Lh0/g;

    .line 254
    .line 255
    invoke-interface {v4, v6, v1}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v4

    .line 259
    check-cast v4, Ljava/lang/Integer;

    .line 260
    .line 261
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 262
    .line 263
    .line 264
    invoke-interface {v11, v4}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    move-result v4

    .line 268
    new-instance v7, Ljava/lang/StringBuilder;

    .line 269
    .line 270
    const-string v9, "The specified output format ("

    .line 271
    .line 272
    invoke-direct {v7, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    iget-object v9, p0, Lb0/z1;->g:Lh0/o2;

    .line 276
    .line 277
    invoke-interface {v9, v6, v1}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v1

    .line 281
    check-cast v1, Ljava/lang/Integer;

    .line 282
    .line 283
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 284
    .line 285
    .line 286
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 287
    .line 288
    .line 289
    move-result v1

    .line 290
    invoke-virtual {v7, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 291
    .line 292
    .line 293
    const-string v1, ") is not supported by current configuration. Supported output formats: "

    .line 294
    .line 295
    invoke-virtual {v7, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 296
    .line 297
    .line 298
    invoke-virtual {v7, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 299
    .line 300
    .line 301
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 302
    .line 303
    .line 304
    move-result-object v1

    .line 305
    invoke-static {v4, v1}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 306
    .line 307
    .line 308
    iget-object v1, p0, Lb0/z1;->g:Lh0/o2;

    .line 309
    .line 310
    sget-object v4, Lh0/y0;->m:Lh0/g;

    .line 311
    .line 312
    sget-object v6, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 313
    .line 314
    invoke-interface {v1, v4, v6}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object v1

    .line 318
    check-cast v1, Ljava/lang/Boolean;

    .line 319
    .line 320
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 321
    .line 322
    .line 323
    move-result v1

    .line 324
    if-eqz v1, :cond_c

    .line 325
    .line 326
    invoke-virtual {p2}, Lh0/y0;->l()I

    .line 327
    .line 328
    .line 329
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 330
    .line 331
    .line 332
    move-result-object v1

    .line 333
    invoke-interface {v1}, Lh0/b0;->h()Lh0/t;

    .line 334
    .line 335
    .line 336
    move-result-object v1

    .line 337
    invoke-interface {v1}, Lh0/t;->r()V

    .line 338
    .line 339
    .line 340
    :cond_c
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 341
    .line 342
    .line 343
    move-result-object v1

    .line 344
    if-eqz v1, :cond_d

    .line 345
    .line 346
    :try_start_0
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 347
    .line 348
    .line 349
    move-result-object v1

    .line 350
    invoke-interface {v1}, Lh0/b0;->l()Lh0/z;

    .line 351
    .line 352
    .line 353
    move-result-object v1

    .line 354
    invoke-interface {v1}, Lh0/z;->i()Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v1

    .line 358
    instance-of v4, v1, Landroid/hardware/camera2/CameraCharacteristics;

    .line 359
    .line 360
    if-eqz v4, :cond_d

    .line 361
    .line 362
    check-cast v1, Landroid/hardware/camera2/CameraCharacteristics;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 363
    .line 364
    move-object v5, v1

    .line 365
    goto :goto_5

    .line 366
    :catch_0
    move-exception v1

    .line 367
    const-string v4, "ImageCapture"

    .line 368
    .line 369
    const-string v6, "getCameraCharacteristics failed"

    .line 370
    .line 371
    invoke-static {v4, v6, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 372
    .line 373
    .line 374
    :cond_d
    :goto_5
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 375
    .line 376
    invoke-direct {v1, p2, p1, v5, v2}, Lcom/google/firebase/messaging/w;-><init>(Lh0/y0;Landroid/util/Size;Landroid/hardware/camera2/CameraCharacteristics;Z)V

    .line 377
    .line 378
    .line 379
    iput-object v1, p0, Lb0/u0;->u:Lcom/google/firebase/messaging/w;

    .line 380
    .line 381
    iget-object p1, p0, Lb0/u0;->v:Lg0/e;

    .line 382
    .line 383
    if-nez p1, :cond_e

    .line 384
    .line 385
    iget-object p1, p0, Lb0/z1;->g:Lh0/o2;

    .line 386
    .line 387
    sget-object p2, Lh0/o2;->c1:Lh0/g;

    .line 388
    .line 389
    new-instance v1, Lh0/m2;

    .line 390
    .line 391
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 392
    .line 393
    .line 394
    invoke-interface {p1, p2, v1}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 395
    .line 396
    .line 397
    move-result-object p1

    .line 398
    check-cast p1, Lh0/m2;

    .line 399
    .line 400
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    iget-object p1, p0, Lb0/u0;->x:Let/d;

    .line 404
    .line 405
    new-instance p2, Lg0/e;

    .line 406
    .line 407
    invoke-direct {p2, p1}, Lg0/e;-><init>(Let/d;)V

    .line 408
    .line 409
    .line 410
    iput-object p2, p0, Lb0/u0;->v:Lg0/e;

    .line 411
    .line 412
    :cond_e
    iget-object p1, p0, Lb0/u0;->v:Lg0/e;

    .line 413
    .line 414
    iget-object p2, p0, Lb0/u0;->u:Lcom/google/firebase/messaging/w;

    .line 415
    .line 416
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 417
    .line 418
    .line 419
    invoke-static {}, Llp/k1;->a()V

    .line 420
    .line 421
    .line 422
    iput-object p2, p1, Lg0/e;->e:Lcom/google/firebase/messaging/w;

    .line 423
    .line 424
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 425
    .line 426
    .line 427
    invoke-static {}, Llp/k1;->a()V

    .line 428
    .line 429
    .line 430
    iget-object p2, p2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 431
    .line 432
    check-cast p2, Lgw0/c;

    .line 433
    .line 434
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 435
    .line 436
    .line 437
    invoke-static {}, Llp/k1;->a()V

    .line 438
    .line 439
    .line 440
    iget-object v1, p2, Lgw0/c;->e:Ljava/lang/Object;

    .line 441
    .line 442
    check-cast v1, Lb0/n1;

    .line 443
    .line 444
    if-eqz v1, :cond_f

    .line 445
    .line 446
    move v0, v3

    .line 447
    :cond_f
    const-string v1, "The ImageReader is not initialized."

    .line 448
    .line 449
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 450
    .line 451
    .line 452
    iget-object p2, p2, Lgw0/c;->e:Ljava/lang/Object;

    .line 453
    .line 454
    check-cast p2, Lb0/n1;

    .line 455
    .line 456
    iget-object v0, p2, Lb0/n1;->f:Ljava/lang/Object;

    .line 457
    .line 458
    monitor-enter v0

    .line 459
    :try_start_1
    iput-object p1, p2, Lb0/n1;->i:Ljava/lang/Object;

    .line 460
    .line 461
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 462
    iget-object p1, p0, Lb0/u0;->u:Lcom/google/firebase/messaging/w;

    .line 463
    .line 464
    iget-object p2, p3, Lh0/k;->a:Landroid/util/Size;

    .line 465
    .line 466
    iget-object v0, p1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 467
    .line 468
    check-cast v0, Lh0/y0;

    .line 469
    .line 470
    invoke-static {v0, p2}, Lh0/v1;->d(Lh0/o2;Landroid/util/Size;)Lh0/v1;

    .line 471
    .line 472
    .line 473
    move-result-object p2

    .line 474
    iget-object p1, p1, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 475
    .line 476
    check-cast p1, Lg0/a;

    .line 477
    .line 478
    iget-object v0, p1, Lg0/a;->a:Lb0/u1;

    .line 479
    .line 480
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    sget-object v1, Lb0/y;->d:Lb0/y;

    .line 484
    .line 485
    invoke-static {v0}, Lh0/i;->a(Lh0/t0;)Landroidx/lifecycle/c1;

    .line 486
    .line 487
    .line 488
    move-result-object v0

    .line 489
    iput-object v1, v0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 490
    .line 491
    invoke-virtual {v0}, Landroidx/lifecycle/c1;->h()Lh0/i;

    .line 492
    .line 493
    .line 494
    move-result-object v0

    .line 495
    iget-object v2, p2, Lh0/u1;->a:Ljava/util/LinkedHashSet;

    .line 496
    .line 497
    invoke-interface {v2, v0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 498
    .line 499
    .line 500
    iget-object v0, p1, Lg0/a;->f:Ljava/util/ArrayList;

    .line 501
    .line 502
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 503
    .line 504
    .line 505
    move-result v0

    .line 506
    if-le v0, v3, :cond_10

    .line 507
    .line 508
    iget-object v0, p1, Lg0/a;->b:Lb0/u1;

    .line 509
    .line 510
    if-eqz v0, :cond_10

    .line 511
    .line 512
    invoke-static {v0}, Lh0/i;->a(Lh0/t0;)Landroidx/lifecycle/c1;

    .line 513
    .line 514
    .line 515
    move-result-object v0

    .line 516
    iput-object v1, v0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 517
    .line 518
    invoke-virtual {v0}, Landroidx/lifecycle/c1;->h()Lh0/i;

    .line 519
    .line 520
    .line 521
    move-result-object v0

    .line 522
    iget-object v1, p2, Lh0/u1;->a:Ljava/util/LinkedHashSet;

    .line 523
    .line 524
    invoke-interface {v1, v0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 525
    .line 526
    .line 527
    :cond_10
    iget-object p1, p1, Lg0/a;->c:Lb0/u1;

    .line 528
    .line 529
    if-eqz p1, :cond_11

    .line 530
    .line 531
    invoke-static {p1}, Lh0/i;->a(Lh0/t0;)Landroidx/lifecycle/c1;

    .line 532
    .line 533
    .line 534
    move-result-object p1

    .line 535
    invoke-virtual {p1}, Landroidx/lifecycle/c1;->h()Lh0/i;

    .line 536
    .line 537
    .line 538
    move-result-object p1

    .line 539
    iput-object p1, p2, Lh0/u1;->i:Lh0/i;

    .line 540
    .line 541
    :cond_11
    iget p1, p3, Lh0/k;->d:I

    .line 542
    .line 543
    iput p1, p2, Lh0/u1;->h:I

    .line 544
    .line 545
    iget p1, p0, Lb0/u0;->p:I

    .line 546
    .line 547
    if-ne p1, v8, :cond_12

    .line 548
    .line 549
    iget-boolean p1, p3, Lh0/k;->g:Z

    .line 550
    .line 551
    if-nez p1, :cond_12

    .line 552
    .line 553
    invoke-virtual {p0}, Lb0/z1;->d()Lh0/y;

    .line 554
    .line 555
    .line 556
    move-result-object p1

    .line 557
    invoke-interface {p1, p2}, Lh0/y;->a(Lh0/v1;)V

    .line 558
    .line 559
    .line 560
    :cond_12
    iget-object p1, p3, Lh0/k;->f:Lh0/q0;

    .line 561
    .line 562
    if-eqz p1, :cond_13

    .line 563
    .line 564
    iget-object p3, p2, Lh0/u1;->b:Lb0/n1;

    .line 565
    .line 566
    invoke-virtual {p3, p1}, Lb0/n1;->i(Lh0/q0;)V

    .line 567
    .line 568
    .line 569
    :cond_13
    iget-object p1, p0, Lb0/u0;->w:Lh0/w1;

    .line 570
    .line 571
    if-eqz p1, :cond_14

    .line 572
    .line 573
    invoke-virtual {p1}, Lh0/w1;->b()V

    .line 574
    .line 575
    .line 576
    :cond_14
    new-instance p1, Lh0/w1;

    .line 577
    .line 578
    new-instance p3, Lb0/q0;

    .line 579
    .line 580
    const/4 v0, 0x0

    .line 581
    invoke-direct {p3, p0, v0}, Lb0/q0;-><init>(Ljava/lang/Object;I)V

    .line 582
    .line 583
    .line 584
    invoke-direct {p1, p3}, Lh0/w1;-><init>(Lh0/x1;)V

    .line 585
    .line 586
    .line 587
    iput-object p1, p0, Lb0/u0;->w:Lh0/w1;

    .line 588
    .line 589
    iput-object p1, p2, Lh0/u1;->f:Lh0/w1;

    .line 590
    .line 591
    return-object p2

    .line 592
    :catchall_0
    move-exception p0

    .line 593
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 594
    throw p0
.end method

.method public final F()I
    .locals 3

    .line 1
    iget-object v0, p0, Lb0/u0;->q:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget v1, p0, Lb0/u0;->r:I

    .line 5
    .line 6
    const/4 v2, -0x1

    .line 7
    if-eq v1, v2, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-object p0, p0, Lb0/z1;->g:Lh0/o2;

    .line 11
    .line 12
    check-cast p0, Lh0/y0;

    .line 13
    .line 14
    sget-object v1, Lh0/y0;->f:Lh0/g;

    .line 15
    .line 16
    const/4 v2, 0x2

    .line 17
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    invoke-interface {p0, v1, v2}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ljava/lang/Integer;

    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    :goto_0
    monitor-exit v0

    .line 32
    return v1

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    throw p0
.end method

.method public final f(ZLh0/r2;)Lh0/o2;
    .locals 3

    .line 1
    sget-object v0, Lb0/u0;->y:Lb0/r0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    sget-object v0, Lb0/r0;->a:Lh0/y0;

    .line 7
    .line 8
    invoke-interface {v0}, Lh0/o2;->J()Lh0/q2;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    iget v2, p0, Lb0/u0;->p:I

    .line 13
    .line 14
    invoke-interface {p2, v1, v2}, Lh0/r2;->a(Lh0/q2;I)Lh0/q0;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    invoke-static {p2, v0}, Lh0/q0;->w(Lh0/q0;Lh0/q0;)Lh0/n1;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    :cond_0
    if-nez p2, :cond_1

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    return-object p0

    .line 28
    :cond_1
    invoke-virtual {p0, p2}, Lb0/u0;->l(Lh0/q0;)Lh0/n2;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    check-cast p0, Lb0/f0;

    .line 33
    .line 34
    new-instance p1, Lh0/y0;

    .line 35
    .line 36
    iget-object p0, p0, Lb0/f0;->b:Lh0/j1;

    .line 37
    .line 38
    invoke-static {p0}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-direct {p1, p0}, Lh0/y0;-><init>(Lh0/n1;)V

    .line 43
    .line 44
    .line 45
    return-object p1
.end method

.method public final k()Ljava/util/Set;
    .locals 1

    .line 1
    new-instance p0, Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/HashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x4

    .line 7
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {p0, v0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final l(Lh0/q0;)Lh0/n2;
    .locals 1

    .line 1
    new-instance p0, Lb0/f0;

    .line 2
    .line 3
    invoke-static {p1}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v0, 0x1

    .line 8
    invoke-direct {p0, p1, v0}, Lb0/f0;-><init>(Lh0/j1;I)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public final r()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "Attached camera cannot be null"

    .line 6
    .line 7
    invoke-static {v0, v1}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lb0/u0;->F()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const/4 v1, 0x3

    .line 15
    if-ne v0, v1, :cond_2

    .line 16
    .line 17
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    invoke-interface {p0}, Lb0/k;->a()Lh0/z;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-interface {p0}, Lh0/z;->h()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 p0, -0x1

    .line 33
    :goto_0
    if-nez p0, :cond_1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 37
    .line 38
    const-string v0, "Not a front camera despite setting FLASH_MODE_SCREEN in ImageCapture"

    .line 39
    .line 40
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_2
    :goto_1
    return-void
.end method

.method public final s()V
    .locals 3

    .line 1
    const-string v0, "ImageCapture"

    .line 2
    .line 3
    const-string v1, "onCameraControlReady"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lb0/u0;->q:Ljava/util/concurrent/atomic/AtomicReference;

    .line 9
    .line 10
    monitor-enter v0

    .line 11
    :try_start_0
    iget-object v1, p0, Lb0/u0;->q:Ljava/util/concurrent/atomic/AtomicReference;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    monitor-exit v0

    .line 20
    goto :goto_0

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    goto :goto_1

    .line 23
    :cond_0
    invoke-virtual {p0}, Lb0/z1;->d()Lh0/y;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-virtual {p0}, Lb0/u0;->F()I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    invoke-interface {v1, v2}, Lh0/y;->b(I)V

    .line 32
    .line 33
    .line 34
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    :goto_0
    iget-object v0, p0, Lb0/u0;->s:Ll0/i;

    .line 36
    .line 37
    invoke-virtual {p0}, Lb0/z1;->d()Lh0/y;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-interface {p0, v0}, Lh0/y;->e(Lb0/s0;)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 46
    throw p0
.end method

.method public final t(Lh0/z;Lh0/n2;)Lh0/o2;
    .locals 13

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/16 v1, 0x23

    .line 8
    .line 9
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    const/16 v3, 0x100

    .line 14
    .line 15
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    iget-object v5, p0, Lb0/z1;->f:Ljava/util/HashSet;

    .line 20
    .line 21
    const/4 v6, 0x0

    .line 22
    if-eqz v5, :cond_2

    .line 23
    .line 24
    invoke-interface {v5}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object v5

    .line 28
    move v7, v6

    .line 29
    :cond_0
    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v8

    .line 33
    if-eqz v8, :cond_1

    .line 34
    .line 35
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v8

    .line 39
    check-cast v8, Lc0/a;

    .line 40
    .line 41
    instance-of v9, v8, Le0/d;

    .line 42
    .line 43
    if-eqz v9, :cond_0

    .line 44
    .line 45
    check-cast v8, Le0/d;

    .line 46
    .line 47
    iget v7, v8, Le0/d;->a:I

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    sget-object v8, Lh0/y0;->h:Lh0/g;

    .line 55
    .line 56
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 57
    .line 58
    .line 59
    move-result-object v7

    .line 60
    check-cast v5, Lh0/j1;

    .line 61
    .line 62
    invoke-virtual {v5, v8, v7}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    :cond_2
    invoke-interface {p1}, Lh0/z;->j()Ld01/x;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    const-class v5, Landroidx/camera/core/internal/compat/quirk/SoftwareJpegEncodingPreferredQuirk;

    .line 70
    .line 71
    invoke-virtual {p1, v5}, Ld01/x;->k(Ljava/lang/Class;)Z

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    const-string v5, "ImageCapture"

    .line 76
    .line 77
    if-eqz p1, :cond_4

    .line 78
    .line 79
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 80
    .line 81
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    sget-object v8, Lh0/y0;->j:Lh0/g;

    .line 86
    .line 87
    sget-object v9, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 88
    .line 89
    check-cast v7, Lh0/n1;

    .line 90
    .line 91
    invoke-virtual {v7, v8, v9}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v7

    .line 95
    invoke-virtual {p1, v7}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result p1

    .line 99
    if-eqz p1, :cond_3

    .line 100
    .line 101
    const-string p1, "Device quirk suggests software JPEG encoder, but it has been explicitly disabled."

    .line 102
    .line 103
    invoke-static {v5, p1}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_3
    const-string p1, "Requesting software JPEG due to device quirk."

    .line 108
    .line 109
    invoke-static {v5, p1}, Ljp/v1;->g(Ljava/lang/String;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    check-cast p1, Lh0/j1;

    .line 117
    .line 118
    invoke-virtual {p1, v8, v9}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    :cond_4
    :goto_1
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    sget-object v7, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 126
    .line 127
    sget-object v8, Lh0/y0;->j:Lh0/g;

    .line 128
    .line 129
    sget-object v9, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 130
    .line 131
    move-object v10, p1

    .line 132
    check-cast v10, Lh0/n1;

    .line 133
    .line 134
    invoke-virtual {v10, v8, v9}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v11

    .line 138
    invoke-virtual {v7, v11}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v7

    .line 142
    const/4 v11, 0x1

    .line 143
    const/4 v12, 0x0

    .line 144
    if-eqz v7, :cond_7

    .line 145
    .line 146
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 147
    .line 148
    .line 149
    move-result-object v7

    .line 150
    if-nez v7, :cond_5

    .line 151
    .line 152
    goto :goto_2

    .line 153
    :cond_5
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 154
    .line 155
    .line 156
    move-result-object v7

    .line 157
    invoke-interface {v7}, Lh0/b0;->h()Lh0/t;

    .line 158
    .line 159
    .line 160
    move-result-object v7

    .line 161
    invoke-interface {v7}, Lh0/t;->r()V

    .line 162
    .line 163
    .line 164
    :goto_2
    sget-object v7, Lh0/y0;->g:Lh0/g;

    .line 165
    .line 166
    invoke-virtual {v10, v7, v12}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v7

    .line 170
    check-cast v7, Ljava/lang/Integer;

    .line 171
    .line 172
    if-eqz v7, :cond_6

    .line 173
    .line 174
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 175
    .line 176
    .line 177
    move-result v7

    .line 178
    if-eq v7, v3, :cond_6

    .line 179
    .line 180
    const-string v7, "Software JPEG cannot be used with non-JPEG output buffer format."

    .line 181
    .line 182
    invoke-static {v5, v7}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    goto :goto_3

    .line 186
    :cond_6
    move v6, v11

    .line 187
    :goto_3
    if-nez v6, :cond_7

    .line 188
    .line 189
    const-string v7, "Unable to support software JPEG. Disabling."

    .line 190
    .line 191
    invoke-static {v5, v7}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    check-cast p1, Lh0/j1;

    .line 195
    .line 196
    invoke-virtual {p1, v8, v9}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    :cond_7
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    sget-object v5, Lh0/y0;->g:Lh0/g;

    .line 204
    .line 205
    check-cast p1, Lh0/n1;

    .line 206
    .line 207
    invoke-virtual {p1, v5, v12}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object p1

    .line 211
    check-cast p1, Ljava/lang/Integer;

    .line 212
    .line 213
    if-eqz p1, :cond_a

    .line 214
    .line 215
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 216
    .line 217
    .line 218
    move-result-object v0

    .line 219
    if-nez v0, :cond_8

    .line 220
    .line 221
    goto :goto_4

    .line 222
    :cond_8
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    invoke-interface {p0}, Lh0/b0;->h()Lh0/t;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    invoke-interface {p0}, Lh0/t;->r()V

    .line 231
    .line 232
    .line 233
    :goto_4
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    sget-object v0, Lh0/z0;->C0:Lh0/g;

    .line 238
    .line 239
    if-eqz v6, :cond_9

    .line 240
    .line 241
    goto :goto_5

    .line 242
    :cond_9
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 243
    .line 244
    .line 245
    move-result v1

    .line 246
    :goto_5
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 247
    .line 248
    .line 249
    move-result-object p1

    .line 250
    check-cast p0, Lh0/j1;

    .line 251
    .line 252
    invoke-virtual {p0, v0, p1}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 253
    .line 254
    .line 255
    goto/16 :goto_6

    .line 256
    .line 257
    :cond_a
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 258
    .line 259
    .line 260
    move-result-object p0

    .line 261
    sget-object p1, Lh0/y0;->h:Lh0/g;

    .line 262
    .line 263
    check-cast p0, Lh0/n1;

    .line 264
    .line 265
    invoke-virtual {p0, p1, v12}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object p0

    .line 269
    const/4 v5, 0x2

    .line 270
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 271
    .line 272
    .line 273
    move-result-object v5

    .line 274
    invoke-static {p0, v5}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 275
    .line 276
    .line 277
    move-result p0

    .line 278
    if-eqz p0, :cond_b

    .line 279
    .line 280
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 281
    .line 282
    .line 283
    move-result-object p0

    .line 284
    sget-object p1, Lh0/z0;->C0:Lh0/g;

    .line 285
    .line 286
    check-cast p0, Lh0/j1;

    .line 287
    .line 288
    invoke-virtual {p0, p1, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    goto/16 :goto_6

    .line 292
    .line 293
    :cond_b
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 294
    .line 295
    .line 296
    move-result-object p0

    .line 297
    check-cast p0, Lh0/n1;

    .line 298
    .line 299
    invoke-virtual {p0, p1, v12}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    move-result-object p0

    .line 303
    const/4 v5, 0x3

    .line 304
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 305
    .line 306
    .line 307
    move-result-object v5

    .line 308
    invoke-static {p0, v5}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 309
    .line 310
    .line 311
    move-result p0

    .line 312
    if-eqz p0, :cond_c

    .line 313
    .line 314
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 315
    .line 316
    .line 317
    move-result-object p0

    .line 318
    sget-object p1, Lh0/z0;->C0:Lh0/g;

    .line 319
    .line 320
    check-cast p0, Lh0/j1;

    .line 321
    .line 322
    invoke-virtual {p0, p1, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 323
    .line 324
    .line 325
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 326
    .line 327
    .line 328
    move-result-object p0

    .line 329
    sget-object p1, Lh0/z0;->D0:Lh0/g;

    .line 330
    .line 331
    check-cast p0, Lh0/j1;

    .line 332
    .line 333
    invoke-virtual {p0, p1, v4}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 334
    .line 335
    .line 336
    goto/16 :goto_6

    .line 337
    .line 338
    :cond_c
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 339
    .line 340
    .line 341
    move-result-object p0

    .line 342
    check-cast p0, Lh0/n1;

    .line 343
    .line 344
    invoke-virtual {p0, p1, v12}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    move-result-object p0

    .line 348
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 349
    .line 350
    .line 351
    move-result-object p1

    .line 352
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 353
    .line 354
    .line 355
    move-result p0

    .line 356
    if-eqz p0, :cond_d

    .line 357
    .line 358
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 359
    .line 360
    .line 361
    move-result-object p0

    .line 362
    sget-object p1, Lh0/z0;->C0:Lh0/g;

    .line 363
    .line 364
    const/16 v0, 0x1005

    .line 365
    .line 366
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 367
    .line 368
    .line 369
    move-result-object v0

    .line 370
    check-cast p0, Lh0/j1;

    .line 371
    .line 372
    invoke-virtual {p0, p1, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 373
    .line 374
    .line 375
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 376
    .line 377
    .line 378
    move-result-object p0

    .line 379
    sget-object p1, Lh0/z0;->E0:Lh0/g;

    .line 380
    .line 381
    sget-object v0, Lb0/y;->c:Lb0/y;

    .line 382
    .line 383
    check-cast p0, Lh0/j1;

    .line 384
    .line 385
    invoke-virtual {p0, p1, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 386
    .line 387
    .line 388
    goto :goto_6

    .line 389
    :cond_d
    if-eqz v6, :cond_e

    .line 390
    .line 391
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 392
    .line 393
    .line 394
    move-result-object p0

    .line 395
    sget-object p1, Lh0/z0;->C0:Lh0/g;

    .line 396
    .line 397
    check-cast p0, Lh0/j1;

    .line 398
    .line 399
    invoke-virtual {p0, p1, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 400
    .line 401
    .line 402
    goto :goto_6

    .line 403
    :cond_e
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 404
    .line 405
    .line 406
    move-result-object p0

    .line 407
    sget-object p1, Lh0/a1;->M0:Lh0/g;

    .line 408
    .line 409
    check-cast p0, Lh0/n1;

    .line 410
    .line 411
    invoke-virtual {p0, p1, v12}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 412
    .line 413
    .line 414
    move-result-object p0

    .line 415
    check-cast p0, Ljava/util/List;

    .line 416
    .line 417
    if-nez p0, :cond_f

    .line 418
    .line 419
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 420
    .line 421
    .line 422
    move-result-object p0

    .line 423
    sget-object p1, Lh0/z0;->C0:Lh0/g;

    .line 424
    .line 425
    check-cast p0, Lh0/j1;

    .line 426
    .line 427
    invoke-virtual {p0, p1, v4}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 428
    .line 429
    .line 430
    goto :goto_6

    .line 431
    :cond_f
    invoke-static {v3, p0}, Lb0/u0;->G(ILjava/util/List;)Z

    .line 432
    .line 433
    .line 434
    move-result p1

    .line 435
    if-eqz p1, :cond_10

    .line 436
    .line 437
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 438
    .line 439
    .line 440
    move-result-object p0

    .line 441
    sget-object p1, Lh0/z0;->C0:Lh0/g;

    .line 442
    .line 443
    check-cast p0, Lh0/j1;

    .line 444
    .line 445
    invoke-virtual {p0, p1, v4}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 446
    .line 447
    .line 448
    goto :goto_6

    .line 449
    :cond_10
    invoke-static {v1, p0}, Lb0/u0;->G(ILjava/util/List;)Z

    .line 450
    .line 451
    .line 452
    move-result p0

    .line 453
    if-eqz p0, :cond_11

    .line 454
    .line 455
    invoke-interface {p2}, Lb0/z;->a()Lh0/i1;

    .line 456
    .line 457
    .line 458
    move-result-object p0

    .line 459
    sget-object p1, Lh0/z0;->C0:Lh0/g;

    .line 460
    .line 461
    check-cast p0, Lh0/j1;

    .line 462
    .line 463
    invoke-virtual {p0, p1, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 464
    .line 465
    .line 466
    :cond_11
    :goto_6
    invoke-interface {p2}, Lh0/n2;->b()Lh0/o2;

    .line 467
    .line 468
    .line 469
    move-result-object p0

    .line 470
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lb0/z1;->g()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "ImageCapture:"

    .line 6
    .line 7
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final v()V
    .locals 1

    .line 1
    iget-object v0, p0, Lb0/u0;->s:Ll0/i;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll0/i;->b()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Ll0/i;->a()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lb0/u0;->v:Lg0/e;

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Lg0/e;->b()V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method

.method public final w(Lh0/q0;)Lh0/k;
    .locals 3

    .line 1
    iget-object v0, p0, Lb0/u0;->t:Lh0/v1;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lh0/v1;->a(Lh0/q0;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lb0/u0;->t:Lh0/v1;

    .line 7
    .line 8
    invoke-virtual {v0}, Lh0/v1;->c()Lh0/z1;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    new-instance v1, Ljava/util/ArrayList;

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 20
    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    aget-object v0, v0, v2

    .line 24
    .line 25
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {p0, v0}, Lb0/z1;->C(Ljava/util/List;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lb0/z1;->h:Lh0/k;

    .line 39
    .line 40
    invoke-virtual {p0}, Lh0/k;->b()Lss/b;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    iput-object p1, p0, Lss/b;->j:Ljava/lang/Object;

    .line 45
    .line 46
    invoke-virtual {p0}, Lss/b;->c()Lh0/k;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0
.end method

.method public final x(Lh0/k;Lh0/k;)Lh0/k;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onSuggestedStreamSpecUpdated: primaryStreamSpec = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string v1, ", secondaryStreamSpec "

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    const-string v0, "ImageCapture"

    .line 24
    .line 25
    invoke-static {v0, p2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Lb0/z1;->e()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p2

    .line 32
    iget-object v0, p0, Lb0/z1;->g:Lh0/o2;

    .line 33
    .line 34
    check-cast v0, Lh0/y0;

    .line 35
    .line 36
    invoke-virtual {p0, p2, v0, p1}, Lb0/u0;->E(Ljava/lang/String;Lh0/y0;Lh0/k;)Lh0/v1;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    iput-object p2, p0, Lb0/u0;->t:Lh0/v1;

    .line 41
    .line 42
    invoke-virtual {p2}, Lh0/v1;->c()Lh0/z1;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    filled-new-array {p2}, [Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p2

    .line 50
    new-instance v0, Ljava/util/ArrayList;

    .line 51
    .line 52
    const/4 v1, 0x1

    .line 53
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 54
    .line 55
    .line 56
    const/4 v1, 0x0

    .line 57
    aget-object p2, p2, v1

    .line 58
    .line 59
    invoke-static {p2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    invoke-virtual {p0, p2}, Lb0/z1;->C(Ljava/util/List;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {p0}, Lb0/z1;->o()V

    .line 73
    .line 74
    .line 75
    return-object p1
.end method

.method public final y()V
    .locals 1

    .line 1
    iget-object v0, p0, Lb0/u0;->s:Ll0/i;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll0/i;->b()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Ll0/i;->a()V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lb0/u0;->v:Lg0/e;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0}, Lg0/e;->b()V

    .line 14
    .line 15
    .line 16
    :cond_0
    const/4 v0, 0x0

    .line 17
    invoke-virtual {p0, v0}, Lb0/u0;->D(Z)V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    invoke-virtual {p0}, Lb0/z1;->d()Lh0/y;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-interface {p0, v0}, Lh0/y;->e(Lb0/s0;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
