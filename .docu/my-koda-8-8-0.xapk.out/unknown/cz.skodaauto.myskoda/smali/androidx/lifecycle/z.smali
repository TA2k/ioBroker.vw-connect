.class public final Landroidx/lifecycle/z;
.super Landroidx/lifecycle/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Z

.field public c:Lo/a;

.field public d:Landroidx/lifecycle/q;

.field public final e:Ljava/lang/ref/WeakReference;

.field public f:I

.field public g:Z

.field public h:Z

.field public final i:Ljava/util/ArrayList;

.field public final j:Lyy0/c2;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/x;Z)V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p2, p0, Landroidx/lifecycle/z;->b:Z

    .line 5
    .line 6
    new-instance p2, Lo/a;

    .line 7
    .line 8
    invoke-direct {p2}, Lo/a;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p2, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 12
    .line 13
    sget-object p2, Landroidx/lifecycle/q;->e:Landroidx/lifecycle/q;

    .line 14
    .line 15
    iput-object p2, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 16
    .line 17
    new-instance v0, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Landroidx/lifecycle/z;->i:Ljava/util/ArrayList;

    .line 23
    .line 24
    new-instance v0, Ljava/lang/ref/WeakReference;

    .line 25
    .line 26
    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iput-object v0, p0, Landroidx/lifecycle/z;->e:Ljava/lang/ref/WeakReference;

    .line 30
    .line 31
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iput-object p1, p0, Landroidx/lifecycle/z;->j:Lyy0/c2;

    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public final a(Landroidx/lifecycle/w;)V
    .locals 8

    .line 1
    const-string v0, "observer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "addObserver"

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Landroidx/lifecycle/z;->f(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 12
    .line 13
    sget-object v1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 14
    .line 15
    if-ne v0, v1, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    sget-object v1, Landroidx/lifecycle/q;->e:Landroidx/lifecycle/q;

    .line 19
    .line 20
    :goto_0
    new-instance v0, Landroidx/lifecycle/y;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 23
    .line 24
    .line 25
    sget-object v2, Landroidx/lifecycle/b0;->a:Ljava/util/HashMap;

    .line 26
    .line 27
    instance-of v2, p1, Landroidx/lifecycle/v;

    .line 28
    .line 29
    instance-of v3, p1, Landroidx/lifecycle/f;

    .line 30
    .line 31
    const/4 v4, 0x0

    .line 32
    const/4 v5, 0x0

    .line 33
    const/4 v6, 0x1

    .line 34
    if-eqz v2, :cond_1

    .line 35
    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    new-instance v2, Landroidx/lifecycle/h;

    .line 39
    .line 40
    move-object v3, p1

    .line 41
    check-cast v3, Landroidx/lifecycle/f;

    .line 42
    .line 43
    move-object v7, p1

    .line 44
    check-cast v7, Landroidx/lifecycle/v;

    .line 45
    .line 46
    invoke-direct {v2, v3, v7}, Landroidx/lifecycle/h;-><init>(Landroidx/lifecycle/f;Landroidx/lifecycle/v;)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    if-eqz v3, :cond_2

    .line 51
    .line 52
    new-instance v2, Landroidx/lifecycle/h;

    .line 53
    .line 54
    move-object v3, p1

    .line 55
    check-cast v3, Landroidx/lifecycle/f;

    .line 56
    .line 57
    invoke-direct {v2, v3, v4}, Landroidx/lifecycle/h;-><init>(Landroidx/lifecycle/f;Landroidx/lifecycle/v;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_2
    if-eqz v2, :cond_3

    .line 62
    .line 63
    move-object v2, p1

    .line 64
    check-cast v2, Landroidx/lifecycle/v;

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    invoke-static {v2}, Landroidx/lifecycle/b0;->b(Ljava/lang/Class;)I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    const/4 v7, 0x2

    .line 76
    if-ne v3, v7, :cond_6

    .line 77
    .line 78
    sget-object v3, Landroidx/lifecycle/b0;->b:Ljava/util/HashMap;

    .line 79
    .line 80
    invoke-virtual {v3, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    check-cast v2, Ljava/util/List;

    .line 88
    .line 89
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    if-eq v3, v6, :cond_5

    .line 94
    .line 95
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    new-array v7, v3, [Landroidx/lifecycle/j;

    .line 100
    .line 101
    if-gtz v3, :cond_4

    .line 102
    .line 103
    new-instance v2, Landroidx/lifecycle/e;

    .line 104
    .line 105
    invoke-direct {v2, v7, v5}, Landroidx/lifecycle/e;-><init>(Ljava/lang/Object;I)V

    .line 106
    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_4
    invoke-interface {v2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    check-cast p0, Ljava/lang/reflect/Constructor;

    .line 114
    .line 115
    invoke-static {p0, p1}, Landroidx/lifecycle/b0;->a(Ljava/lang/reflect/Constructor;Landroidx/lifecycle/w;)V

    .line 116
    .line 117
    .line 118
    throw v4

    .line 119
    :cond_5
    invoke-interface {v2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    check-cast p0, Ljava/lang/reflect/Constructor;

    .line 124
    .line 125
    invoke-static {p0, p1}, Landroidx/lifecycle/b0;->a(Ljava/lang/reflect/Constructor;Landroidx/lifecycle/w;)V

    .line 126
    .line 127
    .line 128
    throw v4

    .line 129
    :cond_6
    new-instance v2, Landroidx/lifecycle/h;

    .line 130
    .line 131
    invoke-direct {v2, p1}, Landroidx/lifecycle/h;-><init>(Landroidx/lifecycle/w;)V

    .line 132
    .line 133
    .line 134
    :goto_1
    iput-object v2, v0, Landroidx/lifecycle/y;->b:Landroidx/lifecycle/v;

    .line 135
    .line 136
    iput-object v1, v0, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 137
    .line 138
    iget-object v1, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 139
    .line 140
    invoke-virtual {v1, p1}, Lo/a;->c(Ljava/lang/Object;)Lo/c;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    if-eqz v2, :cond_7

    .line 145
    .line 146
    iget-object v4, v2, Lo/c;->e:Ljava/lang/Object;

    .line 147
    .line 148
    goto :goto_3

    .line 149
    :cond_7
    iget-object v2, v1, Lo/a;->h:Ljava/util/HashMap;

    .line 150
    .line 151
    new-instance v3, Lo/c;

    .line 152
    .line 153
    invoke-direct {v3, p1, v0}, Lo/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    iget v7, v1, Lo/f;->g:I

    .line 157
    .line 158
    add-int/2addr v7, v6

    .line 159
    iput v7, v1, Lo/f;->g:I

    .line 160
    .line 161
    iget-object v7, v1, Lo/f;->e:Lo/c;

    .line 162
    .line 163
    if-nez v7, :cond_8

    .line 164
    .line 165
    iput-object v3, v1, Lo/f;->d:Lo/c;

    .line 166
    .line 167
    iput-object v3, v1, Lo/f;->e:Lo/c;

    .line 168
    .line 169
    goto :goto_2

    .line 170
    :cond_8
    iput-object v3, v7, Lo/c;->f:Lo/c;

    .line 171
    .line 172
    iput-object v7, v3, Lo/c;->g:Lo/c;

    .line 173
    .line 174
    iput-object v3, v1, Lo/f;->e:Lo/c;

    .line 175
    .line 176
    :goto_2
    invoke-virtual {v2, p1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    :goto_3
    check-cast v4, Landroidx/lifecycle/y;

    .line 180
    .line 181
    if-eqz v4, :cond_9

    .line 182
    .line 183
    goto :goto_4

    .line 184
    :cond_9
    iget-object v1, p0, Landroidx/lifecycle/z;->e:Ljava/lang/ref/WeakReference;

    .line 185
    .line 186
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v1

    .line 190
    check-cast v1, Landroidx/lifecycle/x;

    .line 191
    .line 192
    if-nez v1, :cond_a

    .line 193
    .line 194
    :goto_4
    return-void

    .line 195
    :cond_a
    iget v2, p0, Landroidx/lifecycle/z;->f:I

    .line 196
    .line 197
    if-nez v2, :cond_b

    .line 198
    .line 199
    iget-boolean v2, p0, Landroidx/lifecycle/z;->g:Z

    .line 200
    .line 201
    if-eqz v2, :cond_c

    .line 202
    .line 203
    :cond_b
    move v5, v6

    .line 204
    :cond_c
    invoke-virtual {p0, p1}, Landroidx/lifecycle/z;->e(Landroidx/lifecycle/w;)Landroidx/lifecycle/q;

    .line 205
    .line 206
    .line 207
    move-result-object v2

    .line 208
    iget v3, p0, Landroidx/lifecycle/z;->f:I

    .line 209
    .line 210
    add-int/2addr v3, v6

    .line 211
    iput v3, p0, Landroidx/lifecycle/z;->f:I

    .line 212
    .line 213
    :goto_5
    iget-object v3, v0, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 214
    .line 215
    invoke-virtual {v3, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 216
    .line 217
    .line 218
    move-result v2

    .line 219
    if-gez v2, :cond_e

    .line 220
    .line 221
    iget-object v2, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 222
    .line 223
    iget-object v2, v2, Lo/a;->h:Ljava/util/HashMap;

    .line 224
    .line 225
    invoke-virtual {v2, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 226
    .line 227
    .line 228
    move-result v2

    .line 229
    if-eqz v2, :cond_e

    .line 230
    .line 231
    iget-object v2, v0, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 232
    .line 233
    iget-object v3, p0, Landroidx/lifecycle/z;->i:Ljava/util/ArrayList;

    .line 234
    .line 235
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 236
    .line 237
    .line 238
    sget-object v2, Landroidx/lifecycle/p;->Companion:Landroidx/lifecycle/n;

    .line 239
    .line 240
    iget-object v4, v0, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 241
    .line 242
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 243
    .line 244
    .line 245
    invoke-static {v4}, Landroidx/lifecycle/n;->b(Landroidx/lifecycle/q;)Landroidx/lifecycle/p;

    .line 246
    .line 247
    .line 248
    move-result-object v2

    .line 249
    if-eqz v2, :cond_d

    .line 250
    .line 251
    invoke-virtual {v0, v1, v2}, Landroidx/lifecycle/y;->a(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V

    .line 252
    .line 253
    .line 254
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 255
    .line 256
    .line 257
    move-result v2

    .line 258
    sub-int/2addr v2, v6

    .line 259
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    invoke-virtual {p0, p1}, Landroidx/lifecycle/z;->e(Landroidx/lifecycle/w;)Landroidx/lifecycle/q;

    .line 263
    .line 264
    .line 265
    move-result-object v2

    .line 266
    goto :goto_5

    .line 267
    :cond_d
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 268
    .line 269
    new-instance p1, Ljava/lang/StringBuilder;

    .line 270
    .line 271
    const-string v1, "no event up from "

    .line 272
    .line 273
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 274
    .line 275
    .line 276
    iget-object v0, v0, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 277
    .line 278
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 279
    .line 280
    .line 281
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object p1

    .line 285
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 286
    .line 287
    .line 288
    throw p0

    .line 289
    :cond_e
    if-nez v5, :cond_f

    .line 290
    .line 291
    invoke-virtual {p0}, Landroidx/lifecycle/z;->j()V

    .line 292
    .line 293
    .line 294
    :cond_f
    iget p1, p0, Landroidx/lifecycle/z;->f:I

    .line 295
    .line 296
    add-int/lit8 p1, p1, -0x1

    .line 297
    .line 298
    iput p1, p0, Landroidx/lifecycle/z;->f:I

    .line 299
    .line 300
    return-void
.end method

.method public final b()Landroidx/lifecycle/q;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 2
    .line 3
    return-object p0
.end method

.method public final c()Lyy0/l1;
    .locals 1

    .line 1
    new-instance v0, Lyy0/l1;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/lifecycle/z;->j:Lyy0/c2;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public final d(Landroidx/lifecycle/w;)V
    .locals 1

    .line 1
    const-string v0, "observer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "removeObserver"

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Landroidx/lifecycle/z;->f(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lo/a;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final e(Landroidx/lifecycle/w;)Landroidx/lifecycle/q;
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 2
    .line 3
    iget-object v0, v0, Lo/a;->h:Ljava/util/HashMap;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    check-cast p1, Lo/c;

    .line 17
    .line 18
    iget-object p1, p1, Lo/c;->g:Lo/c;

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move-object p1, v2

    .line 22
    :goto_0
    if-eqz p1, :cond_1

    .line 23
    .line 24
    iget-object p1, p1, Lo/c;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p1, Landroidx/lifecycle/y;

    .line 27
    .line 28
    iget-object p1, p1, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move-object p1, v2

    .line 32
    :goto_1
    iget-object v0, p0, Landroidx/lifecycle/z;->i:Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-nez v1, :cond_2

    .line 39
    .line 40
    const/4 v1, 0x1

    .line 41
    invoke-static {v0, v1}, Lkx/a;->f(Ljava/util/ArrayList;I)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    move-object v2, v0

    .line 46
    check-cast v2, Landroidx/lifecycle/q;

    .line 47
    .line 48
    :cond_2
    iget-object p0, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 49
    .line 50
    const-string v0, "state1"

    .line 51
    .line 52
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    if-eqz p1, :cond_3

    .line 56
    .line 57
    invoke-virtual {p1, p0}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-gez v0, :cond_3

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_3
    move-object p1, p0

    .line 65
    :goto_2
    if-eqz v2, :cond_4

    .line 66
    .line 67
    invoke-virtual {v2, p1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    if-gez p0, :cond_4

    .line 72
    .line 73
    return-object v2

    .line 74
    :cond_4
    return-object p1
.end method

.method public final f(Ljava/lang/String;)V
    .locals 1

    .line 1
    iget-boolean p0, p0, Landroidx/lifecycle/z;->b:Z

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    invoke-static {}, Ln/a;->g()Ln/a;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    iget-object p0, p0, Ln/a;->a:Ln/b;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {p0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    if-ne p0, v0, :cond_0

    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    const-string p0, "Method "

    .line 30
    .line 31
    const-string v0, " must be called on the main thread"

    .line 32
    .line 33
    invoke-static {p0, p1, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p1

    .line 47
    :cond_1
    return-void
.end method

.method public final g(Landroidx/lifecycle/p;)V
    .locals 1

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "handleLifecycleEvent"

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Landroidx/lifecycle/z;->f(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Landroidx/lifecycle/p;->a()Landroidx/lifecycle/q;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p0, p1}, Landroidx/lifecycle/z;->h(Landroidx/lifecycle/q;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final h(Landroidx/lifecycle/q;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 2
    .line 3
    if-ne v0, p1, :cond_0

    .line 4
    .line 5
    goto/16 :goto_2

    .line 6
    .line 7
    :cond_0
    iget-object v0, p0, Landroidx/lifecycle/z;->e:Ljava/lang/ref/WeakReference;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Landroidx/lifecycle/x;

    .line 14
    .line 15
    iget-object v1, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 16
    .line 17
    const-string v2, "current"

    .line 18
    .line 19
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v2, "next"

    .line 23
    .line 24
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    sget-object v2, Landroidx/lifecycle/q;->e:Landroidx/lifecycle/q;

    .line 28
    .line 29
    if-ne v1, v2, :cond_2

    .line 30
    .line 31
    sget-object v2, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 32
    .line 33
    if-eq p1, v2, :cond_1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    new-instance v1, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string v2, "State must be at least \'"

    .line 41
    .line 42
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    sget-object v2, Landroidx/lifecycle/q;->f:Landroidx/lifecycle/q;

    .line 46
    .line 47
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v2, "\' to be moved to \'"

    .line 51
    .line 52
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    const-string p1, "\' in component "

    .line 59
    .line 60
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw p0

    .line 78
    :cond_2
    :goto_0
    sget-object v2, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 79
    .line 80
    if-ne v1, v2, :cond_4

    .line 81
    .line 82
    if-ne v1, p1, :cond_3

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 86
    .line 87
    new-instance v1, Ljava/lang/StringBuilder;

    .line 88
    .line 89
    const-string v3, "State is \'"

    .line 90
    .line 91
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v2, "\' and cannot be moved to `"

    .line 98
    .line 99
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string p1, "` in component "

    .line 106
    .line 107
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    throw p0

    .line 125
    :cond_4
    :goto_1
    iput-object p1, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 126
    .line 127
    iget-boolean p1, p0, Landroidx/lifecycle/z;->g:Z

    .line 128
    .line 129
    const/4 v0, 0x1

    .line 130
    if-nez p1, :cond_7

    .line 131
    .line 132
    iget p1, p0, Landroidx/lifecycle/z;->f:I

    .line 133
    .line 134
    if-eqz p1, :cond_5

    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_5
    iput-boolean v0, p0, Landroidx/lifecycle/z;->g:Z

    .line 138
    .line 139
    invoke-virtual {p0}, Landroidx/lifecycle/z;->j()V

    .line 140
    .line 141
    .line 142
    const/4 p1, 0x0

    .line 143
    iput-boolean p1, p0, Landroidx/lifecycle/z;->g:Z

    .line 144
    .line 145
    iget-object p1, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 146
    .line 147
    if-ne p1, v2, :cond_6

    .line 148
    .line 149
    new-instance p1, Lo/a;

    .line 150
    .line 151
    invoke-direct {p1}, Lo/a;-><init>()V

    .line 152
    .line 153
    .line 154
    iput-object p1, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 155
    .line 156
    :cond_6
    :goto_2
    return-void

    .line 157
    :cond_7
    :goto_3
    iput-boolean v0, p0, Landroidx/lifecycle/z;->h:Z

    .line 158
    .line 159
    return-void
.end method

.method public final i(Landroidx/lifecycle/q;)V
    .locals 1

    .line 1
    const-string v0, "state"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "setCurrentState"

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Landroidx/lifecycle/z;->f(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p1}, Landroidx/lifecycle/z;->h(Landroidx/lifecycle/q;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final j()V
    .locals 7

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/z;->e:Ljava/lang/ref/WeakReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Landroidx/lifecycle/x;

    .line 8
    .line 9
    if-eqz v0, :cond_8

    .line 10
    .line 11
    :cond_0
    iget-object v1, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 12
    .line 13
    iget v2, v1, Lo/f;->g:I

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    if-nez v2, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    iget-object v1, v1, Lo/f;->d:Lo/c;

    .line 20
    .line 21
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    iget-object v1, v1, Lo/c;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Landroidx/lifecycle/y;

    .line 27
    .line 28
    iget-object v1, v1, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 29
    .line 30
    iget-object v2, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 31
    .line 32
    iget-object v2, v2, Lo/f;->e:Lo/c;

    .line 33
    .line 34
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object v2, v2, Lo/c;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v2, Landroidx/lifecycle/y;

    .line 40
    .line 41
    iget-object v2, v2, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 42
    .line 43
    if-ne v1, v2, :cond_2

    .line 44
    .line 45
    iget-object v1, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 46
    .line 47
    if-ne v1, v2, :cond_2

    .line 48
    .line 49
    :goto_0
    iput-boolean v3, p0, Landroidx/lifecycle/z;->h:Z

    .line 50
    .line 51
    iget-object v0, p0, Landroidx/lifecycle/z;->j:Lyy0/c2;

    .line 52
    .line 53
    iget-object p0, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 54
    .line 55
    invoke-virtual {v0, p0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_2
    iput-boolean v3, p0, Landroidx/lifecycle/z;->h:Z

    .line 60
    .line 61
    iget-object v1, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 62
    .line 63
    iget-object v2, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 64
    .line 65
    iget-object v2, v2, Lo/f;->d:Lo/c;

    .line 66
    .line 67
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iget-object v2, v2, Lo/c;->e:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v2, Landroidx/lifecycle/y;

    .line 73
    .line 74
    iget-object v2, v2, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 75
    .line 76
    invoke-virtual {v1, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    iget-object v2, p0, Landroidx/lifecycle/z;->i:Ljava/util/ArrayList;

    .line 81
    .line 82
    if-gez v1, :cond_5

    .line 83
    .line 84
    iget-object v1, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 85
    .line 86
    new-instance v3, Lo/b;

    .line 87
    .line 88
    iget-object v4, v1, Lo/f;->e:Lo/c;

    .line 89
    .line 90
    iget-object v5, v1, Lo/f;->d:Lo/c;

    .line 91
    .line 92
    const/4 v6, 0x1

    .line 93
    invoke-direct {v3, v4, v5, v6}, Lo/b;-><init>(Lo/c;Lo/c;I)V

    .line 94
    .line 95
    .line 96
    iget-object v1, v1, Lo/f;->f:Ljava/util/WeakHashMap;

    .line 97
    .line 98
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 99
    .line 100
    invoke-virtual {v1, v3, v4}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    :cond_3
    invoke-virtual {v3}, Lo/b;->hasNext()Z

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    if-eqz v1, :cond_5

    .line 108
    .line 109
    iget-boolean v1, p0, Landroidx/lifecycle/z;->h:Z

    .line 110
    .line 111
    if-nez v1, :cond_5

    .line 112
    .line 113
    invoke-virtual {v3}, Lo/b;->next()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    check-cast v1, Ljava/util/Map$Entry;

    .line 118
    .line 119
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v4

    .line 126
    check-cast v4, Landroidx/lifecycle/w;

    .line 127
    .line 128
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    check-cast v1, Landroidx/lifecycle/y;

    .line 133
    .line 134
    :goto_1
    iget-object v5, v1, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 135
    .line 136
    iget-object v6, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 137
    .line 138
    invoke-virtual {v5, v6}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 139
    .line 140
    .line 141
    move-result v5

    .line 142
    if-lez v5, :cond_3

    .line 143
    .line 144
    iget-boolean v5, p0, Landroidx/lifecycle/z;->h:Z

    .line 145
    .line 146
    if-nez v5, :cond_3

    .line 147
    .line 148
    iget-object v5, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 149
    .line 150
    iget-object v5, v5, Lo/a;->h:Ljava/util/HashMap;

    .line 151
    .line 152
    invoke-virtual {v5, v4}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result v5

    .line 156
    if-eqz v5, :cond_3

    .line 157
    .line 158
    sget-object v5, Landroidx/lifecycle/p;->Companion:Landroidx/lifecycle/n;

    .line 159
    .line 160
    iget-object v6, v1, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 161
    .line 162
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 163
    .line 164
    .line 165
    invoke-static {v6}, Landroidx/lifecycle/n;->a(Landroidx/lifecycle/q;)Landroidx/lifecycle/p;

    .line 166
    .line 167
    .line 168
    move-result-object v5

    .line 169
    if-eqz v5, :cond_4

    .line 170
    .line 171
    invoke-virtual {v5}, Landroidx/lifecycle/p;->a()Landroidx/lifecycle/q;

    .line 172
    .line 173
    .line 174
    move-result-object v6

    .line 175
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    invoke-virtual {v1, v0, v5}, Landroidx/lifecycle/y;->a(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 182
    .line 183
    .line 184
    move-result v5

    .line 185
    add-int/lit8 v5, v5, -0x1

    .line 186
    .line 187
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    goto :goto_1

    .line 191
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 192
    .line 193
    new-instance v0, Ljava/lang/StringBuilder;

    .line 194
    .line 195
    const-string v2, "no event down from "

    .line 196
    .line 197
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    iget-object v1, v1, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 201
    .line 202
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 203
    .line 204
    .line 205
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    throw p0

    .line 213
    :cond_5
    iget-object v1, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 214
    .line 215
    iget-object v1, v1, Lo/f;->e:Lo/c;

    .line 216
    .line 217
    iget-boolean v3, p0, Landroidx/lifecycle/z;->h:Z

    .line 218
    .line 219
    if-nez v3, :cond_0

    .line 220
    .line 221
    if-eqz v1, :cond_0

    .line 222
    .line 223
    iget-object v3, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 224
    .line 225
    iget-object v1, v1, Lo/c;->e:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast v1, Landroidx/lifecycle/y;

    .line 228
    .line 229
    iget-object v1, v1, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 230
    .line 231
    invoke-virtual {v3, v1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 232
    .line 233
    .line 234
    move-result v1

    .line 235
    if-lez v1, :cond_0

    .line 236
    .line 237
    iget-object v1, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 238
    .line 239
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 240
    .line 241
    .line 242
    new-instance v3, Lo/d;

    .line 243
    .line 244
    invoke-direct {v3, v1}, Lo/d;-><init>(Lo/f;)V

    .line 245
    .line 246
    .line 247
    iget-object v1, v1, Lo/f;->f:Ljava/util/WeakHashMap;

    .line 248
    .line 249
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 250
    .line 251
    invoke-virtual {v1, v3, v4}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    :cond_6
    invoke-virtual {v3}, Lo/d;->hasNext()Z

    .line 255
    .line 256
    .line 257
    move-result v1

    .line 258
    if-eqz v1, :cond_0

    .line 259
    .line 260
    iget-boolean v1, p0, Landroidx/lifecycle/z;->h:Z

    .line 261
    .line 262
    if-nez v1, :cond_0

    .line 263
    .line 264
    invoke-virtual {v3}, Lo/d;->next()Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v1

    .line 268
    check-cast v1, Ljava/util/Map$Entry;

    .line 269
    .line 270
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v4

    .line 274
    check-cast v4, Landroidx/lifecycle/w;

    .line 275
    .line 276
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v1

    .line 280
    check-cast v1, Landroidx/lifecycle/y;

    .line 281
    .line 282
    :goto_2
    iget-object v5, v1, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 283
    .line 284
    iget-object v6, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 285
    .line 286
    invoke-virtual {v5, v6}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 287
    .line 288
    .line 289
    move-result v5

    .line 290
    if-gez v5, :cond_6

    .line 291
    .line 292
    iget-boolean v5, p0, Landroidx/lifecycle/z;->h:Z

    .line 293
    .line 294
    if-nez v5, :cond_6

    .line 295
    .line 296
    iget-object v5, p0, Landroidx/lifecycle/z;->c:Lo/a;

    .line 297
    .line 298
    iget-object v5, v5, Lo/a;->h:Ljava/util/HashMap;

    .line 299
    .line 300
    invoke-virtual {v5, v4}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 301
    .line 302
    .line 303
    move-result v5

    .line 304
    if-eqz v5, :cond_6

    .line 305
    .line 306
    iget-object v5, v1, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 307
    .line 308
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 309
    .line 310
    .line 311
    sget-object v5, Landroidx/lifecycle/p;->Companion:Landroidx/lifecycle/n;

    .line 312
    .line 313
    iget-object v6, v1, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 314
    .line 315
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 316
    .line 317
    .line 318
    invoke-static {v6}, Landroidx/lifecycle/n;->b(Landroidx/lifecycle/q;)Landroidx/lifecycle/p;

    .line 319
    .line 320
    .line 321
    move-result-object v5

    .line 322
    if-eqz v5, :cond_7

    .line 323
    .line 324
    invoke-virtual {v1, v0, v5}, Landroidx/lifecycle/y;->a(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V

    .line 325
    .line 326
    .line 327
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 328
    .line 329
    .line 330
    move-result v5

    .line 331
    add-int/lit8 v5, v5, -0x1

    .line 332
    .line 333
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    goto :goto_2

    .line 337
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 338
    .line 339
    new-instance v0, Ljava/lang/StringBuilder;

    .line 340
    .line 341
    const-string v2, "no event up from "

    .line 342
    .line 343
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    iget-object v1, v1, Landroidx/lifecycle/y;->a:Landroidx/lifecycle/q;

    .line 347
    .line 348
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 349
    .line 350
    .line 351
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 352
    .line 353
    .line 354
    move-result-object v0

    .line 355
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    throw p0

    .line 359
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 360
    .line 361
    const-string v0, "LifecycleOwner of this LifecycleRegistry is already garbage collected. It is too late to change lifecycle state."

    .line 362
    .line 363
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 364
    .line 365
    .line 366
    throw p0
.end method
