.class public final Ll50/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# static fields
.field public static final d:Lsx0/b;


# instance fields
.field public final a:Lgb0/f;

.field public final b:Lpp0/a0;

.field public final c:Lqf0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lmk0/d;->p:Lsx0/b;

    .line 2
    .line 3
    sput-object v0, Ll50/f;->d:Lsx0/b;

    .line 4
    .line 5
    return-void
.end method

.method public constructor <init>(Lgb0/f;Lpp0/a0;Lqf0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll50/f;->a:Lgb0/f;

    .line 5
    .line 6
    iput-object p2, p0, Ll50/f;->b:Lpp0/a0;

    .line 7
    .line 8
    iput-object p3, p0, Ll50/f;->c:Lqf0/g;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ll50/f;->b(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p2, Ll50/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ll50/e;

    .line 7
    .line 8
    iget v1, v0, Ll50/e;->i:I

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
    iput v1, v0, Ll50/e;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ll50/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ll50/e;-><init>(Ll50/f;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ll50/e;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ll50/e;->i:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-boolean p0, v0, Ll50/e;->f:Z

    .line 40
    .line 41
    iget-boolean p1, v0, Ll50/e;->e:Z

    .line 42
    .line 43
    iget-object v0, v0, Ll50/e;->d:Ljava/util/List;

    .line 44
    .line 45
    check-cast v0, Ljava/util/List;

    .line 46
    .line 47
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    goto :goto_3

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    iget-boolean p1, v0, Ll50/e;->e:Z

    .line 60
    .line 61
    iget-object v2, v0, Ll50/e;->d:Ljava/util/List;

    .line 62
    .line 63
    check-cast v2, Ljava/util/List;

    .line 64
    .line 65
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    move-object v11, p2

    .line 69
    move p2, p1

    .line 70
    move-object p1, v2

    .line 71
    move-object v2, v11

    .line 72
    goto :goto_1

    .line 73
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    iget-object p2, p0, Ll50/f;->b:Lpp0/a0;

    .line 77
    .line 78
    invoke-virtual {p2}, Lpp0/a0;->invoke()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    check-cast p2, Ljava/lang/Boolean;

    .line 83
    .line 84
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    move-object v2, p1

    .line 89
    check-cast v2, Ljava/util/List;

    .line 90
    .line 91
    iput-object v2, v0, Ll50/e;->d:Ljava/util/List;

    .line 92
    .line 93
    iput-boolean p2, v0, Ll50/e;->e:Z

    .line 94
    .line 95
    iput v4, v0, Ll50/e;->i:I

    .line 96
    .line 97
    iget-object v2, p0, Ll50/f;->c:Lqf0/g;

    .line 98
    .line 99
    invoke-virtual {v2, v0}, Lqf0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    if-ne v2, v1, :cond_4

    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_4
    :goto_1
    check-cast v2, Ljava/lang/Boolean;

    .line 107
    .line 108
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 109
    .line 110
    .line 111
    move-result v2

    .line 112
    move-object v5, p1

    .line 113
    check-cast v5, Ljava/util/List;

    .line 114
    .line 115
    iput-object v5, v0, Ll50/e;->d:Ljava/util/List;

    .line 116
    .line 117
    iput-boolean p2, v0, Ll50/e;->e:Z

    .line 118
    .line 119
    iput-boolean v2, v0, Ll50/e;->f:Z

    .line 120
    .line 121
    iput v3, v0, Ll50/e;->i:I

    .line 122
    .line 123
    iget-object p0, p0, Ll50/f;->a:Lgb0/f;

    .line 124
    .line 125
    invoke-virtual {p0, v0}, Lgb0/f;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    if-ne p0, v1, :cond_5

    .line 130
    .line 131
    :goto_2
    return-object v1

    .line 132
    :cond_5
    move-object v0, p1

    .line 133
    move p1, p2

    .line 134
    move-object p2, p0

    .line 135
    move p0, v2

    .line 136
    :goto_3
    check-cast p2, Lss0/b;

    .line 137
    .line 138
    new-instance v1, Ljava/util/ArrayList;

    .line 139
    .line 140
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 141
    .line 142
    .line 143
    sget-object v2, Ll50/f;->d:Lsx0/b;

    .line 144
    .line 145
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 146
    .line 147
    .line 148
    new-instance v5, Landroidx/collection/d1;

    .line 149
    .line 150
    const/4 v6, 0x6

    .line 151
    invoke-direct {v5, v2, v6}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 152
    .line 153
    .line 154
    :cond_6
    :goto_4
    invoke-virtual {v5}, Landroidx/collection/d1;->hasNext()Z

    .line 155
    .line 156
    .line 157
    move-result v2

    .line 158
    if-eqz v2, :cond_10

    .line 159
    .line 160
    invoke-virtual {v5}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    move-object v6, v2

    .line 165
    check-cast v6, Lmk0/d;

    .line 166
    .line 167
    const/4 v7, 0x0

    .line 168
    if-eqz v0, :cond_9

    .line 169
    .line 170
    move-object v8, v0

    .line 171
    check-cast v8, Ljava/lang/Iterable;

    .line 172
    .line 173
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 174
    .line 175
    .line 176
    move-result-object v8

    .line 177
    :cond_7
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 178
    .line 179
    .line 180
    move-result v9

    .line 181
    if-eqz v9, :cond_8

    .line 182
    .line 183
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v9

    .line 187
    move-object v10, v9

    .line 188
    check-cast v10, Lmk0/a;

    .line 189
    .line 190
    iget-object v10, v10, Lmk0/a;->b:Lmk0/d;

    .line 191
    .line 192
    if-ne v10, v6, :cond_7

    .line 193
    .line 194
    move-object v7, v9

    .line 195
    :cond_8
    check-cast v7, Lmk0/a;

    .line 196
    .line 197
    :cond_9
    const/4 v8, 0x0

    .line 198
    if-eqz v7, :cond_a

    .line 199
    .line 200
    move v7, v4

    .line 201
    goto :goto_5

    .line 202
    :cond_a
    move v7, v8

    .line 203
    :goto_5
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 204
    .line 205
    .line 206
    move-result v6

    .line 207
    if-eqz v6, :cond_c

    .line 208
    .line 209
    if-eq v6, v4, :cond_c

    .line 210
    .line 211
    if-eq v6, v3, :cond_b

    .line 212
    .line 213
    move v6, v7

    .line 214
    goto :goto_6

    .line 215
    :cond_b
    sget-object v6, Lss0/e;->E1:Lss0/e;

    .line 216
    .line 217
    invoke-static {p2, v6}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 218
    .line 219
    .line 220
    move-result v6

    .line 221
    if-eqz v6, :cond_d

    .line 222
    .line 223
    if-nez p0, :cond_d

    .line 224
    .line 225
    :cond_c
    move v6, v4

    .line 226
    goto :goto_6

    .line 227
    :cond_d
    move v6, v8

    .line 228
    :goto_6
    if-eqz v6, :cond_f

    .line 229
    .line 230
    if-nez v7, :cond_e

    .line 231
    .line 232
    if-nez p1, :cond_f

    .line 233
    .line 234
    :cond_e
    move v8, v4

    .line 235
    :cond_f
    if-eqz v8, :cond_6

    .line 236
    .line 237
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    goto :goto_4

    .line 241
    :cond_10
    new-instance p0, Ljava/util/LinkedHashMap;

    .line 242
    .line 243
    const/16 p1, 0xa

    .line 244
    .line 245
    invoke-static {v1, p1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 246
    .line 247
    .line 248
    move-result p1

    .line 249
    invoke-static {p1}, Lmx0/x;->k(I)I

    .line 250
    .line 251
    .line 252
    move-result p1

    .line 253
    const/16 p2, 0x10

    .line 254
    .line 255
    if-ge p1, p2, :cond_11

    .line 256
    .line 257
    move p1, p2

    .line 258
    :cond_11
    invoke-direct {p0, p1}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 259
    .line 260
    .line 261
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 262
    .line 263
    .line 264
    move-result-object p1

    .line 265
    :goto_7
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 266
    .line 267
    .line 268
    move-result p2

    .line 269
    if-eqz p2, :cond_15

    .line 270
    .line 271
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object p2

    .line 275
    move-object v1, p2

    .line 276
    check-cast v1, Lmk0/d;

    .line 277
    .line 278
    if-eqz v0, :cond_13

    .line 279
    .line 280
    move-object v2, v0

    .line 281
    check-cast v2, Ljava/lang/Iterable;

    .line 282
    .line 283
    new-instance v3, Ljava/util/ArrayList;

    .line 284
    .line 285
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 286
    .line 287
    .line 288
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 289
    .line 290
    .line 291
    move-result-object v2

    .line 292
    :cond_12
    :goto_8
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 293
    .line 294
    .line 295
    move-result v4

    .line 296
    if-eqz v4, :cond_14

    .line 297
    .line 298
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v4

    .line 302
    move-object v5, v4

    .line 303
    check-cast v5, Lmk0/a;

    .line 304
    .line 305
    iget-object v5, v5, Lmk0/a;->b:Lmk0/d;

    .line 306
    .line 307
    if-ne v5, v1, :cond_12

    .line 308
    .line 309
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 310
    .line 311
    .line 312
    goto :goto_8

    .line 313
    :cond_13
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 314
    .line 315
    :cond_14
    invoke-interface {p0, p2, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    goto :goto_7

    .line 319
    :cond_15
    return-object p0
.end method
