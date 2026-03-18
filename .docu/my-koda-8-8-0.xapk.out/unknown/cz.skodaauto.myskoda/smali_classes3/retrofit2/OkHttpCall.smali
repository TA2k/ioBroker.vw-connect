.class final Lretrofit2/OkHttpCall;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lretrofit2/Call;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;,
        Lretrofit2/OkHttpCall$NoContentResponseBody;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lretrofit2/Call<",
        "TT;>;"
    }
.end annotation


# instance fields
.field public final d:Lretrofit2/RequestFactory;

.field public final e:Ljava/lang/Object;

.field public final f:[Ljava/lang/Object;

.field public final g:Ld01/i;

.field public final h:Lretrofit2/Converter;

.field public volatile i:Z

.field public j:Ld01/j;

.field public k:Ljava/lang/Throwable;

.field public l:Z


# direct methods
.method public constructor <init>(Lretrofit2/RequestFactory;Ljava/lang/Object;[Ljava/lang/Object;Ld01/i;Lretrofit2/Converter;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/OkHttpCall;->d:Lretrofit2/RequestFactory;

    .line 5
    .line 6
    iput-object p2, p0, Lretrofit2/OkHttpCall;->e:Ljava/lang/Object;

    .line 7
    .line 8
    iput-object p3, p0, Lretrofit2/OkHttpCall;->f:[Ljava/lang/Object;

    .line 9
    .line 10
    iput-object p4, p0, Lretrofit2/OkHttpCall;->g:Ld01/i;

    .line 11
    .line 12
    iput-object p5, p0, Lretrofit2/OkHttpCall;->h:Lretrofit2/Converter;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a()Ld01/j;
    .locals 14

    .line 1
    iget-object v0, p0, Lretrofit2/OkHttpCall;->d:Lretrofit2/RequestFactory;

    .line 2
    .line 3
    iget-object v1, v0, Lretrofit2/RequestFactory;->k:[Lretrofit2/ParameterHandler;

    .line 4
    .line 5
    iget-object v2, p0, Lretrofit2/OkHttpCall;->f:[Ljava/lang/Object;

    .line 6
    .line 7
    array-length v3, v2

    .line 8
    array-length v4, v1

    .line 9
    if-ne v3, v4, :cond_c

    .line 10
    .line 11
    new-instance v5, Lretrofit2/RequestBuilder;

    .line 12
    .line 13
    iget-object v6, v0, Lretrofit2/RequestFactory;->d:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v7, v0, Lretrofit2/RequestFactory;->c:Ld01/a0;

    .line 16
    .line 17
    iget-object v8, v0, Lretrofit2/RequestFactory;->e:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v9, v0, Lretrofit2/RequestFactory;->f:Ld01/y;

    .line 20
    .line 21
    iget-object v10, v0, Lretrofit2/RequestFactory;->g:Ld01/d0;

    .line 22
    .line 23
    iget-boolean v11, v0, Lretrofit2/RequestFactory;->h:Z

    .line 24
    .line 25
    iget-boolean v12, v0, Lretrofit2/RequestFactory;->i:Z

    .line 26
    .line 27
    iget-boolean v13, v0, Lretrofit2/RequestFactory;->j:Z

    .line 28
    .line 29
    invoke-direct/range {v5 .. v13}, Lretrofit2/RequestBuilder;-><init>(Ljava/lang/String;Ld01/a0;Ljava/lang/String;Ld01/y;Ld01/d0;ZZZ)V

    .line 30
    .line 31
    .line 32
    iget-boolean v4, v0, Lretrofit2/RequestFactory;->l:Z

    .line 33
    .line 34
    if-eqz v4, :cond_0

    .line 35
    .line 36
    add-int/lit8 v3, v3, -0x1

    .line 37
    .line 38
    :cond_0
    new-instance v4, Ljava/util/ArrayList;

    .line 39
    .line 40
    invoke-direct {v4, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 41
    .line 42
    .line 43
    const/4 v6, 0x0

    .line 44
    move v7, v6

    .line 45
    :goto_0
    if-ge v7, v3, :cond_1

    .line 46
    .line 47
    aget-object v8, v2, v7

    .line 48
    .line 49
    invoke-virtual {v4, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    aget-object v8, v1, v7

    .line 53
    .line 54
    aget-object v9, v2, v7

    .line 55
    .line 56
    invoke-virtual {v8, v5, v9}, Lretrofit2/ParameterHandler;->a(Lretrofit2/RequestBuilder;Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    add-int/lit8 v7, v7, 0x1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_1
    iget-object v1, v5, Lretrofit2/RequestBuilder;->d:Ld01/z;

    .line 63
    .line 64
    const/4 v2, 0x0

    .line 65
    if-eqz v1, :cond_2

    .line 66
    .line 67
    invoke-virtual {v1}, Ld01/z;->c()Ld01/a0;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    goto :goto_2

    .line 72
    :cond_2
    iget-object v1, v5, Lretrofit2/RequestBuilder;->c:Ljava/lang/String;

    .line 73
    .line 74
    iget-object v3, v5, Lretrofit2/RequestBuilder;->b:Ld01/a0;

    .line 75
    .line 76
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    const-string v7, "link"

    .line 80
    .line 81
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v3, v1}, Ld01/a0;->h(Ljava/lang/String;)Ld01/z;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    if-eqz v1, :cond_3

    .line 89
    .line 90
    invoke-virtual {v1}, Ld01/z;->c()Ld01/a0;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    goto :goto_1

    .line 95
    :cond_3
    move-object v1, v2

    .line 96
    :goto_1
    if-eqz v1, :cond_b

    .line 97
    .line 98
    :goto_2
    iget-object v3, v5, Lretrofit2/RequestBuilder;->k:Ld01/r0;

    .line 99
    .line 100
    if-nez v3, :cond_7

    .line 101
    .line 102
    iget-object v7, v5, Lretrofit2/RequestBuilder;->j:Lb81/a;

    .line 103
    .line 104
    if-eqz v7, :cond_4

    .line 105
    .line 106
    new-instance v3, Ld01/u;

    .line 107
    .line 108
    iget-object v2, v7, Lb81/a;->e:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v2, Ljava/util/ArrayList;

    .line 111
    .line 112
    iget-object v6, v7, Lb81/a;->f:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast v6, Ljava/util/ArrayList;

    .line 115
    .line 116
    invoke-direct {v3, v2, v6}, Ld01/u;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 117
    .line 118
    .line 119
    goto :goto_3

    .line 120
    :cond_4
    iget-object v7, v5, Lretrofit2/RequestBuilder;->i:Lgw0/c;

    .line 121
    .line 122
    if-eqz v7, :cond_6

    .line 123
    .line 124
    iget-object v2, v7, Lgw0/c;->g:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast v2, Ljava/util/ArrayList;

    .line 127
    .line 128
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 129
    .line 130
    .line 131
    move-result v3

    .line 132
    if-nez v3, :cond_5

    .line 133
    .line 134
    new-instance v3, Ld01/f0;

    .line 135
    .line 136
    iget-object v6, v7, Lgw0/c;->e:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v6, Lu01/i;

    .line 139
    .line 140
    iget-object v7, v7, Lgw0/c;->f:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v7, Ld01/d0;

    .line 143
    .line 144
    invoke-static {v2}, Le01/g;->j(Ljava/util/List;)Ljava/util/List;

    .line 145
    .line 146
    .line 147
    move-result-object v2

    .line 148
    invoke-direct {v3, v6, v7, v2}, Ld01/f0;-><init>(Lu01/i;Ld01/d0;Ljava/util/List;)V

    .line 149
    .line 150
    .line 151
    goto :goto_3

    .line 152
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 153
    .line 154
    const-string v0, "Multipart body must have at least one part."

    .line 155
    .line 156
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    throw p0

    .line 160
    :cond_6
    iget-boolean v7, v5, Lretrofit2/RequestBuilder;->h:Z

    .line 161
    .line 162
    if-eqz v7, :cond_7

    .line 163
    .line 164
    new-array v3, v6, [B

    .line 165
    .line 166
    invoke-static {v2, v3}, Ld01/r0;->create(Ld01/d0;[B)Ld01/r0;

    .line 167
    .line 168
    .line 169
    move-result-object v3

    .line 170
    :cond_7
    :goto_3
    iget-object v2, v5, Lretrofit2/RequestBuilder;->g:Ld01/d0;

    .line 171
    .line 172
    iget-object v6, v5, Lretrofit2/RequestBuilder;->f:Ld01/x;

    .line 173
    .line 174
    if-eqz v2, :cond_9

    .line 175
    .line 176
    if-eqz v3, :cond_8

    .line 177
    .line 178
    new-instance v7, Lretrofit2/RequestBuilder$ContentTypeOverridingRequestBody;

    .line 179
    .line 180
    invoke-direct {v7, v3, v2}, Lretrofit2/RequestBuilder$ContentTypeOverridingRequestBody;-><init>(Ld01/r0;Ld01/d0;)V

    .line 181
    .line 182
    .line 183
    move-object v3, v7

    .line 184
    goto :goto_4

    .line 185
    :cond_8
    const-string v7, "Content-Type"

    .line 186
    .line 187
    iget-object v2, v2, Ld01/d0;->a:Ljava/lang/String;

    .line 188
    .line 189
    invoke-virtual {v6, v7, v2}, Ld01/x;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    :cond_9
    :goto_4
    iget-object v2, v5, Lretrofit2/RequestBuilder;->e:Ld01/j0;

    .line 193
    .line 194
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 195
    .line 196
    .line 197
    iput-object v1, v2, Ld01/j0;->a:Ld01/a0;

    .line 198
    .line 199
    invoke-virtual {v6}, Ld01/x;->j()Ld01/y;

    .line 200
    .line 201
    .line 202
    move-result-object v1

    .line 203
    invoke-virtual {v2, v1}, Ld01/j0;->d(Ld01/y;)V

    .line 204
    .line 205
    .line 206
    iget-object v1, v5, Lretrofit2/RequestBuilder;->a:Ljava/lang/String;

    .line 207
    .line 208
    invoke-virtual {v2, v1, v3}, Ld01/j0;->e(Ljava/lang/String;Ld01/r0;)V

    .line 209
    .line 210
    .line 211
    new-instance v1, Lretrofit2/Invocation;

    .line 212
    .line 213
    iget-object v3, v0, Lretrofit2/RequestFactory;->a:Ljava/lang/Class;

    .line 214
    .line 215
    iget-object v0, v0, Lretrofit2/RequestFactory;->b:Ljava/lang/reflect/Method;

    .line 216
    .line 217
    iget-object v5, p0, Lretrofit2/OkHttpCall;->e:Ljava/lang/Object;

    .line 218
    .line 219
    invoke-direct {v1, v3, v5, v0, v4}, Lretrofit2/Invocation;-><init>(Ljava/lang/Class;Ljava/lang/Object;Ljava/lang/reflect/Method;Ljava/util/ArrayList;)V

    .line 220
    .line 221
    .line 222
    const-class v0, Lretrofit2/Invocation;

    .line 223
    .line 224
    invoke-static {v0}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 225
    .line 226
    .line 227
    move-result-object v0

    .line 228
    const-string v3, "type"

    .line 229
    .line 230
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    iget-object v3, v2, Ld01/j0;->e:Ljp/ng;

    .line 234
    .line 235
    invoke-virtual {v3, v0, v1}, Ljp/ng;->b(Lhy0/d;Ljava/lang/Object;)Ljp/ng;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    iput-object v0, v2, Ld01/j0;->e:Ljp/ng;

    .line 240
    .line 241
    new-instance v0, Ld01/k0;

    .line 242
    .line 243
    invoke-direct {v0, v2}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 244
    .line 245
    .line 246
    iget-object p0, p0, Lretrofit2/OkHttpCall;->g:Ld01/i;

    .line 247
    .line 248
    invoke-interface {p0, v0}, Ld01/i;->newCall(Ld01/k0;)Ld01/j;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    if-eqz p0, :cond_a

    .line 253
    .line 254
    return-object p0

    .line 255
    :cond_a
    new-instance p0, Ljava/lang/NullPointerException;

    .line 256
    .line 257
    const-string v0, "Call.Factory returned null."

    .line 258
    .line 259
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 260
    .line 261
    .line 262
    throw p0

    .line 263
    :cond_b
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 264
    .line 265
    new-instance v0, Ljava/lang/StringBuilder;

    .line 266
    .line 267
    const-string v1, "Malformed URL. Base: "

    .line 268
    .line 269
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 273
    .line 274
    .line 275
    const-string v1, ", Relative: "

    .line 276
    .line 277
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 278
    .line 279
    .line 280
    iget-object v1, v5, Lretrofit2/RequestBuilder;->c:Ljava/lang/String;

    .line 281
    .line 282
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 283
    .line 284
    .line 285
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 286
    .line 287
    .line 288
    move-result-object v0

    .line 289
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    throw p0

    .line 293
    :cond_c
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 294
    .line 295
    const-string v0, "Argument count ("

    .line 296
    .line 297
    const-string v2, ") doesn\'t match expected count ("

    .line 298
    .line 299
    invoke-static {v0, v3, v2}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 300
    .line 301
    .line 302
    move-result-object v0

    .line 303
    array-length v1, v1

    .line 304
    const-string v2, ")"

    .line 305
    .line 306
    invoke-static {v1, v2, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object v0

    .line 310
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    throw p0
.end method

.method public final b()Ld01/j;
    .locals 1

    .line 1
    iget-object v0, p0, Lretrofit2/OkHttpCall;->j:Ld01/j;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    iget-object v0, p0, Lretrofit2/OkHttpCall;->k:Ljava/lang/Throwable;

    .line 7
    .line 8
    if-eqz v0, :cond_3

    .line 9
    .line 10
    instance-of p0, v0, Ljava/io/IOException;

    .line 11
    .line 12
    if-nez p0, :cond_2

    .line 13
    .line 14
    instance-of p0, v0, Ljava/lang/RuntimeException;

    .line 15
    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    check-cast v0, Ljava/lang/RuntimeException;

    .line 19
    .line 20
    throw v0

    .line 21
    :cond_1
    check-cast v0, Ljava/lang/Error;

    .line 22
    .line 23
    throw v0

    .line 24
    :cond_2
    check-cast v0, Ljava/io/IOException;

    .line 25
    .line 26
    throw v0

    .line 27
    :cond_3
    :try_start_0
    invoke-virtual {p0}, Lretrofit2/OkHttpCall;->a()Ld01/j;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    iput-object v0, p0, Lretrofit2/OkHttpCall;->j:Ld01/j;
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/Error; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    .line 33
    return-object v0

    .line 34
    :catch_0
    move-exception v0

    .line 35
    invoke-static {v0}, Lretrofit2/Utils;->m(Ljava/lang/Throwable;)V

    .line 36
    .line 37
    .line 38
    iput-object v0, p0, Lretrofit2/OkHttpCall;->k:Ljava/lang/Throwable;

    .line 39
    .line 40
    throw v0
.end method

.method public final c(Ld01/t0;)Lretrofit2/Response;
    .locals 6

    .line 1
    iget-object v0, p1, Ld01/t0;->j:Ld01/v0;

    .line 2
    .line 3
    invoke-virtual {p1}, Ld01/t0;->d()Ld01/s0;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    new-instance v1, Lretrofit2/OkHttpCall$NoContentResponseBody;

    .line 8
    .line 9
    invoke-virtual {v0}, Ld01/v0;->d()Ld01/d0;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-virtual {v0}, Ld01/v0;->b()J

    .line 14
    .line 15
    .line 16
    move-result-wide v3

    .line 17
    invoke-direct {v1, v2, v3, v4}, Lretrofit2/OkHttpCall$NoContentResponseBody;-><init>(Ld01/d0;J)V

    .line 18
    .line 19
    .line 20
    iput-object v1, p1, Ld01/s0;->g:Ld01/v0;

    .line 21
    .line 22
    invoke-virtual {p1}, Ld01/s0;->a()Ld01/t0;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iget v1, p1, Ld01/t0;->g:I

    .line 27
    .line 28
    const/16 v2, 0xc8

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    if-lt v1, v2, :cond_4

    .line 32
    .line 33
    const/16 v2, 0x12c

    .line 34
    .line 35
    if-lt v1, v2, :cond_0

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_0
    const/16 v2, 0xcc

    .line 39
    .line 40
    if-eq v1, v2, :cond_3

    .line 41
    .line 42
    const/16 v2, 0xcd

    .line 43
    .line 44
    if-ne v1, v2, :cond_1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    new-instance v1, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;

    .line 48
    .line 49
    invoke-direct {v1, v0}, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;-><init>(Ld01/v0;)V

    .line 50
    .line 51
    .line 52
    :try_start_0
    iget-object p0, p0, Lretrofit2/OkHttpCall;->h:Lretrofit2/Converter;

    .line 53
    .line 54
    invoke-interface {p0, v1}, Lretrofit2/Converter;->j(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-static {p0, p1}, Lretrofit2/Response;->b(Ljava/lang/Object;Ld01/t0;)Lretrofit2/Response;

    .line 59
    .line 60
    .line 61
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 62
    return-object p0

    .line 63
    :catch_0
    move-exception p0

    .line 64
    iget-object p1, v1, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;->g:Ljava/io/IOException;

    .line 65
    .line 66
    if-nez p1, :cond_2

    .line 67
    .line 68
    throw p0

    .line 69
    :cond_2
    throw p1

    .line 70
    :cond_3
    :goto_0
    invoke-virtual {v0}, Ld01/v0;->close()V

    .line 71
    .line 72
    .line 73
    invoke-static {v3, p1}, Lretrofit2/Response;->b(Ljava/lang/Object;Ld01/t0;)Lretrofit2/Response;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0

    .line 78
    :cond_4
    :goto_1
    :try_start_1
    new-instance p0, Lu01/f;

    .line 79
    .line 80
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v0}, Ld01/v0;->p0()Lu01/h;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    invoke-interface {v1, p0}, Lu01/h;->L(Lu01/g;)J

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0}, Ld01/v0;->d()Ld01/d0;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-virtual {v0}, Ld01/v0;->b()J

    .line 95
    .line 96
    .line 97
    move-result-wide v4

    .line 98
    sget-object v2, Ld01/v0;->d:Ld01/u0;

    .line 99
    .line 100
    new-instance v2, Ld01/u0;

    .line 101
    .line 102
    invoke-direct {v2, v1, v4, v5, p0}, Ld01/u0;-><init>(Ld01/d0;JLu01/f;)V

    .line 103
    .line 104
    .line 105
    iget-boolean p0, p1, Ld01/t0;->t:Z

    .line 106
    .line 107
    if-nez p0, :cond_5

    .line 108
    .line 109
    new-instance p0, Lretrofit2/Response;

    .line 110
    .line 111
    invoke-direct {p0, p1, v3, v2}, Lretrofit2/Response;-><init>(Ld01/t0;Ljava/lang/Object;Ld01/u0;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0}, Ld01/v0;->close()V

    .line 115
    .line 116
    .line 117
    return-object p0

    .line 118
    :cond_5
    :try_start_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 119
    .line 120
    const-string p1, "rawResponse should not be successful response"

    .line 121
    .line 122
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    throw p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 126
    :catchall_0
    move-exception p0

    .line 127
    invoke-virtual {v0}, Ld01/v0;->close()V

    .line 128
    .line 129
    .line 130
    throw p0
.end method

.method public final cancel()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lretrofit2/OkHttpCall;->i:Z

    .line 3
    .line 4
    monitor-enter p0

    .line 5
    :try_start_0
    iget-object v0, p0, Lretrofit2/OkHttpCall;->j:Ld01/j;

    .line 6
    .line 7
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-interface {v0}, Ld01/j;->cancel()V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void

    .line 14
    :catchall_0
    move-exception v0

    .line 15
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 16
    throw v0
.end method

.method public final clone()Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v0, Lretrofit2/OkHttpCall;

    iget-object v4, p0, Lretrofit2/OkHttpCall;->g:Ld01/i;

    iget-object v5, p0, Lretrofit2/OkHttpCall;->h:Lretrofit2/Converter;

    iget-object v1, p0, Lretrofit2/OkHttpCall;->d:Lretrofit2/RequestFactory;

    iget-object v2, p0, Lretrofit2/OkHttpCall;->e:Ljava/lang/Object;

    iget-object v3, p0, Lretrofit2/OkHttpCall;->f:[Ljava/lang/Object;

    invoke-direct/range {v0 .. v5}, Lretrofit2/OkHttpCall;-><init>(Lretrofit2/RequestFactory;Ljava/lang/Object;[Ljava/lang/Object;Ld01/i;Lretrofit2/Converter;)V

    return-object v0
.end method

.method public final clone()Lretrofit2/Call;
    .locals 6

    .line 2
    new-instance v0, Lretrofit2/OkHttpCall;

    iget-object v4, p0, Lretrofit2/OkHttpCall;->g:Ld01/i;

    iget-object v5, p0, Lretrofit2/OkHttpCall;->h:Lretrofit2/Converter;

    iget-object v1, p0, Lretrofit2/OkHttpCall;->d:Lretrofit2/RequestFactory;

    iget-object v2, p0, Lretrofit2/OkHttpCall;->e:Ljava/lang/Object;

    iget-object v3, p0, Lretrofit2/OkHttpCall;->f:[Ljava/lang/Object;

    invoke-direct/range {v0 .. v5}, Lretrofit2/OkHttpCall;-><init>(Lretrofit2/RequestFactory;Ljava/lang/Object;[Ljava/lang/Object;Ld01/i;Lretrofit2/Converter;)V

    return-object v0
.end method

.method public final g(Lretrofit2/Callback;)V
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lretrofit2/OkHttpCall;->l:Z

    .line 3
    .line 4
    if-nez v0, :cond_3

    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Lretrofit2/OkHttpCall;->l:Z

    .line 8
    .line 9
    iget-object v0, p0, Lretrofit2/OkHttpCall;->j:Ld01/j;

    .line 10
    .line 11
    iget-object v1, p0, Lretrofit2/OkHttpCall;->k:Ljava/lang/Throwable;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    :try_start_1
    invoke-virtual {p0}, Lretrofit2/OkHttpCall;->a()Ld01/j;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    iput-object v2, p0, Lretrofit2/OkHttpCall;->j:Ld01/j;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 22
    .line 23
    move-object v0, v2

    .line 24
    goto :goto_0

    .line 25
    :catchall_0
    move-exception v1

    .line 26
    :try_start_2
    invoke-static {v1}, Lretrofit2/Utils;->m(Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    iput-object v1, p0, Lretrofit2/OkHttpCall;->k:Ljava/lang/Throwable;

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :catchall_1
    move-exception p1

    .line 33
    goto :goto_1

    .line 34
    :cond_0
    :goto_0
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 35
    if-eqz v1, :cond_1

    .line 36
    .line 37
    invoke-interface {p1, p0, v1}, Lretrofit2/Callback;->a(Lretrofit2/Call;Ljava/lang/Throwable;)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_1
    iget-boolean v1, p0, Lretrofit2/OkHttpCall;->i:Z

    .line 42
    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    invoke-interface {v0}, Ld01/j;->cancel()V

    .line 46
    .line 47
    .line 48
    :cond_2
    new-instance v1, Lretrofit2/OkHttpCall$1;

    .line 49
    .line 50
    invoke-direct {v1, p0, p1}, Lretrofit2/OkHttpCall$1;-><init>(Lretrofit2/OkHttpCall;Lretrofit2/Callback;)V

    .line 51
    .line 52
    .line 53
    invoke-static {v0, v1}, Lcom/google/firebase/perf/network/FirebasePerfOkHttpClient;->enqueue(Ld01/j;Ld01/k;)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_3
    :try_start_3
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string v0, "Already executed."

    .line 60
    .line 61
    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p1

    .line 65
    :goto_1
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 66
    throw p1
.end method

.method public final isCanceled()Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Lretrofit2/OkHttpCall;->i:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    monitor-enter p0

    .line 8
    :try_start_0
    iget-object v0, p0, Lretrofit2/OkHttpCall;->j:Ld01/j;

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    invoke-interface {v0}, Ld01/j;->isCanceled()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :catchall_0
    move-exception v0

    .line 20
    goto :goto_1

    .line 21
    :cond_1
    const/4 v1, 0x0

    .line 22
    :goto_0
    monitor-exit p0

    .line 23
    return v1

    .line 24
    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    throw v0
.end method

.method public final declared-synchronized request()Ld01/k0;
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-virtual {p0}, Lretrofit2/OkHttpCall;->b()Ld01/j;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    invoke-interface {v0}, Ld01/j;->request()Ld01/k0;

    .line 7
    .line 8
    .line 9
    move-result-object v0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    monitor-exit p0

    .line 11
    return-object v0

    .line 12
    :catchall_0
    move-exception v0

    .line 13
    goto :goto_0

    .line 14
    :catch_0
    move-exception v0

    .line 15
    :try_start_1
    new-instance v1, Ljava/lang/RuntimeException;

    .line 16
    .line 17
    const-string v2, "Unable to create request."

    .line 18
    .line 19
    invoke-direct {v1, v2, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 20
    .line 21
    .line 22
    throw v1

    .line 23
    :goto_0
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 24
    throw v0
.end method
