.class public final synthetic Lfl/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lt10/k;

.field public final synthetic g:Lr1/b;

.field public final synthetic h:Ltj/h;

.field public final synthetic i:Ltj/h;

.field public final synthetic j:Ltj/h;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lt10/k;Lr1/b;Ltj/h;Ltj/h;Ltj/h;I)V
    .locals 0

    .line 1
    iput p7, p0, Lfl/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lfl/j;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lfl/j;->f:Lt10/k;

    .line 6
    .line 7
    iput-object p3, p0, Lfl/j;->g:Lr1/b;

    .line 8
    .line 9
    iput-object p4, p0, Lfl/j;->h:Ltj/h;

    .line 10
    .line 11
    iput-object p5, p0, Lfl/j;->i:Ltj/h;

    .line 12
    .line 13
    iput-object p6, p0, Lfl/j;->j:Ltj/h;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lfl/j;->d:I

    .line 2
    .line 3
    const-class v1, Lfl/g;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    packed-switch v0, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    check-cast p1, Lhi/a;

    .line 10
    .line 11
    const-string v0, "$this$single"

    .line 12
    .line 13
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 17
    .line 18
    const-class v3, Landroid/content/Context;

    .line 19
    .line 20
    invoke-virtual {v0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    check-cast p1, Lii/a;

    .line 25
    .line 26
    invoke-virtual {p1, v3}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    check-cast v3, Landroid/content/Context;

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    check-cast p1, Lfl/g;

    .line 41
    .line 42
    iget-object v0, p1, Lfl/g;->c:Ljava/io/File;

    .line 43
    .line 44
    new-instance v1, Lfl/b;

    .line 45
    .line 46
    iget-object v4, p0, Lfl/j;->f:Lt10/k;

    .line 47
    .line 48
    invoke-direct {v1, v4, v2}, Lfl/b;-><init>(Ljava/lang/Object;I)V

    .line 49
    .line 50
    .line 51
    new-instance v4, Lfl/d;

    .line 52
    .line 53
    iget-object v5, p1, Lfl/g;->b:Landroid/content/SharedPreferences;

    .line 54
    .line 55
    iget-object v6, p0, Lfl/j;->h:Ltj/h;

    .line 56
    .line 57
    iget-object v7, p0, Lfl/j;->i:Ltj/h;

    .line 58
    .line 59
    invoke-direct {v4, v5, v6, v7}, Lfl/d;-><init>(Landroid/content/SharedPreferences;Ltj/h;Ltj/h;)V

    .line 60
    .line 61
    .line 62
    new-instance v5, Lfl/e;

    .line 63
    .line 64
    iget-object p1, p1, Lfl/g;->a:Landroid/content/SharedPreferences;

    .line 65
    .line 66
    invoke-direct {v5, p1}, Lfl/e;-><init>(Landroid/content/SharedPreferences;)V

    .line 67
    .line 68
    .line 69
    new-instance p1, Lfl/e;

    .line 70
    .line 71
    iget-object v6, p0, Lfl/j;->j:Ltj/h;

    .line 72
    .line 73
    invoke-direct {p1, v6}, Lfl/e;-><init>(Ltj/h;)V

    .line 74
    .line 75
    .line 76
    sget-object v6, Lfl/i;->a:Lvz0/t;

    .line 77
    .line 78
    const-string v6, "cache"

    .line 79
    .line 80
    invoke-static {v0, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    new-instance v6, Ld01/g0;

    .line 84
    .line 85
    invoke-direct {v6}, Ld01/g0;-><init>()V

    .line 86
    .line 87
    .line 88
    sget-object v7, Lfl/l;->a:Ljava/lang/String;

    .line 89
    .line 90
    new-instance v7, Lfl/k;

    .line 91
    .line 92
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v6, v7}, Ld01/g0;->a(Ld01/c0;)V

    .line 96
    .line 97
    .line 98
    iget-object v7, v6, Ld01/g0;->d:Ljava/util/ArrayList;

    .line 99
    .line 100
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    invoke-virtual {v6, v1}, Ld01/g0;->a(Ld01/c0;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v6, p1}, Ld01/g0;->a(Ld01/c0;)V

    .line 107
    .line 108
    .line 109
    new-instance p1, Lfl/h;

    .line 110
    .line 111
    iget-object v1, p0, Lfl/j;->g:Lr1/b;

    .line 112
    .line 113
    invoke-direct {p1, v1, v2}, Lfl/h;-><init>(Lr1/b;I)V

    .line 114
    .line 115
    .line 116
    new-instance v1, Lfl/b;

    .line 117
    .line 118
    const/4 v2, 0x1

    .line 119
    invoke-direct {v1, p1, v2}, Lfl/b;-><init>(Ljava/lang/Object;I)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    invoke-virtual {v7, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    sget-object p1, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 129
    .line 130
    const-wide/16 v1, 0x14

    .line 131
    .line 132
    invoke-virtual {v6, v1, v2, p1}, Ld01/g0;->b(JLjava/util/concurrent/TimeUnit;)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v6, v1, v2, p1}, Ld01/g0;->f(JLjava/util/concurrent/TimeUnit;)V

    .line 136
    .line 137
    .line 138
    const-wide/16 v1, 0x32

    .line 139
    .line 140
    invoke-virtual {v6, v1, v2, p1}, Ld01/g0;->d(JLjava/util/concurrent/TimeUnit;)V

    .line 141
    .line 142
    .line 143
    new-instance p1, Ld01/g;

    .line 144
    .line 145
    invoke-direct {p1, v0}, Ld01/g;-><init>(Ljava/io/File;)V

    .line 146
    .line 147
    .line 148
    iput-object p1, v6, Ld01/g0;->l:Ld01/g;

    .line 149
    .line 150
    new-instance p1, Ld01/h0;

    .line 151
    .line 152
    invoke-direct {p1, v6}, Ld01/h0;-><init>(Ld01/g0;)V

    .line 153
    .line 154
    .line 155
    new-instance v0, Lretrofit2/Retrofit$Builder;

    .line 156
    .line 157
    invoke-direct {v0}, Lretrofit2/Retrofit$Builder;-><init>()V

    .line 158
    .line 159
    .line 160
    iget-object p0, p0, Lfl/j;->e:Ljava/lang/String;

    .line 161
    .line 162
    invoke-virtual {v0, p0}, Lretrofit2/Retrofit$Builder;->c(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    iput-object p1, v0, Lretrofit2/Retrofit$Builder;->a:Ld01/i;

    .line 166
    .line 167
    new-instance p0, Lji/a;

    .line 168
    .line 169
    invoke-direct {p0}, Lretrofit2/CallAdapter$Factory;-><init>()V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v0, p0}, Lretrofit2/Retrofit$Builder;->a(Lretrofit2/CallAdapter$Factory;)V

    .line 173
    .line 174
    .line 175
    new-instance p0, Lji/b;

    .line 176
    .line 177
    new-instance p1, Ljava/io/File;

    .line 178
    .line 179
    invoke-virtual {v3}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    .line 180
    .line 181
    .line 182
    move-result-object v1

    .line 183
    const-string v2, "pdf/"

    .line 184
    .line 185
    invoke-direct {p1, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    invoke-direct {p0, p1}, Lji/b;-><init>(Ljava/io/File;)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v0, p0}, Lretrofit2/Retrofit$Builder;->b(Lretrofit2/Converter$Factory;)V

    .line 192
    .line 193
    .line 194
    sget-object p0, Lfl/i;->a:Lvz0/t;

    .line 195
    .line 196
    sget-object p1, Ld01/d0;->e:Lly0/n;

    .line 197
    .line 198
    const-string p1, "application/json"

    .line 199
    .line 200
    invoke-static {p1}, Ljp/ue;->c(Ljava/lang/String;)Ld01/d0;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    const-string v1, "<this>"

    .line 205
    .line 206
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    new-instance v1, Lzv/a;

    .line 210
    .line 211
    new-instance v2, Lt1/j0;

    .line 212
    .line 213
    invoke-direct {v2, p0}, Lt1/j0;-><init>(Lvz0/t;)V

    .line 214
    .line 215
    .line 216
    invoke-direct {v1, p1, v2}, Lzv/a;-><init>(Ld01/d0;Lt1/j0;)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {v0, v1}, Lretrofit2/Retrofit$Builder;->b(Lretrofit2/Converter$Factory;)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v0}, Lretrofit2/Retrofit$Builder;->d()Lretrofit2/Retrofit;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    return-object p0

    .line 227
    :pswitch_0
    check-cast p1, Lhi/c;

    .line 228
    .line 229
    const-string v0, "$this$module"

    .line 230
    .line 231
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    new-instance v3, Lfl/j;

    .line 235
    .line 236
    const/4 v10, 0x1

    .line 237
    iget-object v4, p0, Lfl/j;->e:Ljava/lang/String;

    .line 238
    .line 239
    iget-object v5, p0, Lfl/j;->f:Lt10/k;

    .line 240
    .line 241
    iget-object v6, p0, Lfl/j;->g:Lr1/b;

    .line 242
    .line 243
    iget-object v7, p0, Lfl/j;->h:Ltj/h;

    .line 244
    .line 245
    iget-object v8, p0, Lfl/j;->i:Ltj/h;

    .line 246
    .line 247
    iget-object v9, p0, Lfl/j;->j:Ltj/h;

    .line 248
    .line 249
    invoke-direct/range {v3 .. v10}, Lfl/j;-><init>(Ljava/lang/String;Lt10/k;Lr1/b;Ltj/h;Ltj/h;Ltj/h;I)V

    .line 250
    .line 251
    .line 252
    new-instance p0, Lii/b;

    .line 253
    .line 254
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 255
    .line 256
    const-class v4, Lretrofit2/Retrofit;

    .line 257
    .line 258
    invoke-virtual {v0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 259
    .line 260
    .line 261
    move-result-object v4

    .line 262
    invoke-direct {p0, v2, v3, v4}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 263
    .line 264
    .line 265
    iget-object p1, p1, Lhi/c;->a:Ljava/util/ArrayList;

    .line 266
    .line 267
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 268
    .line 269
    .line 270
    new-instance p0, Lf31/n;

    .line 271
    .line 272
    const/16 v3, 0xf

    .line 273
    .line 274
    invoke-direct {p0, v3}, Lf31/n;-><init>(I)V

    .line 275
    .line 276
    .line 277
    new-instance v3, Lii/b;

    .line 278
    .line 279
    const-class v4, Ld01/h0;

    .line 280
    .line 281
    invoke-virtual {v0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 282
    .line 283
    .line 284
    move-result-object v4

    .line 285
    invoke-direct {v3, v2, p0, v4}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 286
    .line 287
    .line 288
    invoke-virtual {p1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 289
    .line 290
    .line 291
    new-instance p0, Lf31/n;

    .line 292
    .line 293
    const/16 v3, 0x10

    .line 294
    .line 295
    invoke-direct {p0, v3}, Lf31/n;-><init>(I)V

    .line 296
    .line 297
    .line 298
    new-instance v3, Lii/b;

    .line 299
    .line 300
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 301
    .line 302
    .line 303
    move-result-object v0

    .line 304
    invoke-direct {v3, v2, p0, v0}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 305
    .line 306
    .line 307
    invoke-virtual {p1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 308
    .line 309
    .line 310
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 311
    .line 312
    return-object p0

    .line 313
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
