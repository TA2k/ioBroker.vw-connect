.class public final synthetic Lsc0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lk21/a;


# direct methods
.method public synthetic constructor <init>(Lk21/a;I)V
    .locals 0

    .line 1
    iput p2, p0, Lsc0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lsc0/a;->e:Lk21/a;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lsc0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-class v0, Ld01/h0;

    .line 7
    .line 8
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 9
    .line 10
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget-object p0, p0, Lsc0/a;->e:Lk21/a;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    invoke-virtual {p0, v0, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Ld01/i;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    const-string v0, "AboutLibraries"

    .line 25
    .line 26
    const-class v1, Landroid/content/Context;

    .line 27
    .line 28
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 29
    .line 30
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    iget-object p0, p0, Lsc0/a;->e:Lk21/a;

    .line 35
    .line 36
    const/4 v2, 0x0

    .line 37
    invoke-virtual {p0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    check-cast p0, Landroid/content/Context;

    .line 42
    .line 43
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    const-string v3, "raw"

    .line 48
    .line 49
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v4

    .line 53
    const-string v5, "aboutlibraries"

    .line 54
    .line 55
    invoke-virtual {v1, v5, v3, v4}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-virtual {p0, v1}, Landroid/content/res/Resources;->openRawResource(I)Ljava/io/InputStream;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    const-string v1, "openRawResource(...)"

    .line 68
    .line 69
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    sget-object v1, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 73
    .line 74
    new-instance v3, Ljava/io/InputStreamReader;

    .line 75
    .line 76
    invoke-direct {v3, p0, v1}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/nio/charset/Charset;)V

    .line 77
    .line 78
    .line 79
    new-instance p0, Ljava/io/BufferedReader;

    .line 80
    .line 81
    const/16 v1, 0x2000

    .line 82
    .line 83
    invoke-direct {p0, v3, v1}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 84
    .line 85
    .line 86
    :try_start_1
    invoke-static {p0}, Llp/xd;->b(Ljava/io/Reader;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 90
    :try_start_2
    invoke-interface {p0}, Ljava/io/Closeable;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 91
    .line 92
    .line 93
    move-object v2, v1

    .line 94
    goto :goto_0

    .line 95
    :catchall_0
    move-exception v1

    .line 96
    :try_start_3
    throw v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 97
    :catchall_1
    move-exception v3

    .line 98
    :try_start_4
    invoke-static {p0, v1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 99
    .line 100
    .line 101
    throw v3
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 102
    :catchall_2
    const-string p0, "Unable to retrieve library information given the `raw` resource identifier. \nPlease make sure either the gradle plugin is properly set up, or the file is manually provided. "

    .line 103
    .line 104
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 105
    .line 106
    .line 107
    const-string p0, "Could not retrieve libraries"

    .line 108
    .line 109
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 110
    .line 111
    invoke-virtual {v1, p0}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    :goto_0
    if-eqz v2, :cond_2

    .line 115
    .line 116
    :try_start_5
    new-instance p0, Lorg/json/JSONObject;

    .line 117
    .line 118
    invoke-direct {p0, v2}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    const-string v1, "licenses"

    .line 122
    .line 123
    invoke-virtual {p0, v1}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    new-instance v2, Ldl0/k;

    .line 128
    .line 129
    const/4 v3, 0x5

    .line 130
    invoke-direct {v2, v3}, Ldl0/k;-><init>(I)V

    .line 131
    .line 132
    .line 133
    invoke-static {v1, v2}, Ljp/kg;->b(Lorg/json/JSONObject;Ldl0/k;)Ljava/util/List;

    .line 134
    .line 135
    .line 136
    move-result-object v1

    .line 137
    move-object v2, v1

    .line 138
    check-cast v2, Ljava/lang/Iterable;

    .line 139
    .line 140
    const/16 v3, 0xa

    .line 141
    .line 142
    invoke-static {v2, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 143
    .line 144
    .line 145
    move-result v3

    .line 146
    invoke-static {v3}, Lmx0/x;->k(I)I

    .line 147
    .line 148
    .line 149
    move-result v3

    .line 150
    const/16 v4, 0x10

    .line 151
    .line 152
    if-ge v3, v4, :cond_0

    .line 153
    .line 154
    move v3, v4

    .line 155
    :cond_0
    new-instance v4, Ljava/util/LinkedHashMap;

    .line 156
    .line 157
    invoke-direct {v4, v3}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 158
    .line 159
    .line 160
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 165
    .line 166
    .line 167
    move-result v3

    .line 168
    if-eqz v3, :cond_1

    .line 169
    .line 170
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    move-object v5, v3

    .line 175
    check-cast v5, Lcw/l;

    .line 176
    .line 177
    iget-object v5, v5, Lcw/l;->f:Ljava/lang/String;

    .line 178
    .line 179
    invoke-interface {v4, v5, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    goto :goto_1

    .line 183
    :catchall_3
    move-exception p0

    .line 184
    goto :goto_2

    .line 185
    :cond_1
    const-string v2, "libraries"

    .line 186
    .line 187
    invoke-virtual {p0, v2}, Lorg/json/JSONObject;->getJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    new-instance v2, La2/e;

    .line 192
    .line 193
    const/16 v3, 0x16

    .line 194
    .line 195
    invoke-direct {v2, v4, v3}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 196
    .line 197
    .line 198
    invoke-static {p0, v2}, Ljp/kg;->a(Lorg/json/JSONArray;Lay0/k;)Ljava/util/List;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    new-instance v2, Lb81/b;

    .line 203
    .line 204
    const/4 v3, 0x4

    .line 205
    invoke-direct {v2, v3, p0, v1}, Lb81/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 206
    .line 207
    .line 208
    goto :goto_3

    .line 209
    :goto_2
    new-instance v1, Ljava/lang/StringBuilder;

    .line 210
    .line 211
    const-string v2, "Failed to parse the meta data *.json file: "

    .line 212
    .line 213
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 217
    .line 218
    .line 219
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object p0

    .line 223
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 224
    .line 225
    .line 226
    new-instance v2, Lb81/b;

    .line 227
    .line 228
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 229
    .line 230
    const/4 v0, 0x4

    .line 231
    invoke-direct {v2, v0, p0, p0}, Lb81/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    :goto_3
    iget-object p0, v2, Lb81/b;->e:Ljava/lang/Object;

    .line 235
    .line 236
    iget-object v0, v2, Lb81/b;->f:Ljava/lang/Object;

    .line 237
    .line 238
    new-instance v1, Lbw/c;

    .line 239
    .line 240
    check-cast p0, Ljava/lang/Iterable;

    .line 241
    .line 242
    new-instance v2, La5/f;

    .line 243
    .line 244
    const/4 v3, 0x4

    .line 245
    invoke-direct {v2, v3}, La5/f;-><init>(I)V

    .line 246
    .line 247
    .line 248
    invoke-static {p0, v2}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    check-cast p0, Ljava/lang/Iterable;

    .line 253
    .line 254
    invoke-static {p0}, Ljp/kg;->c(Ljava/lang/Iterable;)Lqy0/b;

    .line 255
    .line 256
    .line 257
    move-result-object p0

    .line 258
    check-cast v0, Ljava/lang/Iterable;

    .line 259
    .line 260
    invoke-static {v0}, Ljp/kg;->d(Ljava/lang/Iterable;)Lqy0/c;

    .line 261
    .line 262
    .line 263
    move-result-object v0

    .line 264
    invoke-direct {v1, p0, v0}, Lbw/c;-><init>(Lqy0/b;Lqy0/c;)V

    .line 265
    .line 266
    .line 267
    return-object v1

    .line 268
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 269
    .line 270
    const-string v0, "Please provide the required library data via the available APIs.\nDepending on the platform this can be done for example via `Libs.Builder().withJson()`.\nFor Android there exists an `Libs.Builder().withContext(context).build()`, automatically loading the `aboutlibraries.json` file from the `raw` resources folder.\nWhen using compose or other parent modules, please check their corresponding APIs."

    .line 271
    .line 272
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    throw p0

    .line 276
    :pswitch_1
    iget-object p0, p0, Lsc0/a;->e:Lk21/a;

    .line 277
    .line 278
    invoke-static {p0}, Llp/va;->a(Lk21/a;)Landroid/content/Context;

    .line 279
    .line 280
    .line 281
    move-result-object p0

    .line 282
    const-string v0, "myskoda"

    .line 283
    .line 284
    invoke-static {p0, v0}, Ljp/hd;->b(Landroid/content/Context;Ljava/lang/String;)Ljava/io/File;

    .line 285
    .line 286
    .line 287
    move-result-object p0

    .line 288
    return-object p0

    .line 289
    :pswitch_2
    const-string v0, "bff-api-auth-no-ssl-pinning"

    .line 290
    .line 291
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 292
    .line 293
    .line 294
    move-result-object v0

    .line 295
    const-class v1, Ld01/h0;

    .line 296
    .line 297
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 298
    .line 299
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 300
    .line 301
    .line 302
    move-result-object v1

    .line 303
    iget-object p0, p0, Lsc0/a;->e:Lk21/a;

    .line 304
    .line 305
    const/4 v2, 0x0

    .line 306
    invoke-virtual {p0, v1, v0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    move-result-object p0

    .line 310
    check-cast p0, Ld01/i;

    .line 311
    .line 312
    return-object p0

    .line 313
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
