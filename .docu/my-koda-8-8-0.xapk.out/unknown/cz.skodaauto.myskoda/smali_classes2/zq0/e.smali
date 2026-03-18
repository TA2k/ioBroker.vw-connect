.class public final Lzq0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Luq0/a;

.field public final c:Lzq0/h;


# direct methods
.method public constructor <init>(Landroid/content/Context;Luq0/a;Lzq0/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzq0/e;->a:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p2, p0, Lzq0/e;->b:Luq0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lzq0/e;->c:Lzq0/h;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lzq0/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Ljava/lang/String;Ljavax/crypto/Cipher;Lay0/n;Lay0/n;)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Landroid/content/Context;->getMainExecutor()Ljava/util/concurrent/Executor;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lzq0/b;

    .line 6
    .line 7
    invoke-direct {v1, p4, p5, p2, p3}, Lzq0/b;-><init>(Lay0/n;Lay0/n;Ljava/lang/String;Ljavax/crypto/Cipher;)V

    .line 8
    .line 9
    .line 10
    if-eqz v0, :cond_c

    .line 11
    .line 12
    invoke-virtual {p1}, Landroidx/fragment/app/o0;->getSupportFragmentManager()Landroidx/fragment/app/j1;

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    invoke-interface {p1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 17
    .line 18
    .line 19
    move-result-object p4

    .line 20
    invoke-interface {p1}, Landroidx/lifecycle/k;->getDefaultViewModelProviderFactory()Landroidx/lifecycle/e1;

    .line 21
    .line 22
    .line 23
    move-result-object p5

    .line 24
    invoke-interface {p1}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    const-string v2, "store"

    .line 29
    .line 30
    invoke-static {p4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-string v2, "factory"

    .line 34
    .line 35
    invoke-static {p5, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const-string v2, "defaultCreationExtras"

    .line 39
    .line 40
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    new-instance v2, Lcom/google/firebase/messaging/w;

    .line 44
    .line 45
    invoke-direct {v2, p4, p5, p1}, Lcom/google/firebase/messaging/w;-><init>(Landroidx/lifecycle/h1;Landroidx/lifecycle/e1;Lp7/c;)V

    .line 46
    .line 47
    .line 48
    const-class p1, Lq/s;

    .line 49
    .line 50
    invoke-static {p1}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    const-string p4, "modelClass"

    .line 55
    .line 56
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-interface {p1}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p4

    .line 63
    if-eqz p4, :cond_b

    .line 64
    .line 65
    const-string p5, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    .line 66
    .line 67
    invoke-virtual {p5, p4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p4

    .line 71
    invoke-virtual {v2, p1, p4}, Lcom/google/firebase/messaging/w;->l(Lhy0/d;Ljava/lang/String;)Landroidx/lifecycle/b1;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    check-cast p1, Lq/s;

    .line 76
    .line 77
    iput-object v0, p1, Lq/s;->d:Ljava/util/concurrent/Executor;

    .line 78
    .line 79
    iput-object v1, p1, Lq/s;->e:Ljp/he;

    .line 80
    .line 81
    iget-object p0, p0, Lzq0/e;->a:Landroid/content/Context;

    .line 82
    .line 83
    const p1, 0x7f12122f

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0, p1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    const p4, 0x7f121227

    .line 91
    .line 92
    .line 93
    invoke-virtual {p0, p4}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object p4

    .line 97
    const p5, 0x7f120373

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0, p5}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 105
    .line 106
    .line 107
    move-result p5

    .line 108
    if-nez p5, :cond_a

    .line 109
    .line 110
    const/4 p5, 0x0

    .line 111
    invoke-static {p5}, Ljp/ge;->b(I)Z

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    if-eqz v0, :cond_9

    .line 116
    .line 117
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    if-nez v0, :cond_8

    .line 122
    .line 123
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 124
    .line 125
    .line 126
    new-instance v0, Lil/g;

    .line 127
    .line 128
    const/16 v1, 0x1a

    .line 129
    .line 130
    invoke-direct {v0, p1, p4, p0, v1}, Lil/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 131
    .line 132
    .line 133
    new-instance p0, Lcom/google/firebase/messaging/w;

    .line 134
    .line 135
    invoke-direct {p0, p3}, Lcom/google/firebase/messaging/w;-><init>(Ljavax/crypto/Cipher;)V

    .line 136
    .line 137
    .line 138
    const/16 p1, 0xf

    .line 139
    .line 140
    const/16 p3, 0xff

    .line 141
    .line 142
    and-int/2addr p1, p3

    .line 143
    if-eq p1, p3, :cond_7

    .line 144
    .line 145
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 146
    .line 147
    const/16 p3, 0x1e

    .line 148
    .line 149
    if-ge p1, p3, :cond_1

    .line 150
    .line 151
    const/16 p1, 0xf

    .line 152
    .line 153
    invoke-static {p1}, Ljp/ge;->a(I)Z

    .line 154
    .line 155
    .line 156
    move-result p1

    .line 157
    if-nez p1, :cond_0

    .line 158
    .line 159
    goto :goto_0

    .line 160
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 161
    .line 162
    const-string p1, "Crypto-based authentication is not supported for device credential prior to API 30."

    .line 163
    .line 164
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    throw p0

    .line 168
    :cond_1
    :goto_0
    const-string p1, "BiometricPromptCompat"

    .line 169
    .line 170
    if-nez p2, :cond_2

    .line 171
    .line 172
    const-string p0, "Unable to start authentication. Client fragment manager was null."

    .line 173
    .line 174
    invoke-static {p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 175
    .line 176
    .line 177
    return-void

    .line 178
    :cond_2
    invoke-virtual {p2}, Landroidx/fragment/app/j1;->P()Z

    .line 179
    .line 180
    .line 181
    move-result p3

    .line 182
    if-eqz p3, :cond_3

    .line 183
    .line 184
    const-string p0, "Unable to start authentication. Called after onSaveInstanceState()."

    .line 185
    .line 186
    invoke-static {p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 187
    .line 188
    .line 189
    return-void

    .line 190
    :cond_3
    const-string p1, "androidx.biometric.BiometricFragment"

    .line 191
    .line 192
    invoke-virtual {p2, p1}, Landroidx/fragment/app/j1;->D(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 193
    .line 194
    .line 195
    move-result-object p3

    .line 196
    check-cast p3, Lq/k;

    .line 197
    .line 198
    if-nez p3, :cond_4

    .line 199
    .line 200
    new-instance p3, Lq/k;

    .line 201
    .line 202
    invoke-direct {p3}, Lq/k;-><init>()V

    .line 203
    .line 204
    .line 205
    new-instance p4, Landroidx/fragment/app/a;

    .line 206
    .line 207
    invoke-direct {p4, p2}, Landroidx/fragment/app/a;-><init>(Landroidx/fragment/app/j1;)V

    .line 208
    .line 209
    .line 210
    const/4 v1, 0x1

    .line 211
    invoke-virtual {p4, p5, p3, p1, v1}, Landroidx/fragment/app/a;->f(ILandroidx/fragment/app/j0;Ljava/lang/String;I)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {p4, v1, v1}, Landroidx/fragment/app/a;->e(ZZ)I

    .line 215
    .line 216
    .line 217
    invoke-virtual {p2, v1}, Landroidx/fragment/app/j1;->z(Z)Z

    .line 218
    .line 219
    .line 220
    invoke-virtual {p2}, Landroidx/fragment/app/j1;->F()V

    .line 221
    .line 222
    .line 223
    :cond_4
    invoke-virtual {p3}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 224
    .line 225
    .line 226
    move-result-object p1

    .line 227
    if-nez p1, :cond_5

    .line 228
    .line 229
    const-string p0, "BiometricFragment"

    .line 230
    .line 231
    const-string p1, "Not launching prompt. Client activity was null."

    .line 232
    .line 233
    invoke-static {p0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 234
    .line 235
    .line 236
    return-void

    .line 237
    :cond_5
    iget-object p1, p3, Lq/k;->e:Lq/s;

    .line 238
    .line 239
    iput-object v0, p1, Lq/s;->f:Lil/g;

    .line 240
    .line 241
    iput-object p0, p1, Lq/s;->g:Lcom/google/firebase/messaging/w;

    .line 242
    .line 243
    iget-boolean p0, p1, Lq/s;->n:Z

    .line 244
    .line 245
    if-eqz p0, :cond_6

    .line 246
    .line 247
    iget-object p0, p3, Lq/k;->d:Landroid/os/Handler;

    .line 248
    .line 249
    new-instance p1, Lq/j;

    .line 250
    .line 251
    invoke-direct {p1, p3}, Lq/j;-><init>(Lq/k;)V

    .line 252
    .line 253
    .line 254
    const-wide/16 p2, 0x258

    .line 255
    .line 256
    invoke-virtual {p0, p1, p2, p3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 257
    .line 258
    .line 259
    return-void

    .line 260
    :cond_6
    invoke-virtual {p3}, Lq/k;->n()V

    .line 261
    .line 262
    .line 263
    return-void

    .line 264
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 265
    .line 266
    const-string p1, "Crypto-based authentication is not supported for Class 2 (Weak) biometrics."

    .line 267
    .line 268
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 269
    .line 270
    .line 271
    throw p0

    .line 272
    :cond_8
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 273
    .line 274
    const-string p1, "Negative text must be set and non-empty."

    .line 275
    .line 276
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 277
    .line 278
    .line 279
    throw p0

    .line 280
    :cond_9
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 281
    .line 282
    new-instance p1, Ljava/lang/StringBuilder;

    .line 283
    .line 284
    const-string p2, "Authenticator combination is unsupported on API "

    .line 285
    .line 286
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 290
    .line 291
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 292
    .line 293
    .line 294
    const-string p2, ": "

    .line 295
    .line 296
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 297
    .line 298
    .line 299
    invoke-static {p5}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 300
    .line 301
    .line 302
    move-result-object p2

    .line 303
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 304
    .line 305
    .line 306
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object p1

    .line 310
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    throw p0

    .line 314
    :cond_a
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 315
    .line 316
    const-string p1, "Title must be set and non-empty."

    .line 317
    .line 318
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    throw p0

    .line 322
    :cond_b
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 323
    .line 324
    const-string p1, "Local and anonymous classes can not be ViewModels"

    .line 325
    .line 326
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    throw p0

    .line 330
    :cond_c
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 331
    .line 332
    const-string p1, "Executor must not be null."

    .line 333
    .line 334
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 335
    .line 336
    .line 337
    throw p0
.end method
