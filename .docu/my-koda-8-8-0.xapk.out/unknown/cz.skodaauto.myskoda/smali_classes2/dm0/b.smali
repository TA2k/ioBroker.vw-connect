.class public final Ldm0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;

.field public final c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lam0/d;Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Ldm0/b;->a:I

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-object p1, p0, Ldm0/b;->b:Ljava/lang/Object;

    .line 9
    iput-object p2, p0, Ldm0/b;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lxl0/o;Ljava/util/List;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Ldm0/b;->a:I

    const-string v0, "interceptors"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ldm0/b;->b:Ljava/lang/Object;

    .line 3
    iput-object p2, p0, Ldm0/b;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lxl0/o;Lxl0/g;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ldm0/b;->a:I

    const-string v0, "environmentHostResource"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Ldm0/b;->b:Ljava/lang/Object;

    .line 6
    iput-object p2, p0, Ldm0/b;->c:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final intercept(Ld01/b0;)Ld01/t0;
    .locals 6

    .line 1
    iget v0, p0, Ldm0/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ldm0/h;

    .line 7
    .line 8
    const/4 v1, 0x2

    .line 9
    const/4 v2, 0x0

    .line 10
    invoke-direct {v0, p0, v2, v1}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    sget-object v1, Lpx0/h;->d:Lpx0/h;

    .line 14
    .line 15
    invoke-static {v1, v0}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lcm0/b;

    .line 20
    .line 21
    check-cast p1, Li01/f;

    .line 22
    .line 23
    iget-object v1, p1, Li01/f;->e:Ld01/k0;

    .line 24
    .line 25
    iget-object p0, p0, Ldm0/b;->c:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Ljava/util/List;

    .line 28
    .line 29
    check-cast p0, Ljava/lang/Iterable;

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_0

    .line 40
    .line 41
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    check-cast v2, Ldm0/l;

    .line 46
    .line 47
    invoke-interface {v2, v0, v1}, Ldm0/l;->a(Lcm0/b;Ld01/k0;)Ld01/k0;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    goto :goto_0

    .line 52
    :cond_0
    invoke-virtual {p1, v1}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_0
    check-cast p1, Li01/f;

    .line 58
    .line 59
    iget-object v0, p1, Li01/f;->e:Ld01/k0;

    .line 60
    .line 61
    iget-object v1, v0, Ld01/k0;->a:Ld01/a0;

    .line 62
    .line 63
    iget-object v2, p0, Ldm0/b;->c:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v2, Lxl0/g;

    .line 66
    .line 67
    new-instance v3, Ldm0/h;

    .line 68
    .line 69
    const/4 v4, 0x1

    .line 70
    const/4 v5, 0x0

    .line 71
    invoke-direct {v3, p0, v5, v4}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 72
    .line 73
    .line 74
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 75
    .line 76
    invoke-static {p0, v3}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    check-cast p0, Lcm0/b;

    .line 81
    .line 82
    invoke-interface {v2, p0}, Lxl0/g;->a(Lcm0/b;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-virtual {v1}, Ld01/a0;->g()Ld01/z;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-virtual {v1, p0}, Ld01/z;->f(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v1}, Ld01/z;->c()Ld01/a0;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-virtual {v0}, Ld01/k0;->b()Ld01/j0;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    iput-object p0, v0, Ld01/j0;->a:Ld01/a0;

    .line 102
    .line 103
    new-instance p0, Lcm0/e;

    .line 104
    .line 105
    invoke-interface {v2}, Lxl0/g;->getSystemId()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    invoke-direct {p0, v1}, Lcm0/e;-><init>(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const-class v1, Lcm0/e;

    .line 113
    .line 114
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 115
    .line 116
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    const-string v2, "type"

    .line 121
    .line 122
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    iget-object v2, v0, Ld01/j0;->e:Ljp/ng;

    .line 126
    .line 127
    invoke-virtual {v2, v1, p0}, Ljp/ng;->b(Lhy0/d;Ljava/lang/Object;)Ljp/ng;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    iput-object p0, v0, Ld01/j0;->e:Ljp/ng;

    .line 132
    .line 133
    new-instance p0, Ld01/k0;

    .line 134
    .line 135
    invoke-direct {p0, v0}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {p1, p0}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    return-object p0

    .line 143
    :pswitch_1
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    const/4 v1, 0x0

    .line 148
    invoke-virtual {v0, v1}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    if-nez v0, :cond_1

    .line 153
    .line 154
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    :cond_1
    iget-object v1, p0, Ldm0/b;->c:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast v1, Landroid/content/Context;

    .line 161
    .line 162
    const-string v2, "phone"

    .line 163
    .line 164
    invoke-virtual {v1, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v1

    .line 168
    const-string v2, "null cannot be cast to non-null type android.telephony.TelephonyManager"

    .line 169
    .line 170
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    check-cast v1, Landroid/telephony/TelephonyManager;

    .line 174
    .line 175
    invoke-virtual {v0}, Ljava/util/Locale;->getCountry()Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v2

    .line 179
    invoke-static {v2}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 180
    .line 181
    .line 182
    move-result v3

    .line 183
    if-eqz v3, :cond_2

    .line 184
    .line 185
    invoke-virtual {v1}, Landroid/telephony/TelephonyManager;->getNetworkCountryIso()Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v2

    .line 189
    :cond_2
    check-cast p1, Li01/f;

    .line 190
    .line 191
    iget-object v1, p1, Li01/f;->e:Ld01/k0;

    .line 192
    .line 193
    invoke-virtual {v1}, Ld01/k0;->b()Ld01/j0;

    .line 194
    .line 195
    .line 196
    move-result-object v1

    .line 197
    const-string v3, "X-APP-VERSION-NAME"

    .line 198
    .line 199
    const-string v4, "8.8.0"

    .line 200
    .line 201
    invoke-virtual {v1, v3, v4}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    const v3, 0xef93c9a

    .line 205
    .line 206
    .line 207
    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object v3

    .line 211
    const-string v4, "X-APP-VERSION-CODE"

    .line 212
    .line 213
    invoke-virtual {v1, v4, v3}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    new-instance v3, La50/a;

    .line 217
    .line 218
    const/16 v4, 0x1c

    .line 219
    .line 220
    const/4 v5, 0x0

    .line 221
    invoke-direct {v3, p0, v5, v4}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 222
    .line 223
    .line 224
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 225
    .line 226
    invoke-static {p0, v3}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    check-cast p0, Ljava/lang/String;

    .line 231
    .line 232
    const-string v3, "X-APP-INSTALLATION-ID"

    .line 233
    .line 234
    invoke-virtual {v1, v3, p0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    const-string p0, "X-APP-PLATFORM"

    .line 238
    .line 239
    const-string v3, "Android"

    .line 240
    .line 241
    invoke-virtual {v1, p0, v3}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    invoke-virtual {v0}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    .line 245
    .line 246
    .line 247
    move-result-object p0

    .line 248
    const-string v0, "getLanguage(...)"

    .line 249
    .line 250
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    const-string v0, "X-DEVICE-LANGUAGE"

    .line 254
    .line 255
    invoke-virtual {v1, v0, p0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 256
    .line 257
    .line 258
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 259
    .line 260
    .line 261
    const-string p0, "X-DEVICE-COUNTRY"

    .line 262
    .line 263
    invoke-virtual {v1, p0, v2}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    const-string p0, "User-Agent"

    .line 267
    .line 268
    const-string v0, "MySkoda/Android/8.8.0/251215002"

    .line 269
    .line 270
    invoke-virtual {v1, p0, v0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 271
    .line 272
    .line 273
    new-instance p0, Ld01/k0;

    .line 274
    .line 275
    invoke-direct {p0, v1}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {p1, p0}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 279
    .line 280
    .line 281
    move-result-object p0

    .line 282
    return-object p0

    .line 283
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
