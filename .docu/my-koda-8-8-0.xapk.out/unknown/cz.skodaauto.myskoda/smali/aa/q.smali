.class public final Laa/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/j0;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;

.field public final synthetic d:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Laa/q;->a:I

    iput-object p1, p0, Laa/q;->c:Ljava/lang/Object;

    iput-object p2, p0, Laa/q;->d:Ljava/lang/Object;

    iput-object p3, p0, Laa/q;->b:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lv2/o;Ljava/lang/Object;Lb1/t;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Laa/q;->a:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Laa/q;->b:Ljava/lang/Object;

    iput-object p2, p0, Laa/q;->c:Ljava/lang/Object;

    iput-object p3, p0, Laa/q;->d:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final dispose()V
    .locals 4

    .line 1
    iget v0, p0, Laa/q;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Laa/q;->c:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/lifecycle/x;

    .line 9
    .line 10
    invoke-interface {v0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget-object v1, p0, Laa/q;->d:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lxf0/u1;

    .line 17
    .line 18
    invoke-virtual {v0, v1}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Laa/q;->b:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lay0/a;

    .line 24
    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    :cond_0
    return-void

    .line 31
    :pswitch_0
    iget-object v0, p0, Laa/q;->c:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, Lu2/e;

    .line 34
    .line 35
    iget-object v1, v0, Lu2/e;->e:Landroidx/collection/q0;

    .line 36
    .line 37
    iget-object v2, p0, Laa/q;->d:Ljava/lang/Object;

    .line 38
    .line 39
    invoke-virtual {v1, v2}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iget-object p0, p0, Laa/q;->b:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Lu2/j;

    .line 46
    .line 47
    if-ne v1, p0, :cond_2

    .line 48
    .line 49
    iget-object v0, v0, Lu2/e;->d:Ljava/util/Map;

    .line 50
    .line 51
    invoke-virtual {p0}, Lu2/j;->e()Ljava/util/Map;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-eqz v1, :cond_1

    .line 60
    .line 61
    invoke-interface {v0, v2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    invoke-interface {v0, v2, p0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    :cond_2
    :goto_0
    return-void

    .line 69
    :pswitch_1
    iget-object v0, p0, Laa/q;->d:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v0, Ll2/b1;

    .line 72
    .line 73
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    check-cast v0, Landroid/view/WindowManager$LayoutParams;

    .line 78
    .line 79
    if-nez v0, :cond_3

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_3
    iget-object v1, p0, Laa/q;->b:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v1, Ll2/b1;

    .line 85
    .line 86
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    check-cast v1, Ljava/lang/Integer;

    .line 91
    .line 92
    if-eqz v1, :cond_6

    .line 93
    .line 94
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    iget-object p0, p0, Laa/q;->c:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p0, Landroid/view/Window;

    .line 101
    .line 102
    iget v2, v0, Landroid/view/WindowManager$LayoutParams;->width:I

    .line 103
    .line 104
    iget v3, v0, Landroid/view/WindowManager$LayoutParams;->height:I

    .line 105
    .line 106
    invoke-virtual {p0, v2, v3}, Landroid/view/Window;->setLayout(II)V

    .line 107
    .line 108
    .line 109
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 110
    .line 111
    const/16 v3, 0x1e

    .line 112
    .line 113
    if-lt v2, v3, :cond_4

    .line 114
    .line 115
    invoke-virtual {p0, v0}, Landroid/view/Window;->setAttributes(Landroid/view/WindowManager$LayoutParams;)V

    .line 116
    .line 117
    .line 118
    :cond_4
    sget-object v0, Lr61/c;->a:Ljava/util/Set;

    .line 119
    .line 120
    check-cast v0, Ljava/lang/Iterable;

    .line 121
    .line 122
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    if-eqz v2, :cond_6

    .line 131
    .line 132
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v2

    .line 136
    check-cast v2, Ljava/lang/Number;

    .line 137
    .line 138
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 139
    .line 140
    .line 141
    move-result v2

    .line 142
    and-int v3, v1, v2

    .line 143
    .line 144
    if-eqz v3, :cond_5

    .line 145
    .line 146
    goto :goto_1

    .line 147
    :cond_5
    invoke-virtual {p0, v2}, Landroid/view/Window;->clearFlags(I)V

    .line 148
    .line 149
    .line 150
    goto :goto_1

    .line 151
    :cond_6
    :goto_2
    return-void

    .line 152
    :pswitch_2
    iget-object v0, p0, Laa/q;->d:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 155
    .line 156
    iget-object v1, p0, Laa/q;->c:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 159
    .line 160
    sget-object v2, Lq61/h;->d:Lq61/h;

    .line 161
    .line 162
    invoke-static {v1, v2}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 163
    .line 164
    .line 165
    iget-object p0, p0, Laa/q;->b:Ljava/lang/Object;

    .line 166
    .line 167
    check-cast p0, Ll2/b1;

    .line 168
    .line 169
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->access$SetupRPATearDown$lambda$1(Ll2/b1;)Z

    .line 170
    .line 171
    .line 172
    move-result p0

    .line 173
    if-eqz p0, :cond_7

    .line 174
    .line 175
    new-instance p0, Lep0/f;

    .line 176
    .line 177
    const/16 v2, 0xe

    .line 178
    .line 179
    invoke-direct {p0, v0, v2}, Lep0/f;-><init>(Ljava/lang/Object;I)V

    .line 180
    .line 181
    .line 182
    invoke-static {v1, p0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->getRpaViewModel()Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;

    .line 186
    .line 187
    .line 188
    move-result-object p0

    .line 189
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->access$getVin$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    invoke-interface {p0, v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;->stopRPAImmediately(Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    :cond_7
    return-void

    .line 197
    :pswitch_3
    iget-object v0, p0, Laa/q;->c:Ljava/lang/Object;

    .line 198
    .line 199
    check-cast v0, Landroidx/compose/runtime/DisposableEffectScope;

    .line 200
    .line 201
    new-instance v1, Lep0/f;

    .line 202
    .line 203
    iget-object v2, p0, Laa/q;->d:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v2, Landroid/view/View;

    .line 206
    .line 207
    const/16 v3, 0xd

    .line 208
    .line 209
    invoke-direct {v1, v2, v3}, Lep0/f;-><init>(Ljava/lang/Object;I)V

    .line 210
    .line 211
    .line 212
    invoke-static {v0, v1}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 213
    .line 214
    .line 215
    iget-object p0, p0, Laa/q;->b:Ljava/lang/Object;

    .line 216
    .line 217
    check-cast p0, Lkq/a;

    .line 218
    .line 219
    invoke-virtual {v2, p0}, Landroid/view/View;->removeOnLayoutChangeListener(Landroid/view/View$OnLayoutChangeListener;)V

    .line 220
    .line 221
    .line 222
    return-void

    .line 223
    :pswitch_4
    iget-object v0, p0, Laa/q;->c:Ljava/lang/Object;

    .line 224
    .line 225
    check-cast v0, Landroidx/lifecycle/x;

    .line 226
    .line 227
    invoke-interface {v0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 228
    .line 229
    .line 230
    move-result-object v0

    .line 231
    iget-object v1, p0, Laa/q;->d:Ljava/lang/Object;

    .line 232
    .line 233
    check-cast v1, Ld6/l;

    .line 234
    .line 235
    invoke-virtual {v0, v1}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 236
    .line 237
    .line 238
    iget-object p0, p0, Laa/q;->b:Ljava/lang/Object;

    .line 239
    .line 240
    check-cast p0, Lkotlin/jvm/internal/f0;

    .line 241
    .line 242
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 243
    .line 244
    check-cast p0, Ly21/e;

    .line 245
    .line 246
    if-eqz p0, :cond_8

    .line 247
    .line 248
    invoke-virtual {p0}, Ly21/e;->a()V

    .line 249
    .line 250
    .line 251
    :cond_8
    return-void

    .line 252
    :pswitch_5
    iget-object v0, p0, Laa/q;->c:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast v0, Lay0/a;

    .line 255
    .line 256
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    iget-object v0, p0, Laa/q;->d:Ljava/lang/Object;

    .line 260
    .line 261
    check-cast v0, Landroidx/lifecycle/x;

    .line 262
    .line 263
    invoke-interface {v0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 264
    .line 265
    .line 266
    move-result-object v0

    .line 267
    iget-object p0, p0, Laa/q;->b:Ljava/lang/Object;

    .line 268
    .line 269
    check-cast p0, Landroidx/lifecycle/m;

    .line 270
    .line 271
    invoke-virtual {v0, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 272
    .line 273
    .line 274
    return-void

    .line 275
    :pswitch_6
    iget-object v0, p0, Laa/q;->b:Ljava/lang/Object;

    .line 276
    .line 277
    check-cast v0, Lv2/o;

    .line 278
    .line 279
    iget-object v1, p0, Laa/q;->c:Ljava/lang/Object;

    .line 280
    .line 281
    invoke-virtual {v0, v1}, Lv2/o;->remove(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    iget-object p0, p0, Laa/q;->d:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast p0, Lb1/t;

    .line 287
    .line 288
    iget-object p0, p0, Lb1/t;->e:Landroidx/collection/q0;

    .line 289
    .line 290
    invoke-virtual {p0, v1}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    return-void

    .line 294
    :pswitch_7
    iget-object v0, p0, Laa/q;->c:Ljava/lang/Object;

    .line 295
    .line 296
    check-cast v0, Laa/v;

    .line 297
    .line 298
    iget-object v1, p0, Laa/q;->d:Ljava/lang/Object;

    .line 299
    .line 300
    check-cast v1, Lz9/k;

    .line 301
    .line 302
    invoke-virtual {v0}, Lz9/j0;->b()Lz9/m;

    .line 303
    .line 304
    .line 305
    move-result-object v0

    .line 306
    invoke-virtual {v0, v1}, Lz9/m;->c(Lz9/k;)V

    .line 307
    .line 308
    .line 309
    iget-object p0, p0, Laa/q;->b:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast p0, Lv2/o;

    .line 312
    .line 313
    invoke-virtual {p0, v1}, Lv2/o;->remove(Ljava/lang/Object;)Z

    .line 314
    .line 315
    .line 316
    return-void

    .line 317
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
