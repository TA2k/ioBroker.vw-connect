.class public final synthetic Lkq/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnLayoutChangeListener;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lkq/a;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lkq/a;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onLayoutChange(Landroid/view/View;IIIIIIII)V
    .locals 10

    .line 1
    iget v0, p0, Lkq/a;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lkq/a;->b:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ly9/w;

    .line 9
    .line 10
    iget-object p3, p0, Ly9/w;->a:Ly9/r;

    .line 11
    .line 12
    invoke-virtual {p3}, Landroid/view/View;->getWidth()I

    .line 13
    .line 14
    .line 15
    move-result p5

    .line 16
    invoke-virtual {p3}, Landroid/view/View;->getPaddingLeft()I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    sub-int/2addr p5, v0

    .line 21
    invoke-virtual {p3}, Landroid/view/View;->getPaddingRight()I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    sub-int/2addr p5, v0

    .line 26
    invoke-virtual {p3}, Landroid/view/View;->getHeight()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    invoke-virtual {p3}, Landroid/view/View;->getPaddingBottom()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    sub-int/2addr v0, v1

    .line 35
    invoke-virtual {p3}, Landroid/view/View;->getPaddingTop()I

    .line 36
    .line 37
    .line 38
    move-result p3

    .line 39
    sub-int/2addr v0, p3

    .line 40
    iget-object p3, p0, Ly9/w;->c:Landroid/view/ViewGroup;

    .line 41
    .line 42
    invoke-static {p3}, Ly9/w;->c(Landroid/view/View;)I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    const/4 v2, 0x0

    .line 47
    if-eqz p3, :cond_0

    .line 48
    .line 49
    invoke-virtual {p3}, Landroid/view/View;->getPaddingLeft()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    invoke-virtual {p3}, Landroid/view/View;->getPaddingRight()I

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    add-int/2addr v4, v3

    .line 58
    goto :goto_0

    .line 59
    :cond_0
    move v4, v2

    .line 60
    :goto_0
    sub-int/2addr v1, v4

    .line 61
    if-nez p3, :cond_1

    .line 62
    .line 63
    move v3, v2

    .line 64
    goto :goto_1

    .line 65
    :cond_1
    invoke-virtual {p3}, Landroid/view/View;->getHeight()I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    invoke-virtual {p3}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    instance-of v5, v4, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 74
    .line 75
    if-eqz v5, :cond_2

    .line 76
    .line 77
    check-cast v4, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 78
    .line 79
    iget v5, v4, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 80
    .line 81
    iget v4, v4, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 82
    .line 83
    add-int/2addr v5, v4

    .line 84
    add-int/2addr v3, v5

    .line 85
    :cond_2
    :goto_1
    if-eqz p3, :cond_3

    .line 86
    .line 87
    invoke-virtual {p3}, Landroid/view/View;->getPaddingTop()I

    .line 88
    .line 89
    .line 90
    move-result v4

    .line 91
    invoke-virtual {p3}, Landroid/view/View;->getPaddingBottom()I

    .line 92
    .line 93
    .line 94
    move-result p3

    .line 95
    add-int/2addr p3, v4

    .line 96
    goto :goto_2

    .line 97
    :cond_3
    move p3, v2

    .line 98
    :goto_2
    sub-int/2addr v3, p3

    .line 99
    iget-object p3, p0, Ly9/w;->i:Landroid/view/ViewGroup;

    .line 100
    .line 101
    invoke-static {p3}, Ly9/w;->c(Landroid/view/View;)I

    .line 102
    .line 103
    .line 104
    move-result p3

    .line 105
    iget-object v4, p0, Ly9/w;->k:Landroid/view/View;

    .line 106
    .line 107
    invoke-static {v4}, Ly9/w;->c(Landroid/view/View;)I

    .line 108
    .line 109
    .line 110
    move-result v4

    .line 111
    add-int/2addr v4, p3

    .line 112
    invoke-static {v1, v4}, Ljava/lang/Math;->max(II)I

    .line 113
    .line 114
    .line 115
    move-result p3

    .line 116
    iget-object v1, p0, Ly9/w;->d:Landroid/view/ViewGroup;

    .line 117
    .line 118
    if-nez v1, :cond_4

    .line 119
    .line 120
    move v4, v2

    .line 121
    goto :goto_3

    .line 122
    :cond_4
    invoke-virtual {v1}, Landroid/view/View;->getHeight()I

    .line 123
    .line 124
    .line 125
    move-result v4

    .line 126
    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    instance-of v5, v1, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 131
    .line 132
    if-eqz v5, :cond_5

    .line 133
    .line 134
    check-cast v1, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 135
    .line 136
    iget v5, v1, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 137
    .line 138
    iget v1, v1, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 139
    .line 140
    add-int/2addr v5, v1

    .line 141
    add-int/2addr v4, v5

    .line 142
    :cond_5
    :goto_3
    mul-int/lit8 v4, v4, 0x2

    .line 143
    .line 144
    add-int/2addr v4, v3

    .line 145
    const/4 v1, 0x1

    .line 146
    if-le p5, p3, :cond_7

    .line 147
    .line 148
    if-gt v0, v4, :cond_6

    .line 149
    .line 150
    goto :goto_4

    .line 151
    :cond_6
    move p3, v2

    .line 152
    goto :goto_5

    .line 153
    :cond_7
    :goto_4
    move p3, v1

    .line 154
    :goto_5
    iget-boolean p5, p0, Ly9/w;->A:Z

    .line 155
    .line 156
    if-eq p5, p3, :cond_8

    .line 157
    .line 158
    iput-boolean p3, p0, Ly9/w;->A:Z

    .line 159
    .line 160
    new-instance p3, Ly9/s;

    .line 161
    .line 162
    const/4 p5, 0x1

    .line 163
    invoke-direct {p3, p0, p5}, Ly9/s;-><init>(Ly9/w;I)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {p1, p3}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 167
    .line 168
    .line 169
    :cond_8
    sub-int/2addr p4, p2

    .line 170
    sub-int p2, p8, p6

    .line 171
    .line 172
    if-eq p4, p2, :cond_9

    .line 173
    .line 174
    move v2, v1

    .line 175
    :cond_9
    iget-boolean p2, p0, Ly9/w;->A:Z

    .line 176
    .line 177
    if-nez p2, :cond_a

    .line 178
    .line 179
    if-eqz v2, :cond_a

    .line 180
    .line 181
    new-instance p2, Ly9/s;

    .line 182
    .line 183
    const/4 p3, 0x2

    .line 184
    invoke-direct {p2, p0, p3}, Ly9/s;-><init>(Ly9/w;I)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {p1, p2}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 188
    .line 189
    .line 190
    :cond_a
    return-void

    .line 191
    :pswitch_0
    check-cast p0, Ly9/r;

    .line 192
    .line 193
    iget v0, p0, Ly9/r;->u:I

    .line 194
    .line 195
    iget-object v1, p0, Ly9/r;->t:Landroid/widget/PopupWindow;

    .line 196
    .line 197
    sub-int/2addr p4, p2

    .line 198
    sub-int/2addr p5, p3

    .line 199
    sub-int p2, p8, p6

    .line 200
    .line 201
    sub-int p3, p9, p7

    .line 202
    .line 203
    if-ne p4, p2, :cond_b

    .line 204
    .line 205
    if-eq p5, p3, :cond_c

    .line 206
    .line 207
    :cond_b
    invoke-virtual {v1}, Landroid/widget/PopupWindow;->isShowing()Z

    .line 208
    .line 209
    .line 210
    move-result p2

    .line 211
    if-eqz p2, :cond_c

    .line 212
    .line 213
    invoke-virtual {p0}, Ly9/r;->u()V

    .line 214
    .line 215
    .line 216
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 217
    .line 218
    .line 219
    move-result p0

    .line 220
    invoke-virtual {v1}, Landroid/widget/PopupWindow;->getWidth()I

    .line 221
    .line 222
    .line 223
    move-result p2

    .line 224
    sub-int/2addr p0, p2

    .line 225
    sub-int p4, p0, v0

    .line 226
    .line 227
    invoke-virtual {v1}, Landroid/widget/PopupWindow;->getHeight()I

    .line 228
    .line 229
    .line 230
    move-result p0

    .line 231
    neg-int p0, p0

    .line 232
    sub-int p5, p0, v0

    .line 233
    .line 234
    const/4 p0, -0x1

    .line 235
    const/4 p2, -0x1

    .line 236
    move/from16 p6, p0

    .line 237
    .line 238
    move-object p3, p1

    .line 239
    move/from16 p7, p2

    .line 240
    .line 241
    move-object p2, v1

    .line 242
    invoke-virtual/range {p2 .. p7}, Landroid/widget/PopupWindow;->update(Landroid/view/View;IIII)V

    .line 243
    .line 244
    .line 245
    :cond_c
    return-void

    .line 246
    :pswitch_1
    check-cast p0, Lw0/i;

    .line 247
    .line 248
    sub-int/2addr p4, p2

    .line 249
    sub-int p1, p8, p6

    .line 250
    .line 251
    if-ne p4, p1, :cond_d

    .line 252
    .line 253
    sub-int/2addr p5, p3

    .line 254
    sub-int p1, p9, p7

    .line 255
    .line 256
    if-eq p5, p1, :cond_e

    .line 257
    .line 258
    :cond_d
    invoke-virtual {p0}, Lw0/i;->a()V

    .line 259
    .line 260
    .line 261
    invoke-static {}, Llp/k1;->a()V

    .line 262
    .line 263
    .line 264
    invoke-virtual {p0}, Lw0/i;->getViewPort()Lb0/a2;

    .line 265
    .line 266
    .line 267
    :cond_e
    return-void

    .line 268
    :pswitch_2
    move-object v0, p0

    .line 269
    check-cast v0, Ll2/b1;

    .line 270
    .line 271
    move-object v1, p1

    .line 272
    move v2, p2

    .line 273
    move v3, p3

    .line 274
    move v4, p4

    .line 275
    move v5, p5

    .line 276
    move/from16 v6, p6

    .line 277
    .line 278
    move/from16 v7, p7

    .line 279
    .line 280
    move/from16 v8, p8

    .line 281
    .line 282
    move/from16 v9, p9

    .line 283
    .line 284
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->e(Ll2/b1;Landroid/view/View;IIIIIIII)V

    .line 285
    .line 286
    .line 287
    return-void

    .line 288
    :pswitch_3
    check-cast p0, Lcom/google/android/material/carousel/CarouselLayoutManager;

    .line 289
    .line 290
    sub-int/2addr p4, p2

    .line 291
    sub-int p2, p8, p6

    .line 292
    .line 293
    if-ne p4, p2, :cond_f

    .line 294
    .line 295
    sub-int/2addr p5, p3

    .line 296
    sub-int p2, p9, p7

    .line 297
    .line 298
    if-eq p5, p2, :cond_10

    .line 299
    .line 300
    :cond_f
    new-instance p2, La0/d;

    .line 301
    .line 302
    const/16 p3, 0x1b

    .line 303
    .line 304
    invoke-direct {p2, p0, p3}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 305
    .line 306
    .line 307
    invoke-virtual {p1, p2}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 308
    .line 309
    .line 310
    :cond_10
    return-void

    .line 311
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
