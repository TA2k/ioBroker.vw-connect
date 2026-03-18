.class public final Ly9/m0;
.super Landroid/widget/FrameLayout;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly9/g0;


# instance fields
.field public final d:Ly9/b;

.field public final e:Ly9/k0;

.field public f:Ljava/util/List;

.field public g:Ly9/c;

.field public h:F

.field public i:F


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0}, Landroid/widget/FrameLayout;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 3
    .line 4
    .line 5
    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 6
    .line 7
    iput-object v1, p0, Ly9/m0;->f:Ljava/util/List;

    .line 8
    .line 9
    sget-object v1, Ly9/c;->g:Ly9/c;

    .line 10
    .line 11
    iput-object v1, p0, Ly9/m0;->g:Ly9/c;

    .line 12
    .line 13
    const v1, 0x3d5a511a    # 0.0533f

    .line 14
    .line 15
    .line 16
    iput v1, p0, Ly9/m0;->h:F

    .line 17
    .line 18
    const v1, 0x3da3d70a    # 0.08f

    .line 19
    .line 20
    .line 21
    iput v1, p0, Ly9/m0;->i:F

    .line 22
    .line 23
    new-instance v1, Ly9/b;

    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    invoke-direct {v1, p1, v2}, Ly9/b;-><init>(Landroid/content/Context;I)V

    .line 27
    .line 28
    .line 29
    iput-object v1, p0, Ly9/m0;->d:Ly9/b;

    .line 30
    .line 31
    new-instance v3, Ly9/k0;

    .line 32
    .line 33
    invoke-direct {v3, p1, v0}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 34
    .line 35
    .line 36
    iput-object v3, p0, Ly9/m0;->e:Ly9/k0;

    .line 37
    .line 38
    invoke-virtual {v3, v2}, Landroid/webkit/WebView;->setBackgroundColor(I)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0, v3}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 45
    .line 46
    .line 47
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/List;Ly9/c;FF)V
    .locals 5

    .line 1
    iput-object p2, p0, Ly9/m0;->g:Ly9/c;

    .line 2
    .line 3
    iput p3, p0, Ly9/m0;->h:F

    .line 4
    .line 5
    iput p4, p0, Ly9/m0;->i:F

    .line 6
    .line 7
    new-instance v0, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 10
    .line 11
    .line 12
    new-instance v1, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-ge v2, v3, :cond_1

    .line 23
    .line 24
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    check-cast v3, Lv7/b;

    .line 29
    .line 30
    iget-object v4, v3, Lv7/b;->d:Landroid/graphics/Bitmap;

    .line 31
    .line 32
    if-eqz v4, :cond_0

    .line 33
    .line 34
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_0
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    iget-object p1, p0, Ly9/m0;->f:Ljava/util/List;

    .line 45
    .line 46
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    if-eqz p1, :cond_2

    .line 51
    .line 52
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    if-nez p1, :cond_3

    .line 57
    .line 58
    :cond_2
    iput-object v1, p0, Ly9/m0;->f:Ljava/util/List;

    .line 59
    .line 60
    invoke-virtual {p0}, Ly9/m0;->c()V

    .line 61
    .line 62
    .line 63
    :cond_3
    iget-object p1, p0, Ly9/m0;->d:Ly9/b;

    .line 64
    .line 65
    invoke-virtual {p1, v0, p2, p3, p4}, Ly9/b;->a(Ljava/util/List;Ly9/c;FF)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 69
    .line 70
    .line 71
    return-void
.end method

.method public final b(IF)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    sub-int/2addr v1, v2

    .line 14
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    sub-int/2addr v1, v2

    .line 19
    invoke-static {p1, v0, v1, p2}, Lqp/i;->d(IIIF)F

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    const p2, -0x800001

    .line 24
    .line 25
    .line 26
    cmpl-float p2, p1, p2

    .line 27
    .line 28
    if-nez p2, :cond_0

    .line 29
    .line 30
    const-string p0, "unset"

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {p0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    iget p0, p0, Landroid/util/DisplayMetrics;->density:F

    .line 46
    .line 47
    div-float/2addr p1, p0

    .line 48
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    sget-object p1, Lw7/w;->a:Ljava/lang/String;

    .line 57
    .line 58
    sget-object p1, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 59
    .line 60
    const-string p2, "%.2fpx"

    .line 61
    .line 62
    invoke-static {p1, p2, p0}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0
.end method

.method public final c()V
    .locals 47

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 6
    .line 7
    .line 8
    iget-object v2, v0, Ly9/m0;->g:Ly9/c;

    .line 9
    .line 10
    iget v2, v2, Ly9/c;->a:I

    .line 11
    .line 12
    invoke-static {v2}, Lpw/a;->a(I)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    iget v3, v0, Ly9/m0;->h:F

    .line 17
    .line 18
    const/4 v4, 0x0

    .line 19
    invoke-virtual {v0, v4, v3}, Ly9/m0;->b(IF)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    const v5, 0x3f99999a    # 1.2f

    .line 24
    .line 25
    .line 26
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 27
    .line 28
    .line 29
    move-result-object v6

    .line 30
    iget-object v7, v0, Ly9/m0;->g:Ly9/c;

    .line 31
    .line 32
    iget v8, v7, Ly9/c;->d:I

    .line 33
    .line 34
    iget v7, v7, Ly9/c;->e:I

    .line 35
    .line 36
    const-string v9, "unset"

    .line 37
    .line 38
    const/4 v10, 0x3

    .line 39
    const/4 v11, 0x2

    .line 40
    const/4 v12, 0x1

    .line 41
    if-eq v8, v12, :cond_3

    .line 42
    .line 43
    if-eq v8, v11, :cond_2

    .line 44
    .line 45
    if-eq v8, v10, :cond_1

    .line 46
    .line 47
    const/4 v13, 0x4

    .line 48
    if-eq v8, v13, :cond_0

    .line 49
    .line 50
    move-object v7, v9

    .line 51
    goto :goto_0

    .line 52
    :cond_0
    invoke-static {v7}, Lpw/a;->a(I)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v7

    .line 56
    sget-object v8, Lw7/w;->a:Ljava/lang/String;

    .line 57
    .line 58
    sget-object v8, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 59
    .line 60
    const-string v8, "-0.05em -0.05em 0.15em "

    .line 61
    .line 62
    invoke-virtual {v8, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v7

    .line 66
    goto :goto_0

    .line 67
    :cond_1
    invoke-static {v7}, Lpw/a;->a(I)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v7

    .line 71
    sget-object v8, Lw7/w;->a:Ljava/lang/String;

    .line 72
    .line 73
    sget-object v8, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 74
    .line 75
    const-string v8, "0.06em 0.08em 0.15em "

    .line 76
    .line 77
    invoke-virtual {v8, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    goto :goto_0

    .line 82
    :cond_2
    invoke-static {v7}, Lpw/a;->a(I)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v7

    .line 86
    sget-object v8, Lw7/w;->a:Ljava/lang/String;

    .line 87
    .line 88
    sget-object v8, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 89
    .line 90
    const-string v8, "0.1em 0.12em 0.15em "

    .line 91
    .line 92
    invoke-virtual {v8, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v7

    .line 96
    goto :goto_0

    .line 97
    :cond_3
    invoke-static {v7}, Lpw/a;->a(I)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v7

    .line 101
    filled-new-array {v7}, [Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v7

    .line 105
    sget-object v8, Lw7/w;->a:Ljava/lang/String;

    .line 106
    .line 107
    sget-object v8, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 108
    .line 109
    const-string v13, "1px 1px 0 %1$s, 1px -1px 0 %1$s, -1px 1px 0 %1$s, -1px -1px 0 %1$s"

    .line 110
    .line 111
    invoke-static {v8, v13, v7}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v7

    .line 115
    :goto_0
    filled-new-array {v2, v3, v6, v7}, [Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    .line 120
    .line 121
    sget-object v3, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 122
    .line 123
    const-string v6, "<body><div style=\'-webkit-user-select:none;position:fixed;top:0;bottom:0;left:0;right:0;color:%s;font-size:%s;line-height:%.2f;text-shadow:%s;\'>"

    .line 124
    .line 125
    invoke-static {v3, v6, v2}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    new-instance v2, Ljava/util/HashMap;

    .line 133
    .line 134
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 135
    .line 136
    .line 137
    iget-object v3, v0, Ly9/m0;->g:Ly9/c;

    .line 138
    .line 139
    iget v3, v3, Ly9/c;->b:I

    .line 140
    .line 141
    invoke-static {v3}, Lpw/a;->a(I)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    new-instance v6, Ljava/lang/StringBuilder;

    .line 146
    .line 147
    const-string v7, "background-color:"

    .line 148
    .line 149
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    const-string v3, ";"

    .line 156
    .line 157
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v6

    .line 164
    const-string v8, ".default_bg,.default_bg *"

    .line 165
    .line 166
    invoke-virtual {v2, v8, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move v6, v4

    .line 170
    :goto_1
    iget-object v8, v0, Ly9/m0;->f:Ljava/util/List;

    .line 171
    .line 172
    invoke-interface {v8}, Ljava/util/List;->size()I

    .line 173
    .line 174
    .line 175
    move-result v8

    .line 176
    if-ge v6, v8, :cond_54

    .line 177
    .line 178
    iget-object v8, v0, Ly9/m0;->f:Ljava/util/List;

    .line 179
    .line 180
    invoke-interface {v8, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v8

    .line 184
    check-cast v8, Lv7/b;

    .line 185
    .line 186
    iget v13, v8, Lv7/b;->h:F

    .line 187
    .line 188
    iget v14, v8, Lv7/b;->g:I

    .line 189
    .line 190
    iget v15, v8, Lv7/b;->p:I

    .line 191
    .line 192
    const v16, -0x800001

    .line 193
    .line 194
    .line 195
    cmpl-float v17, v13, v16

    .line 196
    .line 197
    const/high16 v18, 0x42c80000    # 100.0f

    .line 198
    .line 199
    if-eqz v17, :cond_4

    .line 200
    .line 201
    mul-float v13, v13, v18

    .line 202
    .line 203
    :goto_2
    move/from16 v17, v5

    .line 204
    .line 205
    goto :goto_3

    .line 206
    :cond_4
    const/high16 v13, 0x42480000    # 50.0f

    .line 207
    .line 208
    goto :goto_2

    .line 209
    :goto_3
    iget v5, v8, Lv7/b;->i:I

    .line 210
    .line 211
    const/16 v19, -0x32

    .line 212
    .line 213
    const/16 v20, -0x64

    .line 214
    .line 215
    if-eq v5, v12, :cond_6

    .line 216
    .line 217
    if-eq v5, v11, :cond_5

    .line 218
    .line 219
    move v5, v4

    .line 220
    goto :goto_4

    .line 221
    :cond_5
    move/from16 v5, v20

    .line 222
    .line 223
    goto :goto_4

    .line 224
    :cond_6
    move/from16 v5, v19

    .line 225
    .line 226
    :goto_4
    iget v10, v8, Lv7/b;->e:F

    .line 227
    .line 228
    cmpl-float v21, v10, v16

    .line 229
    .line 230
    const/high16 v22, 0x3f800000    # 1.0f

    .line 231
    .line 232
    const/16 v23, 0x0

    .line 233
    .line 234
    const-string v4, "%.2f%%"

    .line 235
    .line 236
    if-eqz v21, :cond_e

    .line 237
    .line 238
    iget v11, v8, Lv7/b;->f:I

    .line 239
    .line 240
    if-eq v11, v12, :cond_c

    .line 241
    .line 242
    mul-float v10, v10, v18

    .line 243
    .line 244
    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 245
    .line 246
    .line 247
    move-result-object v10

    .line 248
    filled-new-array {v10}, [Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v10

    .line 252
    sget-object v11, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 253
    .line 254
    invoke-static {v11, v4, v10}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v10

    .line 258
    if-ne v15, v12, :cond_9

    .line 259
    .line 260
    if-eq v14, v12, :cond_8

    .line 261
    .line 262
    const/4 v11, 0x2

    .line 263
    if-eq v14, v11, :cond_7

    .line 264
    .line 265
    const/4 v14, 0x0

    .line 266
    goto :goto_5

    .line 267
    :cond_7
    move/from16 v14, v20

    .line 268
    .line 269
    goto :goto_5

    .line 270
    :cond_8
    const/4 v11, 0x2

    .line 271
    move/from16 v14, v19

    .line 272
    .line 273
    :goto_5
    neg-int v14, v14

    .line 274
    move/from16 v20, v14

    .line 275
    .line 276
    goto :goto_7

    .line 277
    :cond_9
    const/4 v11, 0x2

    .line 278
    if-eq v14, v12, :cond_b

    .line 279
    .line 280
    if-eq v14, v11, :cond_a

    .line 281
    .line 282
    const/16 v19, 0x0

    .line 283
    .line 284
    goto :goto_6

    .line 285
    :cond_a
    move/from16 v19, v20

    .line 286
    .line 287
    :cond_b
    :goto_6
    move/from16 v20, v19

    .line 288
    .line 289
    :goto_7
    move-object/from16 v28, v10

    .line 290
    .line 291
    const/4 v10, 0x0

    .line 292
    goto :goto_9

    .line 293
    :cond_c
    cmpl-float v11, v10, v23

    .line 294
    .line 295
    const-string v14, "%.2fem"

    .line 296
    .line 297
    if-ltz v11, :cond_d

    .line 298
    .line 299
    mul-float v10, v10, v17

    .line 300
    .line 301
    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 302
    .line 303
    .line 304
    move-result-object v10

    .line 305
    filled-new-array {v10}, [Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object v10

    .line 309
    sget-object v11, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 310
    .line 311
    invoke-static {v11, v14, v10}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object v10

    .line 315
    move-object/from16 v28, v10

    .line 316
    .line 317
    const/4 v10, 0x0

    .line 318
    :goto_8
    const/16 v20, 0x0

    .line 319
    .line 320
    goto :goto_9

    .line 321
    :cond_d
    neg-float v10, v10

    .line 322
    sub-float v10, v10, v22

    .line 323
    .line 324
    mul-float v10, v10, v17

    .line 325
    .line 326
    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 327
    .line 328
    .line 329
    move-result-object v10

    .line 330
    filled-new-array {v10}, [Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v10

    .line 334
    sget-object v11, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 335
    .line 336
    invoke-static {v11, v14, v10}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 337
    .line 338
    .line 339
    move-result-object v10

    .line 340
    move-object/from16 v28, v10

    .line 341
    .line 342
    move v10, v12

    .line 343
    goto :goto_8

    .line 344
    :cond_e
    iget v10, v0, Ly9/m0;->i:F

    .line 345
    .line 346
    sub-float v22, v22, v10

    .line 347
    .line 348
    mul-float v22, v22, v18

    .line 349
    .line 350
    invoke-static/range {v22 .. v22}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 351
    .line 352
    .line 353
    move-result-object v10

    .line 354
    filled-new-array {v10}, [Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v10

    .line 358
    sget-object v11, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 359
    .line 360
    invoke-static {v11, v4, v10}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 361
    .line 362
    .line 363
    move-result-object v10

    .line 364
    goto :goto_7

    .line 365
    :goto_9
    iget v11, v8, Lv7/b;->j:F

    .line 366
    .line 367
    cmpl-float v14, v11, v16

    .line 368
    .line 369
    if-eqz v14, :cond_f

    .line 370
    .line 371
    mul-float v11, v11, v18

    .line 372
    .line 373
    invoke-static {v11}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 374
    .line 375
    .line 376
    move-result-object v11

    .line 377
    filled-new-array {v11}, [Ljava/lang/Object;

    .line 378
    .line 379
    .line 380
    move-result-object v11

    .line 381
    sget-object v14, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 382
    .line 383
    invoke-static {v14, v4, v11}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 384
    .line 385
    .line 386
    move-result-object v4

    .line 387
    :goto_a
    move-object/from16 v30, v4

    .line 388
    .line 389
    goto :goto_b

    .line 390
    :cond_f
    const-string v4, "fit-content"

    .line 391
    .line 392
    goto :goto_a

    .line 393
    :goto_b
    iget-object v4, v8, Lv7/b;->b:Landroid/text/Layout$Alignment;

    .line 394
    .line 395
    const-string v11, "start"

    .line 396
    .line 397
    const-string v14, "end"

    .line 398
    .line 399
    const-string v16, "center"

    .line 400
    .line 401
    if-nez v4, :cond_10

    .line 402
    .line 403
    move v4, v12

    .line 404
    move-object/from16 v31, v16

    .line 405
    .line 406
    const/4 v12, 0x2

    .line 407
    goto :goto_d

    .line 408
    :cond_10
    sget-object v19, Ly9/l0;->a:[I

    .line 409
    .line 410
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 411
    .line 412
    .line 413
    move-result v4

    .line 414
    aget v4, v19, v4

    .line 415
    .line 416
    if-eq v4, v12, :cond_12

    .line 417
    .line 418
    const/4 v12, 0x2

    .line 419
    if-eq v4, v12, :cond_11

    .line 420
    .line 421
    move-object/from16 v31, v16

    .line 422
    .line 423
    :goto_c
    const/4 v4, 0x1

    .line 424
    goto :goto_d

    .line 425
    :cond_11
    move-object/from16 v31, v14

    .line 426
    .line 427
    goto :goto_c

    .line 428
    :cond_12
    const/4 v12, 0x2

    .line 429
    move-object/from16 v31, v11

    .line 430
    .line 431
    goto :goto_c

    .line 432
    :goto_d
    if-eq v15, v4, :cond_14

    .line 433
    .line 434
    if-eq v15, v12, :cond_13

    .line 435
    .line 436
    const-string v4, "horizontal-tb"

    .line 437
    .line 438
    :goto_e
    move-object/from16 v32, v4

    .line 439
    .line 440
    goto :goto_f

    .line 441
    :cond_13
    const-string v4, "vertical-lr"

    .line 442
    .line 443
    goto :goto_e

    .line 444
    :cond_14
    const-string v4, "vertical-rl"

    .line 445
    .line 446
    goto :goto_e

    .line 447
    :goto_f
    iget v4, v8, Lv7/b;->n:I

    .line 448
    .line 449
    iget v12, v8, Lv7/b;->o:F

    .line 450
    .line 451
    invoke-virtual {v0, v4, v12}, Ly9/m0;->b(IF)Ljava/lang/String;

    .line 452
    .line 453
    .line 454
    move-result-object v33

    .line 455
    iget-boolean v4, v8, Lv7/b;->l:Z

    .line 456
    .line 457
    if-eqz v4, :cond_15

    .line 458
    .line 459
    iget v4, v8, Lv7/b;->m:I

    .line 460
    .line 461
    goto :goto_10

    .line 462
    :cond_15
    iget-object v4, v0, Ly9/m0;->g:Ly9/c;

    .line 463
    .line 464
    iget v4, v4, Ly9/c;->c:I

    .line 465
    .line 466
    :goto_10
    invoke-static {v4}, Lpw/a;->a(I)Ljava/lang/String;

    .line 467
    .line 468
    .line 469
    move-result-object v34

    .line 470
    const-string v4, "right"

    .line 471
    .line 472
    const-string v12, "top"

    .line 473
    .line 474
    const-string v22, "left"

    .line 475
    .line 476
    move-object/from16 v24, v4

    .line 477
    .line 478
    const/4 v4, 0x1

    .line 479
    if-eq v15, v4, :cond_1a

    .line 480
    .line 481
    const/4 v4, 0x2

    .line 482
    if-eq v15, v4, :cond_17

    .line 483
    .line 484
    if-eqz v10, :cond_16

    .line 485
    .line 486
    const-string v12, "bottom"

    .line 487
    .line 488
    :cond_16
    move-object/from16 v27, v12

    .line 489
    .line 490
    move-object/from16 v25, v22

    .line 491
    .line 492
    :goto_11
    const/4 v4, 0x2

    .line 493
    goto :goto_14

    .line 494
    :cond_17
    if-eqz v10, :cond_19

    .line 495
    .line 496
    :cond_18
    move-object/from16 v4, v24

    .line 497
    .line 498
    goto :goto_13

    .line 499
    :cond_19
    :goto_12
    move-object/from16 v4, v22

    .line 500
    .line 501
    :goto_13
    move-object/from16 v27, v4

    .line 502
    .line 503
    move-object/from16 v25, v12

    .line 504
    .line 505
    goto :goto_11

    .line 506
    :cond_1a
    if-eqz v10, :cond_18

    .line 507
    .line 508
    goto :goto_12

    .line 509
    :goto_14
    if-eq v15, v4, :cond_1c

    .line 510
    .line 511
    const/4 v4, 0x1

    .line 512
    if-ne v15, v4, :cond_1b

    .line 513
    .line 514
    goto :goto_16

    .line 515
    :cond_1b
    const-string v4, "width"

    .line 516
    .line 517
    :goto_15
    move-object/from16 v29, v4

    .line 518
    .line 519
    goto :goto_17

    .line 520
    :cond_1c
    :goto_16
    const-string v4, "height"

    .line 521
    .line 522
    move/from16 v29, v20

    .line 523
    .line 524
    move/from16 v20, v5

    .line 525
    .line 526
    move/from16 v5, v29

    .line 527
    .line 528
    goto :goto_15

    .line 529
    :goto_17
    iget-object v4, v8, Lv7/b;->a:Ljava/lang/CharSequence;

    .line 530
    .line 531
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 532
    .line 533
    .line 534
    move-result-object v10

    .line 535
    invoke-virtual {v10}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 536
    .line 537
    .line 538
    move-result-object v10

    .line 539
    invoke-virtual {v10}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 540
    .line 541
    .line 542
    move-result-object v10

    .line 543
    iget v10, v10, Landroid/util/DisplayMetrics;->density:F

    .line 544
    .line 545
    sget-object v12, Ly9/e0;->a:Ljava/util/regex/Pattern;

    .line 546
    .line 547
    const-string v12, "</span>"

    .line 548
    .line 549
    move/from16 v24, v5

    .line 550
    .line 551
    const-string v5, ";\'>"

    .line 552
    .line 553
    move/from16 v38, v6

    .line 554
    .line 555
    const-string v6, ""

    .line 556
    .line 557
    if-nez v4, :cond_1d

    .line 558
    .line 559
    new-instance v4, Lj51/i;

    .line 560
    .line 561
    const/4 v10, 0x5

    .line 562
    invoke-direct {v4, v6, v10}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 563
    .line 564
    .line 565
    move-object/from16 v40, v3

    .line 566
    .line 567
    move-object/from16 v26, v6

    .line 568
    .line 569
    :goto_18
    move-object/from16 v43, v7

    .line 570
    .line 571
    move-object/from16 v39, v11

    .line 572
    .line 573
    move/from16 v36, v13

    .line 574
    .line 575
    move-object/from16 v41, v14

    .line 576
    .line 577
    goto/16 :goto_2b

    .line 578
    .line 579
    :cond_1d
    move-object/from16 v26, v6

    .line 580
    .line 581
    instance-of v6, v4, Landroid/text/Spanned;

    .line 582
    .line 583
    if-nez v6, :cond_1e

    .line 584
    .line 585
    new-instance v6, Lj51/i;

    .line 586
    .line 587
    invoke-static {v4}, Ly9/e0;->a(Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 588
    .line 589
    .line 590
    move-result-object v4

    .line 591
    const/4 v10, 0x5

    .line 592
    invoke-direct {v6, v4, v10}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 593
    .line 594
    .line 595
    move-object/from16 v40, v3

    .line 596
    .line 597
    move-object v4, v6

    .line 598
    goto :goto_18

    .line 599
    :cond_1e
    check-cast v4, Landroid/text/Spanned;

    .line 600
    .line 601
    new-instance v6, Ljava/util/HashSet;

    .line 602
    .line 603
    invoke-direct {v6}, Ljava/util/HashSet;-><init>()V

    .line 604
    .line 605
    .line 606
    move/from16 v35, v10

    .line 607
    .line 608
    invoke-interface {v4}, Ljava/lang/CharSequence;->length()I

    .line 609
    .line 610
    .line 611
    move-result v10

    .line 612
    move-object/from16 v39, v11

    .line 613
    .line 614
    const-class v11, Landroid/text/style/BackgroundColorSpan;

    .line 615
    .line 616
    move/from16 v36, v13

    .line 617
    .line 618
    const/4 v13, 0x0

    .line 619
    invoke-interface {v4, v13, v10, v11}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 620
    .line 621
    .line 622
    move-result-object v10

    .line 623
    check-cast v10, [Landroid/text/style/BackgroundColorSpan;

    .line 624
    .line 625
    array-length v11, v10

    .line 626
    const/4 v13, 0x0

    .line 627
    :goto_19
    if-ge v13, v11, :cond_1f

    .line 628
    .line 629
    aget-object v37, v10, v13

    .line 630
    .line 631
    invoke-virtual/range {v37 .. v37}, Landroid/text/style/BackgroundColorSpan;->getBackgroundColor()I

    .line 632
    .line 633
    .line 634
    move-result v37

    .line 635
    move-object/from16 v40, v10

    .line 636
    .line 637
    invoke-static/range {v37 .. v37}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 638
    .line 639
    .line 640
    move-result-object v10

    .line 641
    invoke-virtual {v6, v10}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 642
    .line 643
    .line 644
    add-int/lit8 v13, v13, 0x1

    .line 645
    .line 646
    move-object/from16 v10, v40

    .line 647
    .line 648
    goto :goto_19

    .line 649
    :cond_1f
    new-instance v10, Ljava/util/HashMap;

    .line 650
    .line 651
    invoke-direct {v10}, Ljava/util/HashMap;-><init>()V

    .line 652
    .line 653
    .line 654
    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 655
    .line 656
    .line 657
    move-result-object v6

    .line 658
    :goto_1a
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 659
    .line 660
    .line 661
    move-result v11

    .line 662
    if-eqz v11, :cond_20

    .line 663
    .line 664
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 665
    .line 666
    .line 667
    move-result-object v11

    .line 668
    check-cast v11, Ljava/lang/Integer;

    .line 669
    .line 670
    invoke-virtual {v11}, Ljava/lang/Integer;->intValue()I

    .line 671
    .line 672
    .line 673
    move-result v11

    .line 674
    const-string v13, "bg_"

    .line 675
    .line 676
    invoke-static {v11, v13}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 677
    .line 678
    .line 679
    move-result-object v13

    .line 680
    move-object/from16 v37, v6

    .line 681
    .line 682
    const-string v6, ",."

    .line 683
    .line 684
    move/from16 v40, v11

    .line 685
    .line 686
    const-string v11, " *"

    .line 687
    .line 688
    move-object/from16 v41, v14

    .line 689
    .line 690
    const-string v14, "."

    .line 691
    .line 692
    invoke-static {v14, v13, v6, v13, v11}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 693
    .line 694
    .line 695
    move-result-object v6

    .line 696
    invoke-static/range {v40 .. v40}, Lpw/a;->a(I)Ljava/lang/String;

    .line 697
    .line 698
    .line 699
    move-result-object v11

    .line 700
    sget-object v13, Lw7/w;->a:Ljava/lang/String;

    .line 701
    .line 702
    sget-object v13, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 703
    .line 704
    new-instance v13, Ljava/lang/StringBuilder;

    .line 705
    .line 706
    invoke-direct {v13, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 707
    .line 708
    .line 709
    invoke-virtual {v13, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 710
    .line 711
    .line 712
    invoke-virtual {v13, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 713
    .line 714
    .line 715
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 716
    .line 717
    .line 718
    move-result-object v11

    .line 719
    invoke-virtual {v10, v6, v11}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 720
    .line 721
    .line 722
    move-object/from16 v6, v37

    .line 723
    .line 724
    move-object/from16 v14, v41

    .line 725
    .line 726
    goto :goto_1a

    .line 727
    :cond_20
    move-object/from16 v41, v14

    .line 728
    .line 729
    new-instance v6, Landroid/util/SparseArray;

    .line 730
    .line 731
    invoke-direct {v6}, Landroid/util/SparseArray;-><init>()V

    .line 732
    .line 733
    .line 734
    invoke-interface {v4}, Ljava/lang/CharSequence;->length()I

    .line 735
    .line 736
    .line 737
    move-result v10

    .line 738
    const-class v11, Ljava/lang/Object;

    .line 739
    .line 740
    const/4 v13, 0x0

    .line 741
    invoke-interface {v4, v13, v10, v11}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 742
    .line 743
    .line 744
    move-result-object v10

    .line 745
    array-length v11, v10

    .line 746
    const/4 v13, 0x0

    .line 747
    :goto_1b
    if-ge v13, v11, :cond_47

    .line 748
    .line 749
    aget-object v14, v10, v13

    .line 750
    .line 751
    move-object/from16 v40, v3

    .line 752
    .line 753
    instance-of v3, v14, Landroid/text/style/StrikethroughSpan;

    .line 754
    .line 755
    const/16 v37, 0x0

    .line 756
    .line 757
    if-eqz v3, :cond_21

    .line 758
    .line 759
    const-string v42, "<span style=\'text-decoration:line-through;\'>"

    .line 760
    .line 761
    move-object/from16 v43, v42

    .line 762
    .line 763
    move/from16 v42, v3

    .line 764
    .line 765
    move-object/from16 v3, v43

    .line 766
    .line 767
    move-object/from16 v43, v7

    .line 768
    .line 769
    :goto_1c
    move-object/from16 v44, v10

    .line 770
    .line 771
    :goto_1d
    move/from16 v45, v11

    .line 772
    .line 773
    move/from16 v46, v13

    .line 774
    .line 775
    goto/16 :goto_23

    .line 776
    .line 777
    :cond_21
    move/from16 v42, v3

    .line 778
    .line 779
    instance-of v3, v14, Landroid/text/style/ForegroundColorSpan;

    .line 780
    .line 781
    if-eqz v3, :cond_22

    .line 782
    .line 783
    move-object v3, v14

    .line 784
    check-cast v3, Landroid/text/style/ForegroundColorSpan;

    .line 785
    .line 786
    invoke-virtual {v3}, Landroid/text/style/ForegroundColorSpan;->getForegroundColor()I

    .line 787
    .line 788
    .line 789
    move-result v3

    .line 790
    invoke-static {v3}, Lpw/a;->a(I)Ljava/lang/String;

    .line 791
    .line 792
    .line 793
    move-result-object v3

    .line 794
    sget-object v43, Lw7/w;->a:Ljava/lang/String;

    .line 795
    .line 796
    sget-object v43, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 797
    .line 798
    move-object/from16 v43, v7

    .line 799
    .line 800
    const-string v7, "<span style=\'color:"

    .line 801
    .line 802
    invoke-static {v7, v3, v5}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 803
    .line 804
    .line 805
    move-result-object v3

    .line 806
    goto :goto_1c

    .line 807
    :cond_22
    move-object/from16 v43, v7

    .line 808
    .line 809
    instance-of v3, v14, Landroid/text/style/BackgroundColorSpan;

    .line 810
    .line 811
    if-eqz v3, :cond_23

    .line 812
    .line 813
    move-object v3, v14

    .line 814
    check-cast v3, Landroid/text/style/BackgroundColorSpan;

    .line 815
    .line 816
    invoke-virtual {v3}, Landroid/text/style/BackgroundColorSpan;->getBackgroundColor()I

    .line 817
    .line 818
    .line 819
    move-result v3

    .line 820
    sget-object v7, Lw7/w;->a:Ljava/lang/String;

    .line 821
    .line 822
    sget-object v7, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 823
    .line 824
    const-string v7, "<span class=\'bg_"

    .line 825
    .line 826
    move-object/from16 v44, v10

    .line 827
    .line 828
    const-string v10, "\'>"

    .line 829
    .line 830
    invoke-static {v7, v3, v10}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 831
    .line 832
    .line 833
    move-result-object v3

    .line 834
    goto :goto_1d

    .line 835
    :cond_23
    move-object/from16 v44, v10

    .line 836
    .line 837
    instance-of v3, v14, Lv7/e;

    .line 838
    .line 839
    if-eqz v3, :cond_24

    .line 840
    .line 841
    const-string v3, "<span style=\'text-combine-upright:all;\'>"

    .line 842
    .line 843
    goto :goto_1d

    .line 844
    :cond_24
    instance-of v3, v14, Landroid/text/style/AbsoluteSizeSpan;

    .line 845
    .line 846
    if-eqz v3, :cond_26

    .line 847
    .line 848
    move-object v3, v14

    .line 849
    check-cast v3, Landroid/text/style/AbsoluteSizeSpan;

    .line 850
    .line 851
    invoke-virtual {v3}, Landroid/text/style/AbsoluteSizeSpan;->getDip()Z

    .line 852
    .line 853
    .line 854
    move-result v7

    .line 855
    if-eqz v7, :cond_25

    .line 856
    .line 857
    invoke-virtual {v3}, Landroid/text/style/AbsoluteSizeSpan;->getSize()I

    .line 858
    .line 859
    .line 860
    move-result v3

    .line 861
    int-to-float v3, v3

    .line 862
    goto :goto_1e

    .line 863
    :cond_25
    invoke-virtual {v3}, Landroid/text/style/AbsoluteSizeSpan;->getSize()I

    .line 864
    .line 865
    .line 866
    move-result v3

    .line 867
    int-to-float v3, v3

    .line 868
    div-float v3, v3, v35

    .line 869
    .line 870
    :goto_1e
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 871
    .line 872
    .line 873
    move-result-object v3

    .line 874
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 875
    .line 876
    .line 877
    move-result-object v3

    .line 878
    sget-object v7, Lw7/w;->a:Ljava/lang/String;

    .line 879
    .line 880
    sget-object v7, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 881
    .line 882
    const-string v10, "<span style=\'font-size:%.2fpx;\'>"

    .line 883
    .line 884
    invoke-static {v7, v10, v3}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 885
    .line 886
    .line 887
    move-result-object v3

    .line 888
    goto :goto_1d

    .line 889
    :cond_26
    instance-of v3, v14, Landroid/text/style/RelativeSizeSpan;

    .line 890
    .line 891
    if-eqz v3, :cond_27

    .line 892
    .line 893
    move-object v3, v14

    .line 894
    check-cast v3, Landroid/text/style/RelativeSizeSpan;

    .line 895
    .line 896
    invoke-virtual {v3}, Landroid/text/style/RelativeSizeSpan;->getSizeChange()F

    .line 897
    .line 898
    .line 899
    move-result v3

    .line 900
    mul-float v3, v3, v18

    .line 901
    .line 902
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 903
    .line 904
    .line 905
    move-result-object v3

    .line 906
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 907
    .line 908
    .line 909
    move-result-object v3

    .line 910
    sget-object v7, Lw7/w;->a:Ljava/lang/String;

    .line 911
    .line 912
    sget-object v7, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 913
    .line 914
    const-string v10, "<span style=\'font-size:%.2f%%;\'>"

    .line 915
    .line 916
    invoke-static {v7, v10, v3}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 917
    .line 918
    .line 919
    move-result-object v3

    .line 920
    goto/16 :goto_1d

    .line 921
    .line 922
    :cond_27
    instance-of v3, v14, Landroid/text/style/TypefaceSpan;

    .line 923
    .line 924
    if-eqz v3, :cond_29

    .line 925
    .line 926
    move-object v3, v14

    .line 927
    check-cast v3, Landroid/text/style/TypefaceSpan;

    .line 928
    .line 929
    invoke-virtual {v3}, Landroid/text/style/TypefaceSpan;->getFamily()Ljava/lang/String;

    .line 930
    .line 931
    .line 932
    move-result-object v3

    .line 933
    if-eqz v3, :cond_28

    .line 934
    .line 935
    sget-object v7, Lw7/w;->a:Ljava/lang/String;

    .line 936
    .line 937
    sget-object v7, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 938
    .line 939
    const-string v7, "<span style=\'font-family:\""

    .line 940
    .line 941
    const-string v10, "\";\'>"

    .line 942
    .line 943
    invoke-static {v7, v3, v10}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 944
    .line 945
    .line 946
    move-result-object v3

    .line 947
    goto/16 :goto_1d

    .line 948
    .line 949
    :cond_28
    :goto_1f
    move/from16 v45, v11

    .line 950
    .line 951
    move/from16 v46, v13

    .line 952
    .line 953
    move-object/from16 v3, v37

    .line 954
    .line 955
    goto/16 :goto_23

    .line 956
    .line 957
    :cond_29
    instance-of v3, v14, Landroid/text/style/StyleSpan;

    .line 958
    .line 959
    if-eqz v3, :cond_2d

    .line 960
    .line 961
    move-object v3, v14

    .line 962
    check-cast v3, Landroid/text/style/StyleSpan;

    .line 963
    .line 964
    invoke-virtual {v3}, Landroid/text/style/StyleSpan;->getStyle()I

    .line 965
    .line 966
    .line 967
    move-result v3

    .line 968
    const/4 v7, 0x1

    .line 969
    if-eq v3, v7, :cond_2c

    .line 970
    .line 971
    const/4 v7, 0x2

    .line 972
    if-eq v3, v7, :cond_2b

    .line 973
    .line 974
    const/4 v7, 0x3

    .line 975
    if-eq v3, v7, :cond_2a

    .line 976
    .line 977
    goto :goto_1f

    .line 978
    :cond_2a
    const-string v3, "<b><i>"

    .line 979
    .line 980
    goto/16 :goto_1d

    .line 981
    .line 982
    :cond_2b
    const-string v3, "<i>"

    .line 983
    .line 984
    goto/16 :goto_1d

    .line 985
    .line 986
    :cond_2c
    const-string v3, "<b>"

    .line 987
    .line 988
    goto/16 :goto_1d

    .line 989
    .line 990
    :cond_2d
    instance-of v3, v14, Lv7/g;

    .line 991
    .line 992
    if-eqz v3, :cond_31

    .line 993
    .line 994
    move-object v3, v14

    .line 995
    check-cast v3, Lv7/g;

    .line 996
    .line 997
    iget v3, v3, Lv7/g;->b:I

    .line 998
    .line 999
    const/4 v7, -0x1

    .line 1000
    if-eq v3, v7, :cond_30

    .line 1001
    .line 1002
    const/4 v7, 0x1

    .line 1003
    if-eq v3, v7, :cond_2f

    .line 1004
    .line 1005
    const/4 v7, 0x2

    .line 1006
    if-eq v3, v7, :cond_2e

    .line 1007
    .line 1008
    goto :goto_1f

    .line 1009
    :cond_2e
    const-string v3, "<ruby style=\'ruby-position:under;\'>"

    .line 1010
    .line 1011
    goto/16 :goto_1d

    .line 1012
    .line 1013
    :cond_2f
    const-string v3, "<ruby style=\'ruby-position:over;\'>"

    .line 1014
    .line 1015
    goto/16 :goto_1d

    .line 1016
    .line 1017
    :cond_30
    const-string v3, "<ruby style=\'ruby-position:unset;\'>"

    .line 1018
    .line 1019
    goto/16 :goto_1d

    .line 1020
    .line 1021
    :cond_31
    instance-of v3, v14, Landroid/text/style/UnderlineSpan;

    .line 1022
    .line 1023
    if-eqz v3, :cond_32

    .line 1024
    .line 1025
    const-string v3, "<u>"

    .line 1026
    .line 1027
    goto/16 :goto_1d

    .line 1028
    .line 1029
    :cond_32
    instance-of v3, v14, Lv7/h;

    .line 1030
    .line 1031
    if-eqz v3, :cond_28

    .line 1032
    .line 1033
    move-object v3, v14

    .line 1034
    check-cast v3, Lv7/h;

    .line 1035
    .line 1036
    iget v7, v3, Lv7/h;->a:I

    .line 1037
    .line 1038
    iget v10, v3, Lv7/h;->b:I

    .line 1039
    .line 1040
    move/from16 v45, v11

    .line 1041
    .line 1042
    new-instance v11, Ljava/lang/StringBuilder;

    .line 1043
    .line 1044
    invoke-direct {v11}, Ljava/lang/StringBuilder;-><init>()V

    .line 1045
    .line 1046
    .line 1047
    move/from16 v46, v13

    .line 1048
    .line 1049
    const/4 v13, 0x1

    .line 1050
    if-eq v10, v13, :cond_34

    .line 1051
    .line 1052
    const/4 v13, 0x2

    .line 1053
    if-eq v10, v13, :cond_33

    .line 1054
    .line 1055
    goto :goto_20

    .line 1056
    :cond_33
    const-string v10, "open "

    .line 1057
    .line 1058
    invoke-virtual {v11, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1059
    .line 1060
    .line 1061
    goto :goto_20

    .line 1062
    :cond_34
    const/4 v13, 0x2

    .line 1063
    const-string v10, "filled "

    .line 1064
    .line 1065
    invoke-virtual {v11, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1066
    .line 1067
    .line 1068
    :goto_20
    if-eqz v7, :cond_38

    .line 1069
    .line 1070
    const/4 v10, 0x1

    .line 1071
    if-eq v7, v10, :cond_37

    .line 1072
    .line 1073
    if-eq v7, v13, :cond_36

    .line 1074
    .line 1075
    const/4 v10, 0x3

    .line 1076
    if-eq v7, v10, :cond_35

    .line 1077
    .line 1078
    invoke-virtual {v11, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1079
    .line 1080
    .line 1081
    goto :goto_21

    .line 1082
    :cond_35
    const-string v7, "sesame"

    .line 1083
    .line 1084
    invoke-virtual {v11, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1085
    .line 1086
    .line 1087
    goto :goto_21

    .line 1088
    :cond_36
    const-string v7, "dot"

    .line 1089
    .line 1090
    invoke-virtual {v11, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1091
    .line 1092
    .line 1093
    goto :goto_21

    .line 1094
    :cond_37
    const-string v7, "circle"

    .line 1095
    .line 1096
    invoke-virtual {v11, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1097
    .line 1098
    .line 1099
    goto :goto_21

    .line 1100
    :cond_38
    const-string v7, "none"

    .line 1101
    .line 1102
    invoke-virtual {v11, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1103
    .line 1104
    .line 1105
    :goto_21
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1106
    .line 1107
    .line 1108
    move-result-object v7

    .line 1109
    iget v3, v3, Lv7/h;->c:I

    .line 1110
    .line 1111
    const/4 v11, 0x2

    .line 1112
    if-eq v3, v11, :cond_39

    .line 1113
    .line 1114
    const-string v3, "over right"

    .line 1115
    .line 1116
    goto :goto_22

    .line 1117
    :cond_39
    const-string v3, "under left"

    .line 1118
    .line 1119
    :goto_22
    filled-new-array {v7, v3}, [Ljava/lang/Object;

    .line 1120
    .line 1121
    .line 1122
    move-result-object v3

    .line 1123
    sget-object v7, Lw7/w;->a:Ljava/lang/String;

    .line 1124
    .line 1125
    sget-object v7, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 1126
    .line 1127
    const-string v10, "<span style=\'-webkit-text-emphasis-style:%1$s;text-emphasis-style:%1$s;-webkit-text-emphasis-position:%2$s;text-emphasis-position:%2$s;display:inline-block;\'>"

    .line 1128
    .line 1129
    invoke-static {v7, v10, v3}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 1130
    .line 1131
    .line 1132
    move-result-object v3

    .line 1133
    :goto_23
    if-nez v42, :cond_3a

    .line 1134
    .line 1135
    instance-of v7, v14, Landroid/text/style/ForegroundColorSpan;

    .line 1136
    .line 1137
    if-nez v7, :cond_3a

    .line 1138
    .line 1139
    instance-of v7, v14, Landroid/text/style/BackgroundColorSpan;

    .line 1140
    .line 1141
    if-nez v7, :cond_3a

    .line 1142
    .line 1143
    instance-of v7, v14, Lv7/e;

    .line 1144
    .line 1145
    if-nez v7, :cond_3a

    .line 1146
    .line 1147
    instance-of v7, v14, Landroid/text/style/AbsoluteSizeSpan;

    .line 1148
    .line 1149
    if-nez v7, :cond_3a

    .line 1150
    .line 1151
    instance-of v7, v14, Landroid/text/style/RelativeSizeSpan;

    .line 1152
    .line 1153
    if-nez v7, :cond_3a

    .line 1154
    .line 1155
    instance-of v7, v14, Lv7/h;

    .line 1156
    .line 1157
    if-eqz v7, :cond_3b

    .line 1158
    .line 1159
    :cond_3a
    const/4 v10, 0x3

    .line 1160
    goto :goto_26

    .line 1161
    :cond_3b
    instance-of v7, v14, Landroid/text/style/TypefaceSpan;

    .line 1162
    .line 1163
    if-eqz v7, :cond_3d

    .line 1164
    .line 1165
    move-object v7, v14

    .line 1166
    check-cast v7, Landroid/text/style/TypefaceSpan;

    .line 1167
    .line 1168
    invoke-virtual {v7}, Landroid/text/style/TypefaceSpan;->getFamily()Ljava/lang/String;

    .line 1169
    .line 1170
    .line 1171
    move-result-object v7

    .line 1172
    if-eqz v7, :cond_3c

    .line 1173
    .line 1174
    move-object v7, v12

    .line 1175
    :goto_24
    const/4 v10, 0x3

    .line 1176
    goto :goto_27

    .line 1177
    :cond_3c
    move-object/from16 v7, v37

    .line 1178
    .line 1179
    goto :goto_24

    .line 1180
    :cond_3d
    instance-of v7, v14, Landroid/text/style/StyleSpan;

    .line 1181
    .line 1182
    if-eqz v7, :cond_42

    .line 1183
    .line 1184
    move-object v7, v14

    .line 1185
    check-cast v7, Landroid/text/style/StyleSpan;

    .line 1186
    .line 1187
    invoke-virtual {v7}, Landroid/text/style/StyleSpan;->getStyle()I

    .line 1188
    .line 1189
    .line 1190
    move-result v7

    .line 1191
    const/4 v10, 0x1

    .line 1192
    if-eq v7, v10, :cond_41

    .line 1193
    .line 1194
    const/4 v11, 0x2

    .line 1195
    if-eq v7, v11, :cond_40

    .line 1196
    .line 1197
    const/4 v10, 0x3

    .line 1198
    if-eq v7, v10, :cond_3e

    .line 1199
    .line 1200
    goto :goto_25

    .line 1201
    :cond_3e
    const-string v37, "</i></b>"

    .line 1202
    .line 1203
    :cond_3f
    :goto_25
    move-object/from16 v7, v37

    .line 1204
    .line 1205
    goto :goto_27

    .line 1206
    :cond_40
    const/4 v10, 0x3

    .line 1207
    const-string v37, "</i>"

    .line 1208
    .line 1209
    goto :goto_25

    .line 1210
    :cond_41
    const/4 v10, 0x3

    .line 1211
    const-string v37, "</b>"

    .line 1212
    .line 1213
    goto :goto_25

    .line 1214
    :cond_42
    const/4 v10, 0x3

    .line 1215
    instance-of v7, v14, Lv7/g;

    .line 1216
    .line 1217
    if-eqz v7, :cond_43

    .line 1218
    .line 1219
    move-object v7, v14

    .line 1220
    check-cast v7, Lv7/g;

    .line 1221
    .line 1222
    new-instance v11, Ljava/lang/StringBuilder;

    .line 1223
    .line 1224
    const-string v13, "<rt>"

    .line 1225
    .line 1226
    invoke-direct {v11, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1227
    .line 1228
    .line 1229
    iget-object v7, v7, Lv7/g;->a:Ljava/lang/String;

    .line 1230
    .line 1231
    invoke-static {v7}, Ly9/e0;->a(Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 1232
    .line 1233
    .line 1234
    move-result-object v7

    .line 1235
    invoke-virtual {v11, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1236
    .line 1237
    .line 1238
    const-string v7, "</rt></ruby>"

    .line 1239
    .line 1240
    invoke-virtual {v11, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1241
    .line 1242
    .line 1243
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1244
    .line 1245
    .line 1246
    move-result-object v37

    .line 1247
    goto :goto_25

    .line 1248
    :cond_43
    instance-of v7, v14, Landroid/text/style/UnderlineSpan;

    .line 1249
    .line 1250
    if-eqz v7, :cond_3f

    .line 1251
    .line 1252
    const-string v37, "</u>"

    .line 1253
    .line 1254
    goto :goto_25

    .line 1255
    :goto_26
    move-object v7, v12

    .line 1256
    :goto_27
    invoke-interface {v4, v14}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 1257
    .line 1258
    .line 1259
    move-result v11

    .line 1260
    invoke-interface {v4, v14}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    .line 1261
    .line 1262
    .line 1263
    move-result v13

    .line 1264
    if-eqz v3, :cond_46

    .line 1265
    .line 1266
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1267
    .line 1268
    .line 1269
    new-instance v14, Ly9/c0;

    .line 1270
    .line 1271
    invoke-direct {v14, v3, v7, v11, v13}, Ly9/c0;-><init>(Ljava/lang/String;Ljava/lang/String;II)V

    .line 1272
    .line 1273
    .line 1274
    invoke-virtual {v6, v11}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 1275
    .line 1276
    .line 1277
    move-result-object v3

    .line 1278
    check-cast v3, Ly9/d0;

    .line 1279
    .line 1280
    if-nez v3, :cond_44

    .line 1281
    .line 1282
    new-instance v3, Ly9/d0;

    .line 1283
    .line 1284
    invoke-direct {v3}, Ly9/d0;-><init>()V

    .line 1285
    .line 1286
    .line 1287
    invoke-virtual {v6, v11, v3}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 1288
    .line 1289
    .line 1290
    :cond_44
    iget-object v3, v3, Ly9/d0;->a:Ljava/util/ArrayList;

    .line 1291
    .line 1292
    invoke-virtual {v3, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1293
    .line 1294
    .line 1295
    invoke-virtual {v6, v13}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 1296
    .line 1297
    .line 1298
    move-result-object v3

    .line 1299
    check-cast v3, Ly9/d0;

    .line 1300
    .line 1301
    if-nez v3, :cond_45

    .line 1302
    .line 1303
    new-instance v3, Ly9/d0;

    .line 1304
    .line 1305
    invoke-direct {v3}, Ly9/d0;-><init>()V

    .line 1306
    .line 1307
    .line 1308
    invoke-virtual {v6, v13, v3}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 1309
    .line 1310
    .line 1311
    :cond_45
    iget-object v3, v3, Ly9/d0;->b:Ljava/util/ArrayList;

    .line 1312
    .line 1313
    invoke-virtual {v3, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1314
    .line 1315
    .line 1316
    :cond_46
    add-int/lit8 v13, v46, 0x1

    .line 1317
    .line 1318
    move-object/from16 v3, v40

    .line 1319
    .line 1320
    move-object/from16 v7, v43

    .line 1321
    .line 1322
    move-object/from16 v10, v44

    .line 1323
    .line 1324
    move/from16 v11, v45

    .line 1325
    .line 1326
    goto/16 :goto_1b

    .line 1327
    .line 1328
    :cond_47
    move-object/from16 v40, v3

    .line 1329
    .line 1330
    move-object/from16 v43, v7

    .line 1331
    .line 1332
    const/4 v10, 0x3

    .line 1333
    new-instance v3, Ljava/lang/StringBuilder;

    .line 1334
    .line 1335
    invoke-interface {v4}, Ljava/lang/CharSequence;->length()I

    .line 1336
    .line 1337
    .line 1338
    move-result v7

    .line 1339
    invoke-direct {v3, v7}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 1340
    .line 1341
    .line 1342
    const/4 v7, 0x0

    .line 1343
    const/4 v13, 0x0

    .line 1344
    :goto_28
    invoke-virtual {v6}, Landroid/util/SparseArray;->size()I

    .line 1345
    .line 1346
    .line 1347
    move-result v11

    .line 1348
    if-ge v13, v11, :cond_4a

    .line 1349
    .line 1350
    invoke-virtual {v6, v13}, Landroid/util/SparseArray;->keyAt(I)I

    .line 1351
    .line 1352
    .line 1353
    move-result v11

    .line 1354
    invoke-interface {v4, v7, v11}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 1355
    .line 1356
    .line 1357
    move-result-object v7

    .line 1358
    invoke-static {v7}, Ly9/e0;->a(Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 1359
    .line 1360
    .line 1361
    move-result-object v7

    .line 1362
    invoke-virtual {v3, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1363
    .line 1364
    .line 1365
    invoke-virtual {v6, v11}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 1366
    .line 1367
    .line 1368
    move-result-object v7

    .line 1369
    check-cast v7, Ly9/d0;

    .line 1370
    .line 1371
    iget-object v14, v7, Ly9/d0;->b:Ljava/util/ArrayList;

    .line 1372
    .line 1373
    iget-object v10, v7, Ly9/d0;->a:Ljava/util/ArrayList;

    .line 1374
    .line 1375
    move-object/from16 v18, v6

    .line 1376
    .line 1377
    sget-object v6, Ly9/c0;->f:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 1378
    .line 1379
    invoke-static {v14, v6}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 1380
    .line 1381
    .line 1382
    iget-object v6, v7, Ly9/d0;->b:Ljava/util/ArrayList;

    .line 1383
    .line 1384
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1385
    .line 1386
    .line 1387
    move-result-object v6

    .line 1388
    :goto_29
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 1389
    .line 1390
    .line 1391
    move-result v7

    .line 1392
    if-eqz v7, :cond_48

    .line 1393
    .line 1394
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1395
    .line 1396
    .line 1397
    move-result-object v7

    .line 1398
    check-cast v7, Ly9/c0;

    .line 1399
    .line 1400
    iget-object v7, v7, Ly9/c0;->d:Ljava/lang/String;

    .line 1401
    .line 1402
    invoke-virtual {v3, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1403
    .line 1404
    .line 1405
    goto :goto_29

    .line 1406
    :cond_48
    sget-object v6, Ly9/c0;->e:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 1407
    .line 1408
    invoke-static {v10, v6}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 1409
    .line 1410
    .line 1411
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1412
    .line 1413
    .line 1414
    move-result-object v6

    .line 1415
    :goto_2a
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 1416
    .line 1417
    .line 1418
    move-result v7

    .line 1419
    if-eqz v7, :cond_49

    .line 1420
    .line 1421
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1422
    .line 1423
    .line 1424
    move-result-object v7

    .line 1425
    check-cast v7, Ly9/c0;

    .line 1426
    .line 1427
    iget-object v7, v7, Ly9/c0;->c:Ljava/lang/String;

    .line 1428
    .line 1429
    invoke-virtual {v3, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1430
    .line 1431
    .line 1432
    goto :goto_2a

    .line 1433
    :cond_49
    add-int/lit8 v13, v13, 0x1

    .line 1434
    .line 1435
    move v7, v11

    .line 1436
    move-object/from16 v6, v18

    .line 1437
    .line 1438
    const/4 v10, 0x3

    .line 1439
    goto :goto_28

    .line 1440
    :cond_4a
    invoke-interface {v4}, Ljava/lang/CharSequence;->length()I

    .line 1441
    .line 1442
    .line 1443
    move-result v6

    .line 1444
    invoke-interface {v4, v7, v6}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 1445
    .line 1446
    .line 1447
    move-result-object v4

    .line 1448
    invoke-static {v4}, Ly9/e0;->a(Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 1449
    .line 1450
    .line 1451
    move-result-object v4

    .line 1452
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1453
    .line 1454
    .line 1455
    new-instance v4, Lj51/i;

    .line 1456
    .line 1457
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1458
    .line 1459
    .line 1460
    move-result-object v3

    .line 1461
    const/4 v10, 0x5

    .line 1462
    invoke-direct {v4, v3, v10}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 1463
    .line 1464
    .line 1465
    :goto_2b
    invoke-virtual {v2}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 1466
    .line 1467
    .line 1468
    move-result-object v3

    .line 1469
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1470
    .line 1471
    .line 1472
    move-result-object v3

    .line 1473
    :goto_2c
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1474
    .line 1475
    .line 1476
    move-result v6

    .line 1477
    if-eqz v6, :cond_4d

    .line 1478
    .line 1479
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1480
    .line 1481
    .line 1482
    move-result-object v6

    .line 1483
    check-cast v6, Ljava/lang/String;

    .line 1484
    .line 1485
    invoke-virtual {v2, v6}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1486
    .line 1487
    .line 1488
    move-result-object v7

    .line 1489
    check-cast v7, Ljava/lang/String;

    .line 1490
    .line 1491
    invoke-virtual {v2, v6, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1492
    .line 1493
    .line 1494
    move-result-object v7

    .line 1495
    check-cast v7, Ljava/lang/String;

    .line 1496
    .line 1497
    if-eqz v7, :cond_4c

    .line 1498
    .line 1499
    invoke-virtual {v2, v6}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1500
    .line 1501
    .line 1502
    move-result-object v6

    .line 1503
    invoke-virtual {v7, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1504
    .line 1505
    .line 1506
    move-result v6

    .line 1507
    if-eqz v6, :cond_4b

    .line 1508
    .line 1509
    goto :goto_2d

    .line 1510
    :cond_4b
    const/4 v6, 0x0

    .line 1511
    goto :goto_2e

    .line 1512
    :cond_4c
    :goto_2d
    const/4 v6, 0x1

    .line 1513
    :goto_2e
    invoke-static {v6}, Lw7/a;->j(Z)V

    .line 1514
    .line 1515
    .line 1516
    goto :goto_2c

    .line 1517
    :cond_4d
    invoke-static/range {v38 .. v38}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1518
    .line 1519
    .line 1520
    move-result-object v3

    .line 1521
    invoke-static/range {v36 .. v36}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1522
    .line 1523
    .line 1524
    move-result-object v6

    .line 1525
    invoke-static/range {v24 .. v24}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1526
    .line 1527
    .line 1528
    move-result-object v35

    .line 1529
    invoke-static/range {v20 .. v20}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1530
    .line 1531
    .line 1532
    move-result-object v36

    .line 1533
    iget v7, v8, Lv7/b;->q:F

    .line 1534
    .line 1535
    cmpl-float v10, v7, v23

    .line 1536
    .line 1537
    if-eqz v10, :cond_50

    .line 1538
    .line 1539
    const/4 v11, 0x2

    .line 1540
    if-eq v15, v11, :cond_4f

    .line 1541
    .line 1542
    const/4 v10, 0x1

    .line 1543
    if-ne v15, v10, :cond_4e

    .line 1544
    .line 1545
    goto :goto_2f

    .line 1546
    :cond_4e
    const-string v10, "skewX"

    .line 1547
    .line 1548
    goto :goto_30

    .line 1549
    :cond_4f
    :goto_2f
    const-string v10, "skewY"

    .line 1550
    .line 1551
    :goto_30
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1552
    .line 1553
    .line 1554
    move-result-object v7

    .line 1555
    filled-new-array {v10, v7}, [Ljava/lang/Object;

    .line 1556
    .line 1557
    .line 1558
    move-result-object v7

    .line 1559
    sget-object v10, Lw7/w;->a:Ljava/lang/String;

    .line 1560
    .line 1561
    sget-object v10, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 1562
    .line 1563
    const-string v11, "%s(%.2fdeg)"

    .line 1564
    .line 1565
    invoke-static {v10, v11, v7}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 1566
    .line 1567
    .line 1568
    move-result-object v7

    .line 1569
    move-object/from16 v37, v7

    .line 1570
    .line 1571
    :goto_31
    move-object/from16 v24, v3

    .line 1572
    .line 1573
    move-object/from16 v26, v6

    .line 1574
    .line 1575
    goto :goto_32

    .line 1576
    :cond_50
    move-object/from16 v37, v26

    .line 1577
    .line 1578
    goto :goto_31

    .line 1579
    :goto_32
    filled-new-array/range {v24 .. v37}, [Ljava/lang/Object;

    .line 1580
    .line 1581
    .line 1582
    move-result-object v3

    .line 1583
    sget-object v6, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 1584
    .line 1585
    const-string v7, "<div style=\'position:absolute;z-index:%s;%s:%.2f%%;%s:%s;%s:%s;text-align:%s;writing-mode:%s;font-size:%s;background-color:%s;transform:translate(%s%%,%s%%)%s;\'>"

    .line 1586
    .line 1587
    invoke-static {v6, v7, v3}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 1588
    .line 1589
    .line 1590
    move-result-object v3

    .line 1591
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1592
    .line 1593
    .line 1594
    const-string v3, "<span class=\'default_bg\'>"

    .line 1595
    .line 1596
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1597
    .line 1598
    .line 1599
    iget-object v3, v8, Lv7/b;->c:Landroid/text/Layout$Alignment;

    .line 1600
    .line 1601
    iget-object v4, v4, Lj51/i;->b:Ljava/lang/String;

    .line 1602
    .line 1603
    if-eqz v3, :cond_53

    .line 1604
    .line 1605
    sget-object v6, Ly9/l0;->a:[I

    .line 1606
    .line 1607
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 1608
    .line 1609
    .line 1610
    move-result v3

    .line 1611
    aget v3, v6, v3

    .line 1612
    .line 1613
    const/4 v10, 0x1

    .line 1614
    if-eq v3, v10, :cond_52

    .line 1615
    .line 1616
    const/4 v11, 0x2

    .line 1617
    if-eq v3, v11, :cond_51

    .line 1618
    .line 1619
    move-object/from16 v3, v16

    .line 1620
    .line 1621
    goto :goto_33

    .line 1622
    :cond_51
    move-object/from16 v3, v41

    .line 1623
    .line 1624
    goto :goto_33

    .line 1625
    :cond_52
    const/4 v11, 0x2

    .line 1626
    move-object/from16 v3, v39

    .line 1627
    .line 1628
    :goto_33
    new-instance v6, Ljava/lang/StringBuilder;

    .line 1629
    .line 1630
    const-string v7, "<span style=\'display:inline-block; text-align:"

    .line 1631
    .line 1632
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1633
    .line 1634
    .line 1635
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1636
    .line 1637
    .line 1638
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1639
    .line 1640
    .line 1641
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1642
    .line 1643
    .line 1644
    move-result-object v3

    .line 1645
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1646
    .line 1647
    .line 1648
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1649
    .line 1650
    .line 1651
    invoke-virtual {v1, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1652
    .line 1653
    .line 1654
    goto :goto_34

    .line 1655
    :cond_53
    const/4 v11, 0x2

    .line 1656
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1657
    .line 1658
    .line 1659
    :goto_34
    const-string v3, "</span></div>"

    .line 1660
    .line 1661
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1662
    .line 1663
    .line 1664
    add-int/lit8 v6, v38, 0x1

    .line 1665
    .line 1666
    move/from16 v5, v17

    .line 1667
    .line 1668
    move-object/from16 v3, v40

    .line 1669
    .line 1670
    move-object/from16 v7, v43

    .line 1671
    .line 1672
    const/4 v4, 0x0

    .line 1673
    const/4 v10, 0x3

    .line 1674
    const/4 v12, 0x1

    .line 1675
    goto/16 :goto_1

    .line 1676
    .line 1677
    :cond_54
    const-string v3, "</div></body></html>"

    .line 1678
    .line 1679
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1680
    .line 1681
    .line 1682
    new-instance v3, Ljava/lang/StringBuilder;

    .line 1683
    .line 1684
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 1685
    .line 1686
    .line 1687
    const-string v4, "<html><head><style>"

    .line 1688
    .line 1689
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1690
    .line 1691
    .line 1692
    invoke-virtual {v2}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 1693
    .line 1694
    .line 1695
    move-result-object v4

    .line 1696
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1697
    .line 1698
    .line 1699
    move-result-object v4

    .line 1700
    :goto_35
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 1701
    .line 1702
    .line 1703
    move-result v5

    .line 1704
    if-eqz v5, :cond_55

    .line 1705
    .line 1706
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1707
    .line 1708
    .line 1709
    move-result-object v5

    .line 1710
    check-cast v5, Ljava/lang/String;

    .line 1711
    .line 1712
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1713
    .line 1714
    .line 1715
    const-string v6, "{"

    .line 1716
    .line 1717
    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1718
    .line 1719
    .line 1720
    invoke-virtual {v2, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1721
    .line 1722
    .line 1723
    move-result-object v5

    .line 1724
    check-cast v5, Ljava/lang/String;

    .line 1725
    .line 1726
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1727
    .line 1728
    .line 1729
    const-string v5, "}"

    .line 1730
    .line 1731
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1732
    .line 1733
    .line 1734
    goto :goto_35

    .line 1735
    :cond_55
    const-string v2, "</style></head>"

    .line 1736
    .line 1737
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1738
    .line 1739
    .line 1740
    const/4 v13, 0x0

    .line 1741
    invoke-virtual {v1, v13, v3}, Ljava/lang/StringBuilder;->insert(ILjava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 1742
    .line 1743
    .line 1744
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1745
    .line 1746
    .line 1747
    move-result-object v1

    .line 1748
    sget-object v2, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 1749
    .line 1750
    invoke-virtual {v1, v2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 1751
    .line 1752
    .line 1753
    move-result-object v1

    .line 1754
    const/4 v10, 0x1

    .line 1755
    invoke-static {v1, v10}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 1756
    .line 1757
    .line 1758
    move-result-object v1

    .line 1759
    const-string v2, "text/html"

    .line 1760
    .line 1761
    const-string v3, "base64"

    .line 1762
    .line 1763
    iget-object v0, v0, Ly9/m0;->e:Ly9/k0;

    .line 1764
    .line 1765
    invoke-virtual {v0, v1, v2, v3}, Landroid/webkit/WebView;->loadData(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 1766
    .line 1767
    .line 1768
    return-void
.end method

.method public final onLayout(ZIIII)V
    .locals 0

    .line 1
    invoke-super/range {p0 .. p5}, Landroid/widget/FrameLayout;->onLayout(ZIIII)V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    iget-object p1, p0, Ly9/m0;->f:Ljava/util/List;

    .line 7
    .line 8
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    if-nez p1, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Ly9/m0;->c()V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void
.end method
