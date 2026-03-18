.class public final Lh2/w5;
.super Lb/t;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public g:Lay0/a;

.field public h:Lh2/k6;

.field public i:J

.field public final j:Landroid/view/View;

.field public final k:Lh2/s5;


# direct methods
.method public constructor <init>(Lay0/a;Lh2/k6;JLandroid/view/View;Lt4/m;Lt4/c;Ljava/util/UUID;Lc1/c;Lvy0/b0;)V
    .locals 8

    .line 1
    new-instance v0, Landroid/view/ContextThemeWrapper;

    .line 2
    .line 3
    invoke-virtual {p5}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const v2, 0x7f130131

    .line 8
    .line 9
    .line 10
    invoke-direct {v0, v1, v2}, Landroid/view/ContextThemeWrapper;-><init>(Landroid/content/Context;I)V

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-direct {p0, v0, v1}, Lb/t;-><init>(Landroid/content/Context;I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lh2/w5;->g:Lay0/a;

    .line 18
    .line 19
    iput-object p2, p0, Lh2/w5;->h:Lh2/k6;

    .line 20
    .line 21
    iput-wide p3, p0, Lh2/w5;->i:J

    .line 22
    .line 23
    iput-object p5, p0, Lh2/w5;->j:Landroid/view/View;

    .line 24
    .line 25
    const/16 p2, 0x8

    .line 26
    .line 27
    int-to-float p2, p2

    .line 28
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 29
    .line 30
    .line 31
    move-result-object p3

    .line 32
    if-eqz p3, :cond_4

    .line 33
    .line 34
    const/4 p4, 0x1

    .line 35
    invoke-virtual {p3, p4}, Landroid/view/Window;->requestFeature(I)Z

    .line 36
    .line 37
    .line 38
    const v0, 0x106000d

    .line 39
    .line 40
    .line 41
    invoke-virtual {p3, v0}, Landroid/view/Window;->setBackgroundDrawableResource(I)V

    .line 42
    .line 43
    .line 44
    invoke-static {p3, v1}, Ljp/pf;->b(Landroid/view/Window;Z)V

    .line 45
    .line 46
    .line 47
    new-instance v0, Lh2/s5;

    .line 48
    .line 49
    invoke-virtual {p0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    invoke-direct {v0, v2, p3}, Lh2/s5;-><init>(Landroid/content/Context;Landroid/view/Window;)V

    .line 54
    .line 55
    .line 56
    new-instance v2, Ljava/lang/StringBuilder;

    .line 57
    .line 58
    const-string v3, "Dialog:"

    .line 59
    .line 60
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    move-object/from16 v3, p8

    .line 64
    .line 65
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    const v3, 0x7f0a00e9

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0, v3, v2}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->setClipChildren(Z)V

    .line 79
    .line 80
    .line 81
    invoke-interface {p7, p2}, Lt4/c;->w0(F)F

    .line 82
    .line 83
    .line 84
    move-result p2

    .line 85
    invoke-virtual {v0, p2}, Landroid/view/View;->setElevation(F)V

    .line 86
    .line 87
    .line 88
    new-instance p2, Lh2/t5;

    .line 89
    .line 90
    const/4 v2, 0x0

    .line 91
    invoke-direct {p2, v2}, Lh2/t5;-><init>(I)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0, p2}, Landroid/view/View;->setOutlineProvider(Landroid/view/ViewOutlineProvider;)V

    .line 95
    .line 96
    .line 97
    iput-object v0, p0, Lh2/w5;->k:Lh2/s5;

    .line 98
    .line 99
    invoke-virtual {p0, v0}, Lb/t;->setContentView(Landroid/view/View;)V

    .line 100
    .line 101
    .line 102
    invoke-static {p5}, Landroidx/lifecycle/v0;->d(Landroid/view/View;)Landroidx/lifecycle/x;

    .line 103
    .line 104
    .line 105
    move-result-object p2

    .line 106
    invoke-static {v0, p2}, Landroidx/lifecycle/v0;->l(Landroid/view/View;Landroidx/lifecycle/x;)V

    .line 107
    .line 108
    .line 109
    invoke-static {p5}, Landroidx/lifecycle/v0;->e(Landroid/view/View;)Landroidx/lifecycle/i1;

    .line 110
    .line 111
    .line 112
    move-result-object p2

    .line 113
    invoke-static {v0, p2}, Landroidx/lifecycle/v0;->m(Landroid/view/View;Landroidx/lifecycle/i1;)V

    .line 114
    .line 115
    .line 116
    invoke-static {p5}, Lkp/w;->b(Landroid/view/View;)Lra/f;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    invoke-static {v0, p1}, Lkp/w;->d(Landroid/view/View;Lra/f;)V

    .line 121
    .line 122
    .line 123
    iget-object v3, p0, Lh2/w5;->g:Lay0/a;

    .line 124
    .line 125
    iget-object v4, p0, Lh2/w5;->h:Lh2/k6;

    .line 126
    .line 127
    iget-wide v5, p0, Lh2/w5;->i:J

    .line 128
    .line 129
    move-object v2, p0

    .line 130
    move-object v7, p6

    .line 131
    invoke-virtual/range {v2 .. v7}, Lh2/w5;->c(Lay0/a;Lh2/k6;JLt4/m;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {p3}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    new-instance p2, Laq/a;

    .line 139
    .line 140
    invoke-direct {p2, p1}, Laq/a;-><init>(Landroid/view/View;)V

    .line 141
    .line 142
    .line 143
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 144
    .line 145
    const/16 v0, 0x23

    .line 146
    .line 147
    if-lt p1, v0, :cond_0

    .line 148
    .line 149
    new-instance p1, Ld6/z1;

    .line 150
    .line 151
    invoke-direct {p1, p3, p2}, Ld6/y1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 152
    .line 153
    .line 154
    goto :goto_0

    .line 155
    :cond_0
    const/16 v0, 0x1e

    .line 156
    .line 157
    if-lt p1, v0, :cond_1

    .line 158
    .line 159
    new-instance p1, Ld6/y1;

    .line 160
    .line 161
    invoke-direct {p1, p3, p2}, Ld6/y1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 162
    .line 163
    .line 164
    goto :goto_0

    .line 165
    :cond_1
    new-instance p1, Ld6/x1;

    .line 166
    .line 167
    invoke-direct {p1, p3, p2}, Ld6/x1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 168
    .line 169
    .line 170
    :goto_0
    iget-object p2, p0, Lh2/w5;->h:Lh2/k6;

    .line 171
    .line 172
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 173
    .line 174
    .line 175
    iget-wide p2, p0, Lh2/w5;->i:J

    .line 176
    .line 177
    sget-wide v3, Le3/s;->h:J

    .line 178
    .line 179
    invoke-static {p2, p3, v3, v4}, Le3/s;->c(JJ)Z

    .line 180
    .line 181
    .line 182
    move-result v0

    .line 183
    const-wide/high16 v5, 0x3fe0000000000000L    # 0.5

    .line 184
    .line 185
    if-nez v0, :cond_2

    .line 186
    .line 187
    invoke-static {p2, p3}, Le3/j0;->r(J)F

    .line 188
    .line 189
    .line 190
    move-result p2

    .line 191
    float-to-double p2, p2

    .line 192
    cmpg-double p2, p2, v5

    .line 193
    .line 194
    if-gtz p2, :cond_2

    .line 195
    .line 196
    move p2, p4

    .line 197
    goto :goto_1

    .line 198
    :cond_2
    move p2, v1

    .line 199
    :goto_1
    invoke-virtual {p1, p2}, Ljp/rf;->c(Z)V

    .line 200
    .line 201
    .line 202
    iget-object p2, p0, Lh2/w5;->h:Lh2/k6;

    .line 203
    .line 204
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 205
    .line 206
    .line 207
    iget-wide p2, p0, Lh2/w5;->i:J

    .line 208
    .line 209
    invoke-static {p2, p3, v3, v4}, Le3/s;->c(JJ)Z

    .line 210
    .line 211
    .line 212
    move-result v0

    .line 213
    if-nez v0, :cond_3

    .line 214
    .line 215
    invoke-static {p2, p3}, Le3/j0;->r(J)F

    .line 216
    .line 217
    .line 218
    move-result p2

    .line 219
    float-to-double p2, p2

    .line 220
    cmpg-double p2, p2, v5

    .line 221
    .line 222
    if-gtz p2, :cond_3

    .line 223
    .line 224
    move v1, p4

    .line 225
    :cond_3
    invoke-virtual {p1, v1}, Ljp/rf;->b(Z)V

    .line 226
    .line 227
    .line 228
    iget-object p1, p0, Lb/t;->f:Lb/h0;

    .line 229
    .line 230
    new-instance p2, Lh2/v5;

    .line 231
    .line 232
    iget-object p3, p0, Lh2/w5;->h:Lh2/k6;

    .line 233
    .line 234
    iget-boolean p3, p3, Lh2/k6;->b:Z

    .line 235
    .line 236
    new-instance p4, Ld2/g;

    .line 237
    .line 238
    const/16 v0, 0x17

    .line 239
    .line 240
    invoke-direct {p4, p0, v0}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 241
    .line 242
    .line 243
    move-object/from16 v0, p9

    .line 244
    .line 245
    move-object/from16 v1, p10

    .line 246
    .line 247
    invoke-direct {p2, p3, v1, v0, p4}, Lh2/v5;-><init>(ZLvy0/b0;Lc1/c;Ld2/g;)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {p1, p0, p2}, Lb/h0;->a(Landroidx/lifecycle/x;Lb/a0;)V

    .line 251
    .line 252
    .line 253
    return-void

    .line 254
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 255
    .line 256
    const-string p1, "Dialog has no window"

    .line 257
    .line 258
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    throw p0
.end method


# virtual methods
.method public final c(Lay0/a;Lh2/k6;JLt4/m;)V
    .locals 1

    .line 1
    iput-object p1, p0, Lh2/w5;->g:Lay0/a;

    .line 2
    .line 3
    iput-object p2, p0, Lh2/w5;->h:Lh2/k6;

    .line 4
    .line 5
    iput-wide p3, p0, Lh2/w5;->i:J

    .line 6
    .line 7
    iget-object p1, p2, Lh2/k6;->a:Lx4/x;

    .line 8
    .line 9
    iget-object p2, p0, Lh2/w5;->j:Landroid/view/View;

    .line 10
    .line 11
    invoke-virtual {p2}, Landroid/view/View;->getRootView()Landroid/view/View;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    invoke-virtual {p2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    instance-of p3, p2, Landroid/view/WindowManager$LayoutParams;

    .line 20
    .line 21
    if-eqz p3, :cond_0

    .line 22
    .line 23
    check-cast p2, Landroid/view/WindowManager$LayoutParams;

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 p2, 0x0

    .line 27
    :goto_0
    const/4 p3, 0x1

    .line 28
    const/16 p4, 0x2000

    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    if-eqz p2, :cond_1

    .line 32
    .line 33
    iget p2, p2, Landroid/view/WindowManager$LayoutParams;->flags:I

    .line 34
    .line 35
    and-int/2addr p2, p4

    .line 36
    if-eqz p2, :cond_1

    .line 37
    .line 38
    move p2, p3

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    move p2, v0

    .line 41
    :goto_1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-eqz p1, :cond_4

    .line 46
    .line 47
    if-eq p1, p3, :cond_3

    .line 48
    .line 49
    const/4 p2, 0x2

    .line 50
    if-ne p1, p2, :cond_2

    .line 51
    .line 52
    move p2, v0

    .line 53
    goto :goto_2

    .line 54
    :cond_2
    new-instance p0, La8/r0;

    .line 55
    .line 56
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_3
    move p2, p3

    .line 61
    :cond_4
    :goto_2
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    if-eqz p2, :cond_5

    .line 69
    .line 70
    move p2, p4

    .line 71
    goto :goto_3

    .line 72
    :cond_5
    const/16 p2, -0x2001

    .line 73
    .line 74
    :goto_3
    invoke-virtual {p1, p2, p4}, Landroid/view/Window;->setFlags(II)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p5}, Ljava/lang/Enum;->ordinal()I

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    if-eqz p1, :cond_7

    .line 82
    .line 83
    if-ne p1, p3, :cond_6

    .line 84
    .line 85
    goto :goto_4

    .line 86
    :cond_6
    new-instance p0, La8/r0;

    .line 87
    .line 88
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 89
    .line 90
    .line 91
    throw p0

    .line 92
    :cond_7
    move p3, v0

    .line 93
    :goto_4
    iget-object p1, p0, Lh2/w5;->k:Lh2/s5;

    .line 94
    .line 95
    invoke-virtual {p1, p3}, Landroid/view/View;->setLayoutDirection(I)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    if-eqz p1, :cond_8

    .line 103
    .line 104
    const/4 p2, -0x1

    .line 105
    invoke-virtual {p1, p2, p2}, Landroid/view/Window;->setLayout(II)V

    .line 106
    .line 107
    .line 108
    :cond_8
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    if-eqz p0, :cond_a

    .line 113
    .line 114
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 115
    .line 116
    const/16 p2, 0x1e

    .line 117
    .line 118
    if-lt p1, p2, :cond_9

    .line 119
    .line 120
    const/16 p1, 0x30

    .line 121
    .line 122
    goto :goto_5

    .line 123
    :cond_9
    const/16 p1, 0x10

    .line 124
    .line 125
    :goto_5
    invoke-virtual {p0, p1}, Landroid/view/Window;->setSoftInputMode(I)V

    .line 126
    .line 127
    .line 128
    :cond_a
    return-void
.end method

.method public final cancel()V
    .locals 0

    .line 1
    return-void
.end method

.method public final onTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/app/Dialog;->onTouchEvent(Landroid/view/MotionEvent;)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lh2/w5;->g:Lay0/a;

    .line 8
    .line 9
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    :cond_0
    return p1
.end method
