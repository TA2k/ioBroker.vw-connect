.class public final Lx4/r;
.super Lb/t;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public g:Lay0/a;

.field public h:Lx4/p;

.field public final i:Landroid/view/View;

.field public final j:Lx4/o;

.field public k:Z


# direct methods
.method public constructor <init>(Lay0/a;Lx4/p;Landroid/view/View;Lt4/m;Lt4/c;Ljava/util/UUID;)V
    .locals 4

    .line 1
    new-instance v0, Landroid/view/ContextThemeWrapper;

    .line 2
    .line 3
    invoke-virtual {p3}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    iget-boolean v2, p2, Lx4/p;->e:Z

    .line 8
    .line 9
    if-eqz v2, :cond_0

    .line 10
    .line 11
    const v2, 0x7f13012f

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const v2, 0x7f130152

    .line 16
    .line 17
    .line 18
    :goto_0
    invoke-direct {v0, v1, v2}, Landroid/view/ContextThemeWrapper;-><init>(Landroid/content/Context;I)V

    .line 19
    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {p0, v0, v1}, Lb/t;-><init>(Landroid/content/Context;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lx4/r;->g:Lay0/a;

    .line 26
    .line 27
    iput-object p2, p0, Lx4/r;->h:Lx4/p;

    .line 28
    .line 29
    iput-object p3, p0, Lx4/r;->i:Landroid/view/View;

    .line 30
    .line 31
    const/16 p1, 0x8

    .line 32
    .line 33
    int-to-float p1, p1

    .line 34
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    if-eqz p2, :cond_5

    .line 39
    .line 40
    const/4 v0, 0x1

    .line 41
    invoke-virtual {p2, v0}, Landroid/view/Window;->requestFeature(I)Z

    .line 42
    .line 43
    .line 44
    const v0, 0x106000d

    .line 45
    .line 46
    .line 47
    invoke-virtual {p2, v0}, Landroid/view/Window;->setBackgroundDrawableResource(I)V

    .line 48
    .line 49
    .line 50
    iget-object v0, p0, Lx4/r;->h:Lx4/p;

    .line 51
    .line 52
    iget-boolean v0, v0, Lx4/p;->e:Z

    .line 53
    .line 54
    invoke-static {p2, v0}, Ljp/pf;->b(Landroid/view/Window;Z)V

    .line 55
    .line 56
    .line 57
    const/16 v0, 0x11

    .line 58
    .line 59
    invoke-virtual {p2, v0}, Landroid/view/Window;->setGravity(I)V

    .line 60
    .line 61
    .line 62
    iget-object v0, p0, Lx4/r;->h:Lx4/p;

    .line 63
    .line 64
    iget-boolean v0, v0, Lx4/p;->e:Z

    .line 65
    .line 66
    if-nez v0, :cond_2

    .line 67
    .line 68
    const v0, 0x10100

    .line 69
    .line 70
    .line 71
    invoke-virtual {p2, v0}, Landroid/view/Window;->addFlags(I)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p2}, Landroid/view/Window;->getAttributes()Landroid/view/WindowManager$LayoutParams;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 79
    .line 80
    sget-object v3, Lx4/j;->a:Lx4/j;

    .line 81
    .line 82
    invoke-virtual {v3, v0}, Lx4/j;->a(Landroid/view/WindowManager$LayoutParams;)V

    .line 83
    .line 84
    .line 85
    const/16 v3, 0x1e

    .line 86
    .line 87
    if-lt v2, v3, :cond_1

    .line 88
    .line 89
    sget-object v2, Lx4/k;->a:Lx4/k;

    .line 90
    .line 91
    invoke-virtual {v2, v0, v1}, Lx4/k;->a(Landroid/view/WindowManager$LayoutParams;I)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v2, v0, v1}, Lx4/k;->b(Landroid/view/WindowManager$LayoutParams;I)V

    .line 95
    .line 96
    .line 97
    :cond_1
    invoke-virtual {p2, v0}, Landroid/view/Window;->setAttributes(Landroid/view/WindowManager$LayoutParams;)V

    .line 98
    .line 99
    .line 100
    :cond_2
    new-instance v0, Lx4/o;

    .line 101
    .line 102
    invoke-virtual {p0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    invoke-direct {v0, v2, p2}, Lx4/o;-><init>(Landroid/content/Context;Landroid/view/Window;)V

    .line 107
    .line 108
    .line 109
    iget-object v2, p0, Lx4/r;->h:Lx4/p;

    .line 110
    .line 111
    iget-object v2, v2, Lx4/p;->f:Ljava/lang/String;

    .line 112
    .line 113
    invoke-virtual {p0, v2}, Landroid/app/Dialog;->setTitle(Ljava/lang/CharSequence;)V

    .line 114
    .line 115
    .line 116
    new-instance v2, Ljava/lang/StringBuilder;

    .line 117
    .line 118
    const-string v3, "Dialog:"

    .line 119
    .line 120
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v2, p6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p6

    .line 130
    const v2, 0x7f0a00e9

    .line 131
    .line 132
    .line 133
    invoke-virtual {v0, v2, p6}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->setClipChildren(Z)V

    .line 137
    .line 138
    .line 139
    invoke-interface {p5, p1}, Lt4/c;->w0(F)F

    .line 140
    .line 141
    .line 142
    move-result p1

    .line 143
    invoke-virtual {v0, p1}, Landroid/view/View;->setElevation(F)V

    .line 144
    .line 145
    .line 146
    new-instance p1, Lh2/t5;

    .line 147
    .line 148
    const/4 p5, 0x2

    .line 149
    invoke-direct {p1, p5}, Lh2/t5;-><init>(I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v0, p1}, Landroid/view/View;->setOutlineProvider(Landroid/view/ViewOutlineProvider;)V

    .line 153
    .line 154
    .line 155
    iput-object v0, p0, Lx4/r;->j:Lx4/o;

    .line 156
    .line 157
    invoke-virtual {p2}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    instance-of p2, p1, Landroid/view/ViewGroup;

    .line 162
    .line 163
    if-eqz p2, :cond_3

    .line 164
    .line 165
    check-cast p1, Landroid/view/ViewGroup;

    .line 166
    .line 167
    goto :goto_1

    .line 168
    :cond_3
    const/4 p1, 0x0

    .line 169
    :goto_1
    if-eqz p1, :cond_4

    .line 170
    .line 171
    invoke-static {p1}, Lx4/r;->c(Landroid/view/ViewGroup;)V

    .line 172
    .line 173
    .line 174
    :cond_4
    invoke-virtual {p0, v0}, Lb/t;->setContentView(Landroid/view/View;)V

    .line 175
    .line 176
    .line 177
    invoke-static {p3}, Landroidx/lifecycle/v0;->d(Landroid/view/View;)Landroidx/lifecycle/x;

    .line 178
    .line 179
    .line 180
    move-result-object p1

    .line 181
    invoke-static {v0, p1}, Landroidx/lifecycle/v0;->l(Landroid/view/View;Landroidx/lifecycle/x;)V

    .line 182
    .line 183
    .line 184
    invoke-static {p3}, Landroidx/lifecycle/v0;->e(Landroid/view/View;)Landroidx/lifecycle/i1;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    invoke-static {v0, p1}, Landroidx/lifecycle/v0;->m(Landroid/view/View;Landroidx/lifecycle/i1;)V

    .line 189
    .line 190
    .line 191
    invoke-static {p3}, Lkp/w;->b(Landroid/view/View;)Lra/f;

    .line 192
    .line 193
    .line 194
    move-result-object p1

    .line 195
    invoke-static {v0, p1}, Lkp/w;->d(Landroid/view/View;Lra/f;)V

    .line 196
    .line 197
    .line 198
    iget-object p1, p0, Lx4/r;->g:Lay0/a;

    .line 199
    .line 200
    iget-object p2, p0, Lx4/r;->h:Lx4/p;

    .line 201
    .line 202
    invoke-virtual {p0, p1, p2, p4}, Lx4/r;->d(Lay0/a;Lx4/p;Lt4/m;)V

    .line 203
    .line 204
    .line 205
    iget-object p1, p0, Lb/t;->f:Lb/h0;

    .line 206
    .line 207
    new-instance p2, Lx4/b;

    .line 208
    .line 209
    const/4 p3, 0x1

    .line 210
    invoke-direct {p2, p0, p3}, Lx4/b;-><init>(Lx4/r;I)V

    .line 211
    .line 212
    .line 213
    invoke-static {p1, p0, p2}, Ljp/t1;->e(Lb/h0;Lb/t;Lay0/k;)V

    .line 214
    .line 215
    .line 216
    return-void

    .line 217
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 218
    .line 219
    const-string p1, "Dialog has no window"

    .line 220
    .line 221
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    throw p0
.end method

.method public static final c(Landroid/view/ViewGroup;)V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->setClipChildren(Z)V

    .line 3
    .line 4
    .line 5
    instance-of v1, p0, Lx4/o;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    goto :goto_2

    .line 10
    :cond_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    :goto_0
    if-ge v0, v1, :cond_3

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    instance-of v3, v2, Landroid/view/ViewGroup;

    .line 21
    .line 22
    if-eqz v3, :cond_1

    .line 23
    .line 24
    check-cast v2, Landroid/view/ViewGroup;

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const/4 v2, 0x0

    .line 28
    :goto_1
    if-eqz v2, :cond_2

    .line 29
    .line 30
    invoke-static {v2}, Lx4/r;->c(Landroid/view/ViewGroup;)V

    .line 31
    .line 32
    .line 33
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_3
    :goto_2
    return-void
.end method


# virtual methods
.method public final cancel()V
    .locals 0

    .line 1
    return-void
.end method

.method public final d(Lay0/a;Lx4/p;Lt4/m;)V
    .locals 6

    .line 1
    iput-object p1, p0, Lx4/r;->g:Lay0/a;

    .line 2
    .line 3
    iput-object p2, p0, Lx4/r;->h:Lx4/p;

    .line 4
    .line 5
    iget-object p1, p2, Lx4/p;->c:Lx4/x;

    .line 6
    .line 7
    iget-object v0, p0, Lx4/r;->i:Landroid/view/View;

    .line 8
    .line 9
    invoke-static {v0}, Lx4/i;->c(Landroid/view/View;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    const/4 v1, 0x0

    .line 18
    const/4 v2, 0x1

    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    if-eq p1, v2, :cond_1

    .line 22
    .line 23
    const/4 v0, 0x2

    .line 24
    if-ne p1, v0, :cond_0

    .line 25
    .line 26
    move v0, v1

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance p0, La8/r0;

    .line 29
    .line 30
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    move v0, v2

    .line 35
    :cond_2
    :goto_0
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    const/16 v3, 0x2000

    .line 43
    .line 44
    if-eqz v0, :cond_3

    .line 45
    .line 46
    move v0, v3

    .line 47
    goto :goto_1

    .line 48
    :cond_3
    const/16 v0, -0x2001

    .line 49
    .line 50
    :goto_1
    invoke-virtual {p1, v0, v3}, Landroid/view/Window;->setFlags(II)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p3}, Ljava/lang/Enum;->ordinal()I

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    if-eqz p1, :cond_5

    .line 58
    .line 59
    if-ne p1, v2, :cond_4

    .line 60
    .line 61
    move p1, v2

    .line 62
    goto :goto_2

    .line 63
    :cond_4
    new-instance p0, La8/r0;

    .line 64
    .line 65
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_5
    move p1, v1

    .line 70
    :goto_2
    iget-object p3, p0, Lx4/r;->j:Lx4/o;

    .line 71
    .line 72
    invoke-virtual {p3, p1}, Landroid/view/View;->setLayoutDirection(I)V

    .line 73
    .line 74
    .line 75
    iget-boolean p1, p2, Lx4/p;->e:Z

    .line 76
    .line 77
    iget-boolean v0, p2, Lx4/p;->d:Z

    .line 78
    .line 79
    iget-object v3, p3, Lx4/o;->l:Landroid/view/Window;

    .line 80
    .line 81
    iget-boolean v4, p3, Lx4/o;->p:Z

    .line 82
    .line 83
    if-eqz v4, :cond_7

    .line 84
    .line 85
    iget-boolean v4, p3, Lx4/o;->n:Z

    .line 86
    .line 87
    if-ne v0, v4, :cond_7

    .line 88
    .line 89
    iget-boolean v4, p3, Lx4/o;->o:Z

    .line 90
    .line 91
    if-eq p1, v4, :cond_6

    .line 92
    .line 93
    goto :goto_3

    .line 94
    :cond_6
    move v4, v1

    .line 95
    goto :goto_4

    .line 96
    :cond_7
    :goto_3
    move v4, v2

    .line 97
    :goto_4
    iput-boolean v0, p3, Lx4/o;->n:Z

    .line 98
    .line 99
    iput-boolean p1, p3, Lx4/o;->o:Z

    .line 100
    .line 101
    if-eqz v4, :cond_a

    .line 102
    .line 103
    invoke-virtual {v3}, Landroid/view/Window;->getAttributes()Landroid/view/WindowManager$LayoutParams;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    const/4 v5, -0x2

    .line 108
    if-eqz v0, :cond_8

    .line 109
    .line 110
    move v0, v5

    .line 111
    goto :goto_5

    .line 112
    :cond_8
    const/4 v0, -0x1

    .line 113
    :goto_5
    iget v4, v4, Landroid/view/WindowManager$LayoutParams;->width:I

    .line 114
    .line 115
    if-ne v0, v4, :cond_9

    .line 116
    .line 117
    iget-boolean v4, p3, Lx4/o;->p:Z

    .line 118
    .line 119
    if-nez v4, :cond_a

    .line 120
    .line 121
    :cond_9
    invoke-virtual {v3, v0, v5}, Landroid/view/Window;->setLayout(II)V

    .line 122
    .line 123
    .line 124
    iput-boolean v2, p3, Lx4/o;->p:Z

    .line 125
    .line 126
    :cond_a
    iget-boolean p2, p2, Lx4/p;->b:Z

    .line 127
    .line 128
    invoke-virtual {p0, p2}, Landroid/app/Dialog;->setCanceledOnTouchOutside(Z)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    if-eqz p0, :cond_d

    .line 136
    .line 137
    if-eqz p1, :cond_b

    .line 138
    .line 139
    goto :goto_6

    .line 140
    :cond_b
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 141
    .line 142
    const/16 p2, 0x1f

    .line 143
    .line 144
    if-ge p1, p2, :cond_c

    .line 145
    .line 146
    const/16 v1, 0x10

    .line 147
    .line 148
    goto :goto_6

    .line 149
    :cond_c
    const/16 v1, 0x30

    .line 150
    .line 151
    :goto_6
    invoke-virtual {p0, v1}, Landroid/view/Window;->setSoftInputMode(I)V

    .line 152
    .line 153
    .line 154
    :cond_d
    return-void
.end method

.method public final onKeyUp(ILandroid/view/KeyEvent;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lx4/r;->h:Lx4/p;

    .line 2
    .line 3
    iget-boolean v0, v0, Lx4/p;->a:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p2}, Landroid/view/KeyEvent;->isTracking()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p2}, Landroid/view/KeyEvent;->isCanceled()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    const/16 v0, 0x6f

    .line 20
    .line 21
    if-ne p1, v0, :cond_0

    .line 22
    .line 23
    iget-object p0, p0, Lx4/r;->g:Lay0/a;

    .line 24
    .line 25
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x1

    .line 29
    return p0

    .line 30
    :cond_0
    invoke-super {p0, p1, p2}, Landroid/app/Dialog;->onKeyUp(ILandroid/view/KeyEvent;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    return p0
.end method

.method public final onTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 9

    .line 1
    invoke-super {p0, p1}, Landroid/app/Dialog;->onTouchEvent(Landroid/view/MotionEvent;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Lx4/r;->h:Lx4/p;

    .line 6
    .line 7
    iget-boolean v1, v1, Lx4/p;->b:Z

    .line 8
    .line 9
    const/4 v2, 0x3

    .line 10
    const/4 v3, 0x0

    .line 11
    const/4 v4, 0x1

    .line 12
    if-eqz v1, :cond_5

    .line 13
    .line 14
    iget-object v1, p0, Lx4/r;->j:Lx4/o;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getX()F

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    invoke-static {v5}, Ljava/lang/Float;->isInfinite(F)Z

    .line 24
    .line 25
    .line 26
    move-result v6

    .line 27
    if-nez v6, :cond_1

    .line 28
    .line 29
    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    if-nez v5, :cond_1

    .line 34
    .line 35
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getY()F

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    invoke-static {v5}, Ljava/lang/Float;->isInfinite(F)Z

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    if-nez v6, :cond_1

    .line 44
    .line 45
    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    if-nez v5, :cond_1

    .line 50
    .line 51
    invoke-virtual {v1, v3}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 52
    .line 53
    .line 54
    move-result-object v5

    .line 55
    if-nez v5, :cond_0

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_0
    invoke-virtual {v1}, Landroid/view/View;->getLeft()I

    .line 59
    .line 60
    .line 61
    move-result v6

    .line 62
    invoke-virtual {v5}, Landroid/view/View;->getLeft()I

    .line 63
    .line 64
    .line 65
    move-result v7

    .line 66
    add-int/2addr v7, v6

    .line 67
    invoke-virtual {v5}, Landroid/view/View;->getWidth()I

    .line 68
    .line 69
    .line 70
    move-result v6

    .line 71
    add-int/2addr v6, v7

    .line 72
    invoke-virtual {v1}, Landroid/view/View;->getTop()I

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    invoke-virtual {v5}, Landroid/view/View;->getTop()I

    .line 77
    .line 78
    .line 79
    move-result v8

    .line 80
    add-int/2addr v8, v1

    .line 81
    invoke-virtual {v5}, Landroid/view/View;->getHeight()I

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    add-int/2addr v1, v8

    .line 86
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getX()F

    .line 87
    .line 88
    .line 89
    move-result v5

    .line 90
    invoke-static {v5}, Lcy0/a;->i(F)I

    .line 91
    .line 92
    .line 93
    move-result v5

    .line 94
    if-gt v7, v5, :cond_1

    .line 95
    .line 96
    if-gt v5, v6, :cond_1

    .line 97
    .line 98
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getY()F

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    invoke-static {v5}, Lcy0/a;->i(F)I

    .line 103
    .line 104
    .line 105
    move-result v5

    .line 106
    if-gt v8, v5, :cond_1

    .line 107
    .line 108
    if-gt v5, v1, :cond_1

    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_1
    :goto_0
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 112
    .line 113
    .line 114
    move-result p1

    .line 115
    if-eqz p1, :cond_4

    .line 116
    .line 117
    if-eq p1, v4, :cond_3

    .line 118
    .line 119
    if-eq p1, v2, :cond_2

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_2
    iput-boolean v3, p0, Lx4/r;->k:Z

    .line 123
    .line 124
    return v0

    .line 125
    :cond_3
    iget-boolean p1, p0, Lx4/r;->k:Z

    .line 126
    .line 127
    if-eqz p1, :cond_6

    .line 128
    .line 129
    iget-object p1, p0, Lx4/r;->g:Lay0/a;

    .line 130
    .line 131
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    iput-boolean v3, p0, Lx4/r;->k:Z

    .line 135
    .line 136
    return v4

    .line 137
    :cond_4
    iput-boolean v4, p0, Lx4/r;->k:Z

    .line 138
    .line 139
    return v4

    .line 140
    :cond_5
    :goto_1
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 141
    .line 142
    .line 143
    move-result p1

    .line 144
    if-eqz p1, :cond_7

    .line 145
    .line 146
    if-eq p1, v4, :cond_7

    .line 147
    .line 148
    if-eq p1, v2, :cond_7

    .line 149
    .line 150
    :cond_6
    :goto_2
    return v0

    .line 151
    :cond_7
    iput-boolean v3, p0, Lx4/r;->k:Z

    .line 152
    .line 153
    return v0
.end method
