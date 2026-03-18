.class public final Lx4/t;
.super Lw3/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:Lb/d0;

.field public final B:Ll2/j1;

.field public C:Z

.field public final D:[I

.field public l:Lay0/a;

.field public m:Lx4/w;

.field public n:Ljava/lang/String;

.field public final o:Landroid/view/View;

.field public final p:Lx4/u;

.field public final q:Landroid/view/WindowManager;

.field public final r:Landroid/view/WindowManager$LayoutParams;

.field public s:Lx4/v;

.field public t:Lt4/m;

.field public final u:Ll2/j1;

.field public final v:Ll2/j1;

.field public w:Lt4/k;

.field public final x:Ll2/h0;

.field public final y:Landroid/graphics/Rect;

.field public final z:Lv2/r;


# direct methods
.method public constructor <init>(Lay0/a;Lx4/w;Ljava/lang/String;Landroid/view/View;Lt4/c;Lx4/v;Ljava/util/UUID;)V
    .locals 2

    .line 1
    new-instance v0, Lx4/u;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p4}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-direct {p0, v1}, Lw3/a;-><init>(Landroid/content/Context;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lx4/t;->l:Lay0/a;

    .line 14
    .line 15
    iput-object p2, p0, Lx4/t;->m:Lx4/w;

    .line 16
    .line 17
    iput-object p3, p0, Lx4/t;->n:Ljava/lang/String;

    .line 18
    .line 19
    iput-object p4, p0, Lx4/t;->o:Landroid/view/View;

    .line 20
    .line 21
    iput-object v0, p0, Lx4/t;->p:Lx4/u;

    .line 22
    .line 23
    invoke-virtual {p4}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    const-string p2, "window"

    .line 28
    .line 29
    invoke-virtual {p1, p2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    const-string p2, "null cannot be cast to non-null type android.view.WindowManager"

    .line 34
    .line 35
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    check-cast p1, Landroid/view/WindowManager;

    .line 39
    .line 40
    iput-object p1, p0, Lx4/t;->q:Landroid/view/WindowManager;

    .line 41
    .line 42
    new-instance p1, Landroid/view/WindowManager$LayoutParams;

    .line 43
    .line 44
    invoke-direct {p1}, Landroid/view/WindowManager$LayoutParams;-><init>()V

    .line 45
    .line 46
    .line 47
    const p2, 0x800033

    .line 48
    .line 49
    .line 50
    iput p2, p1, Landroid/view/WindowManager$LayoutParams;->gravity:I

    .line 51
    .line 52
    iget-object p2, p0, Lx4/t;->m:Lx4/w;

    .line 53
    .line 54
    invoke-static {p4}, Lx4/i;->c(Landroid/view/View;)Z

    .line 55
    .line 56
    .line 57
    move-result p3

    .line 58
    iget-boolean v0, p2, Lx4/w;->b:Z

    .line 59
    .line 60
    iget p2, p2, Lx4/w;->a:I

    .line 61
    .line 62
    if-eqz v0, :cond_0

    .line 63
    .line 64
    if-eqz p3, :cond_0

    .line 65
    .line 66
    or-int/lit16 p2, p2, 0x2000

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_0
    if-eqz v0, :cond_1

    .line 70
    .line 71
    if-nez p3, :cond_1

    .line 72
    .line 73
    and-int/lit16 p2, p2, -0x2001

    .line 74
    .line 75
    :cond_1
    :goto_0
    iput p2, p1, Landroid/view/WindowManager$LayoutParams;->flags:I

    .line 76
    .line 77
    const/16 p2, 0x3ea

    .line 78
    .line 79
    iput p2, p1, Landroid/view/WindowManager$LayoutParams;->type:I

    .line 80
    .line 81
    invoke-virtual {p4}, Landroid/view/View;->getApplicationWindowToken()Landroid/os/IBinder;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    iput-object p2, p1, Landroid/view/WindowManager$LayoutParams;->token:Landroid/os/IBinder;

    .line 86
    .line 87
    const/4 p2, -0x2

    .line 88
    iput p2, p1, Landroid/view/WindowManager$LayoutParams;->width:I

    .line 89
    .line 90
    iput p2, p1, Landroid/view/WindowManager$LayoutParams;->height:I

    .line 91
    .line 92
    const/4 p2, -0x3

    .line 93
    iput p2, p1, Landroid/view/WindowManager$LayoutParams;->format:I

    .line 94
    .line 95
    invoke-virtual {p4}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 96
    .line 97
    .line 98
    move-result-object p2

    .line 99
    invoke-virtual {p2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 100
    .line 101
    .line 102
    move-result-object p2

    .line 103
    const p3, 0x7f1201f1

    .line 104
    .line 105
    .line 106
    invoke-virtual {p2, p3}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p2

    .line 110
    invoke-virtual {p1, p2}, Landroid/view/WindowManager$LayoutParams;->setTitle(Ljava/lang/CharSequence;)V

    .line 111
    .line 112
    .line 113
    iput-object p1, p0, Lx4/t;->r:Landroid/view/WindowManager$LayoutParams;

    .line 114
    .line 115
    iput-object p6, p0, Lx4/t;->s:Lx4/v;

    .line 116
    .line 117
    sget-object p1, Lt4/m;->d:Lt4/m;

    .line 118
    .line 119
    iput-object p1, p0, Lx4/t;->t:Lt4/m;

    .line 120
    .line 121
    const/4 p1, 0x0

    .line 122
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 123
    .line 124
    .line 125
    move-result-object p2

    .line 126
    iput-object p2, p0, Lx4/t;->u:Ll2/j1;

    .line 127
    .line 128
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    iput-object p1, p0, Lx4/t;->v:Ll2/j1;

    .line 133
    .line 134
    new-instance p1, La7/j;

    .line 135
    .line 136
    const/16 p2, 0x1c

    .line 137
    .line 138
    invoke-direct {p1, p0, p2}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 139
    .line 140
    .line 141
    invoke-static {p1}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    iput-object p1, p0, Lx4/t;->x:Ll2/h0;

    .line 146
    .line 147
    const/16 p1, 0x8

    .line 148
    .line 149
    int-to-float p1, p1

    .line 150
    new-instance p2, Landroid/graphics/Rect;

    .line 151
    .line 152
    invoke-direct {p2}, Landroid/graphics/Rect;-><init>()V

    .line 153
    .line 154
    .line 155
    iput-object p2, p0, Lx4/t;->y:Landroid/graphics/Rect;

    .line 156
    .line 157
    new-instance p2, Lv2/r;

    .line 158
    .line 159
    new-instance p3, Lx4/h;

    .line 160
    .line 161
    const/4 p6, 0x2

    .line 162
    invoke-direct {p3, p0, p6}, Lx4/h;-><init>(Lx4/t;I)V

    .line 163
    .line 164
    .line 165
    invoke-direct {p2, p3}, Lv2/r;-><init>(Lay0/k;)V

    .line 166
    .line 167
    .line 168
    iput-object p2, p0, Lx4/t;->z:Lv2/r;

    .line 169
    .line 170
    const p2, 0x1020002

    .line 171
    .line 172
    .line 173
    invoke-virtual {p0, p2}, Landroid/view/View;->setId(I)V

    .line 174
    .line 175
    .line 176
    invoke-static {p4}, Landroidx/lifecycle/v0;->d(Landroid/view/View;)Landroidx/lifecycle/x;

    .line 177
    .line 178
    .line 179
    move-result-object p2

    .line 180
    invoke-static {p0, p2}, Landroidx/lifecycle/v0;->l(Landroid/view/View;Landroidx/lifecycle/x;)V

    .line 181
    .line 182
    .line 183
    invoke-static {p4}, Landroidx/lifecycle/v0;->e(Landroid/view/View;)Landroidx/lifecycle/i1;

    .line 184
    .line 185
    .line 186
    move-result-object p2

    .line 187
    invoke-static {p0, p2}, Landroidx/lifecycle/v0;->m(Landroid/view/View;Landroidx/lifecycle/i1;)V

    .line 188
    .line 189
    .line 190
    invoke-static {p4}, Lkp/w;->b(Landroid/view/View;)Lra/f;

    .line 191
    .line 192
    .line 193
    move-result-object p2

    .line 194
    invoke-static {p0, p2}, Lkp/w;->d(Landroid/view/View;Lra/f;)V

    .line 195
    .line 196
    .line 197
    new-instance p2, Ljava/lang/StringBuilder;

    .line 198
    .line 199
    const-string p3, "Popup:"

    .line 200
    .line 201
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {p2, p7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 205
    .line 206
    .line 207
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object p2

    .line 211
    const p3, 0x7f0a00e9

    .line 212
    .line 213
    .line 214
    invoke-virtual {p0, p3, p2}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    const/4 p2, 0x0

    .line 218
    invoke-virtual {p0, p2}, Landroid/view/ViewGroup;->setClipChildren(Z)V

    .line 219
    .line 220
    .line 221
    invoke-interface {p5, p1}, Lt4/c;->w0(F)F

    .line 222
    .line 223
    .line 224
    move-result p1

    .line 225
    invoke-virtual {p0, p1}, Landroid/view/View;->setElevation(F)V

    .line 226
    .line 227
    .line 228
    new-instance p1, Lh2/t5;

    .line 229
    .line 230
    const/4 p2, 0x3

    .line 231
    invoke-direct {p1, p2}, Lh2/t5;-><init>(I)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {p0, p1}, Landroid/view/View;->setOutlineProvider(Landroid/view/ViewOutlineProvider;)V

    .line 235
    .line 236
    .line 237
    sget-object p1, Lx4/n;->a:Lt2/b;

    .line 238
    .line 239
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 240
    .line 241
    .line 242
    move-result-object p1

    .line 243
    iput-object p1, p0, Lx4/t;->B:Ll2/j1;

    .line 244
    .line 245
    const/4 p1, 0x2

    .line 246
    new-array p1, p1, [I

    .line 247
    .line 248
    iput-object p1, p0, Lx4/t;->D:[I

    .line 249
    .line 250
    return-void
.end method

.method private final getContent()Lay0/n;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/n;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lx4/t;->B:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lay0/n;

    .line 8
    .line 9
    return-object p0
.end method

.method public static synthetic getParams$ui_release$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method private final getParentLayoutCoordinates()Lt3/y;
    .locals 0

    .line 1
    iget-object p0, p0, Lx4/t;->v:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lt3/y;

    .line 8
    .line 9
    return-object p0
.end method

.method private final getVisibleDisplayBounds()Lt4/k;
    .locals 4

    .line 1
    iget-object v0, p0, Lx4/t;->p:Lx4/u;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lx4/t;->o:Landroid/view/View;

    .line 7
    .line 8
    iget-object p0, p0, Lx4/t;->y:Landroid/graphics/Rect;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Landroid/view/View;->getWindowVisibleDisplayFrame(Landroid/graphics/Rect;)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lt4/k;

    .line 14
    .line 15
    iget v1, p0, Landroid/graphics/Rect;->left:I

    .line 16
    .line 17
    iget v2, p0, Landroid/graphics/Rect;->top:I

    .line 18
    .line 19
    iget v3, p0, Landroid/graphics/Rect;->right:I

    .line 20
    .line 21
    iget p0, p0, Landroid/graphics/Rect;->bottom:I

    .line 22
    .line 23
    invoke-direct {v0, v1, v2, v3, p0}, Lt4/k;-><init>(IIII)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method

.method public static final synthetic i(Lx4/t;)Lt3/y;
    .locals 0

    .line 1
    invoke-direct {p0}, Lx4/t;->getParentLayoutCoordinates()Lt3/y;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final setContent(Lay0/n;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/n;",
            ")V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lx4/t;->B:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private final setParentLayoutCoordinates(Lt3/y;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lx4/t;->v:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ll2/o;I)V
    .locals 5

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0x331e2520

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x2

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v1

    .line 19
    :goto_0
    or-int/2addr v0, p2

    .line 20
    and-int/lit8 v2, v0, 0x3

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    const/4 v4, 0x1

    .line 24
    if-eq v2, v1, :cond_1

    .line 25
    .line 26
    move v1, v4

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move v1, v3

    .line 29
    :goto_1
    and-int/2addr v0, v4

    .line 30
    invoke-virtual {p1, v0, v1}, Ll2/t;->O(IZ)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    invoke-direct {p0}, Lx4/t;->getContent()Lay0/n;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-interface {v0, p1, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 49
    .line 50
    .line 51
    :goto_2
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    if-eqz p1, :cond_3

    .line 56
    .line 57
    new-instance v0, Lb1/g;

    .line 58
    .line 59
    const/16 v1, 0x9

    .line 60
    .line 61
    invoke-direct {v0, p0, p2, v1}, Lb1/g;-><init>(Lw3/a;II)V

    .line 62
    .line 63
    .line 64
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 65
    .line 66
    :cond_3
    return-void
.end method

.method public final dispatchKeyEvent(Landroid/view/KeyEvent;)Z
    .locals 3

    .line 1
    iget-object v0, p0, Lx4/t;->m:Lx4/w;

    .line 2
    .line 3
    iget-boolean v0, v0, Lx4/w;->c:Z

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-super {p0, p1}, Landroid/view/View;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v1, 0x4

    .line 17
    if-eq v0, v1, :cond_1

    .line 18
    .line 19
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    const/16 v1, 0x6f

    .line 24
    .line 25
    if-ne v0, v1, :cond_5

    .line 26
    .line 27
    :cond_1
    invoke-virtual {p0}, Landroid/view/View;->getKeyDispatcherState()Landroid/view/KeyEvent$DispatcherState;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    if-nez v0, :cond_2

    .line 32
    .line 33
    invoke-super {p0, p1}, Landroid/view/View;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    return p0

    .line 38
    :cond_2
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getAction()I

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    const/4 v2, 0x1

    .line 43
    if-nez v1, :cond_3

    .line 44
    .line 45
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getRepeatCount()I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_3

    .line 50
    .line 51
    invoke-virtual {v0, p1, p0}, Landroid/view/KeyEvent$DispatcherState;->startTracking(Landroid/view/KeyEvent;Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    return v2

    .line 55
    :cond_3
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getAction()I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-ne v1, v2, :cond_5

    .line 60
    .line 61
    invoke-virtual {v0, p1}, Landroid/view/KeyEvent$DispatcherState;->isTracking(Landroid/view/KeyEvent;)Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    if-eqz v0, :cond_5

    .line 66
    .line 67
    invoke-virtual {p1}, Landroid/view/KeyEvent;->isCanceled()Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-nez v0, :cond_5

    .line 72
    .line 73
    iget-object p0, p0, Lx4/t;->l:Lay0/a;

    .line 74
    .line 75
    if-eqz p0, :cond_4

    .line 76
    .line 77
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    :cond_4
    return v2

    .line 81
    :cond_5
    invoke-super {p0, p1}, Landroid/view/View;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    return p0
.end method

.method public final f(IIIIZ)V
    .locals 0

    .line 1
    invoke-super/range {p0 .. p5}, Lw3/a;->f(IIIIZ)V

    .line 2
    .line 3
    .line 4
    iget-object p1, p0, Lx4/t;->m:Lx4/w;

    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    if-nez p1, :cond_0

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getMeasuredWidth()I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    iget-object p3, p0, Lx4/t;->r:Landroid/view/WindowManager$LayoutParams;

    .line 22
    .line 23
    iput p2, p3, Landroid/view/WindowManager$LayoutParams;->width:I

    .line 24
    .line 25
    invoke-virtual {p1}, Landroid/view/View;->getMeasuredHeight()I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    iput p1, p3, Landroid/view/WindowManager$LayoutParams;->height:I

    .line 30
    .line 31
    iget-object p1, p0, Lx4/t;->p:Lx4/u;

    .line 32
    .line 33
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    iget-object p1, p0, Lx4/t;->q:Landroid/view/WindowManager;

    .line 37
    .line 38
    invoke-interface {p1, p0, p3}, Landroid/view/ViewManager;->updateViewLayout(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public final g(II)V
    .locals 1

    .line 1
    iget-object p1, p0, Lx4/t;->m:Lx4/w;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Lx4/t;->getVisibleDisplayBounds()Lt4/k;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p1}, Lt4/k;->d()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    const/high16 v0, -0x80000000

    .line 15
    .line 16
    invoke-static {p2, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 17
    .line 18
    .line 19
    move-result p2

    .line 20
    invoke-virtual {p1}, Lt4/k;->b()I

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    invoke-static {p1, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    invoke-super {p0, p2, p1}, Lw3/a;->g(II)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public final getCanCalculatePosition()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lx4/t;->x:Ll2/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final getParams$ui_release()Landroid/view/WindowManager$LayoutParams;
    .locals 0

    .line 1
    iget-object p0, p0, Lx4/t;->r:Landroid/view/WindowManager$LayoutParams;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParentLayoutDirection()Lt4/m;
    .locals 0

    .line 1
    iget-object p0, p0, Lx4/t;->t:Lt4/m;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPopupContentSize-bOM6tXw()Lt4/l;
    .locals 0

    .line 1
    iget-object p0, p0, Lx4/t;->u:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lt4/l;

    .line 8
    .line 9
    return-object p0
.end method

.method public final getPositionProvider()Lx4/v;
    .locals 0

    .line 1
    iget-object p0, p0, Lx4/t;->s:Lx4/v;

    .line 2
    .line 3
    return-object p0
.end method

.method public getShouldCreateCompositionOnAttachedToWindow()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lx4/t;->C:Z

    .line 2
    .line 3
    return p0
.end method

.method public getSubCompositionView()Lw3/a;
    .locals 0

    .line 1
    return-object p0
.end method

.method public final getTestTag()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lx4/t;->n:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public bridge synthetic getViewRoot()Landroid/view/View;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final j(Ll2/x;Lay0/n;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lw3/a;->setParentCompositionContext(Ll2/x;)V

    .line 2
    .line 3
    .line 4
    invoke-direct {p0, p2}, Lx4/t;->setContent(Lay0/n;)V

    .line 5
    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    iput-boolean p1, p0, Lx4/t;->C:Z

    .line 9
    .line 10
    return-void
.end method

.method public final k(Lay0/a;Lx4/w;Ljava/lang/String;Lt4/m;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx4/t;->l:Lay0/a;

    .line 2
    .line 3
    iput-object p3, p0, Lx4/t;->n:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p1, p0, Lx4/t;->m:Lx4/w;

    .line 6
    .line 7
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    goto :goto_1

    .line 14
    :cond_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    iput-object p2, p0, Lx4/t;->m:Lx4/w;

    .line 18
    .line 19
    iget-object p1, p0, Lx4/t;->o:Landroid/view/View;

    .line 20
    .line 21
    invoke-static {p1}, Lx4/i;->c(Landroid/view/View;)Z

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    iget-boolean p3, p2, Lx4/w;->b:Z

    .line 26
    .line 27
    iget p2, p2, Lx4/w;->a:I

    .line 28
    .line 29
    if-eqz p3, :cond_1

    .line 30
    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    or-int/lit16 p2, p2, 0x2000

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    if-eqz p3, :cond_2

    .line 37
    .line 38
    if-nez p1, :cond_2

    .line 39
    .line 40
    and-int/lit16 p2, p2, -0x2001

    .line 41
    .line 42
    :cond_2
    :goto_0
    iget-object p1, p0, Lx4/t;->r:Landroid/view/WindowManager$LayoutParams;

    .line 43
    .line 44
    iput p2, p1, Landroid/view/WindowManager$LayoutParams;->flags:I

    .line 45
    .line 46
    iget-object p2, p0, Lx4/t;->p:Lx4/u;

    .line 47
    .line 48
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 49
    .line 50
    .line 51
    iget-object p2, p0, Lx4/t;->q:Landroid/view/WindowManager;

    .line 52
    .line 53
    invoke-interface {p2, p0, p1}, Landroid/view/ViewManager;->updateViewLayout(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 54
    .line 55
    .line 56
    :goto_1
    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    if-eqz p1, :cond_4

    .line 61
    .line 62
    const/4 p2, 0x1

    .line 63
    if-ne p1, p2, :cond_3

    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_3
    new-instance p0, La8/r0;

    .line 67
    .line 68
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 69
    .line 70
    .line 71
    throw p0

    .line 72
    :cond_4
    const/4 p2, 0x0

    .line 73
    :goto_2
    invoke-super {p0, p2}, Landroid/view/View;->setLayoutDirection(I)V

    .line 74
    .line 75
    .line 76
    return-void
.end method

.method public final l()V
    .locals 10

    .line 1
    invoke-direct {p0}, Lx4/t;->getParentLayoutCoordinates()Lt3/y;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    invoke-interface {v0}, Lt3/y;->g()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 v0, 0x0

    .line 15
    :goto_0
    if-nez v0, :cond_1

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_1
    invoke-interface {v0}, Lt3/y;->h()J

    .line 19
    .line 20
    .line 21
    move-result-wide v1

    .line 22
    const-wide/16 v3, 0x0

    .line 23
    .line 24
    invoke-interface {v0, v3, v4}, Lt3/y;->B(J)J

    .line 25
    .line 26
    .line 27
    move-result-wide v3

    .line 28
    const/16 v0, 0x20

    .line 29
    .line 30
    shr-long v5, v3, v0

    .line 31
    .line 32
    long-to-int v5, v5

    .line 33
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    .line 38
    .line 39
    .line 40
    move-result v5

    .line 41
    const-wide v6, 0xffffffffL

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    and-long/2addr v3, v6

    .line 47
    long-to-int v3, v3

    .line 48
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 49
    .line 50
    .line 51
    move-result v3

    .line 52
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    int-to-long v4, v5

    .line 57
    shl-long/2addr v4, v0

    .line 58
    int-to-long v8, v3

    .line 59
    and-long/2addr v6, v8

    .line 60
    or-long v3, v4, v6

    .line 61
    .line 62
    invoke-static {v3, v4, v1, v2}, Lkp/e9;->a(JJ)Lt4/k;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    iget-object v1, p0, Lx4/t;->w:Lt4/k;

    .line 67
    .line 68
    invoke-virtual {v0, v1}, Lt4/k;->equals(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_2

    .line 73
    .line 74
    iput-object v0, p0, Lx4/t;->w:Lt4/k;

    .line 75
    .line 76
    invoke-virtual {p0}, Lx4/t;->n()V

    .line 77
    .line 78
    .line 79
    :cond_2
    :goto_1
    return-void
.end method

.method public final m(Lt3/y;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lx4/t;->setParentLayoutCoordinates(Lt3/y;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lx4/t;->l()V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final n()V
    .locals 13

    .line 1
    iget-object v3, p0, Lx4/t;->w:Lt4/k;

    .line 2
    .line 3
    if-nez v3, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    invoke-virtual {p0}, Lx4/t;->getPopupContentSize-bOM6tXw()Lt4/l;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-eqz v0, :cond_2

    .line 11
    .line 12
    iget-wide v6, v0, Lt4/l;->a:J

    .line 13
    .line 14
    invoke-direct {p0}, Lx4/t;->getVisibleDisplayBounds()Lt4/k;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {v0}, Lt4/k;->d()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    invoke-virtual {v0}, Lt4/k;->b()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    int-to-long v1, v1

    .line 27
    const/16 v8, 0x20

    .line 28
    .line 29
    shl-long/2addr v1, v8

    .line 30
    int-to-long v4, v0

    .line 31
    const-wide v9, 0xffffffffL

    .line 32
    .line 33
    .line 34
    .line 35
    .line 36
    and-long/2addr v4, v9

    .line 37
    or-long/2addr v4, v1

    .line 38
    new-instance v1, Lkotlin/jvm/internal/e0;

    .line 39
    .line 40
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 41
    .line 42
    .line 43
    const-wide/16 v11, 0x0

    .line 44
    .line 45
    iput-wide v11, v1, Lkotlin/jvm/internal/e0;->d:J

    .line 46
    .line 47
    sget-object v11, Lx4/c;->l:Lx4/c;

    .line 48
    .line 49
    new-instance v0, Lx4/s;

    .line 50
    .line 51
    move-object v2, p0

    .line 52
    invoke-direct/range {v0 .. v7}, Lx4/s;-><init>(Lkotlin/jvm/internal/e0;Lx4/t;Lt4/k;JJ)V

    .line 53
    .line 54
    .line 55
    iget-object p0, v2, Lx4/t;->z:Lv2/r;

    .line 56
    .line 57
    invoke-virtual {p0, v2, v11, v0}, Lv2/r;->d(Ljava/lang/Object;Lay0/k;Lay0/a;)V

    .line 58
    .line 59
    .line 60
    iget-wide v0, v1, Lkotlin/jvm/internal/e0;->d:J

    .line 61
    .line 62
    shr-long v6, v0, v8

    .line 63
    .line 64
    long-to-int p0, v6

    .line 65
    iget-object v3, v2, Lx4/t;->r:Landroid/view/WindowManager$LayoutParams;

    .line 66
    .line 67
    iput p0, v3, Landroid/view/WindowManager$LayoutParams;->x:I

    .line 68
    .line 69
    and-long/2addr v0, v9

    .line 70
    long-to-int p0, v0

    .line 71
    iput p0, v3, Landroid/view/WindowManager$LayoutParams;->y:I

    .line 72
    .line 73
    iget-object p0, v2, Lx4/t;->m:Lx4/w;

    .line 74
    .line 75
    iget-boolean p0, p0, Lx4/w;->e:Z

    .line 76
    .line 77
    iget-object v0, v2, Lx4/t;->p:Lx4/u;

    .line 78
    .line 79
    if-eqz p0, :cond_1

    .line 80
    .line 81
    shr-long v6, v4, v8

    .line 82
    .line 83
    long-to-int p0, v6

    .line 84
    and-long/2addr v4, v9

    .line 85
    long-to-int v1, v4

    .line 86
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    new-instance v4, Landroid/graphics/Rect;

    .line 90
    .line 91
    const/4 v5, 0x0

    .line 92
    invoke-direct {v4, v5, v5, p0, v1}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 93
    .line 94
    .line 95
    filled-new-array {v4}, [Landroid/graphics/Rect;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    invoke-static {p0}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    invoke-virtual {v2, p0}, Landroid/view/View;->setSystemGestureExclusionRects(Ljava/util/List;)V

    .line 104
    .line 105
    .line 106
    :cond_1
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    iget-object p0, v2, Lx4/t;->q:Landroid/view/WindowManager;

    .line 110
    .line 111
    invoke-interface {p0, v2, v3}, Landroid/view/ViewManager;->updateViewLayout(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 112
    .line 113
    .line 114
    :cond_2
    :goto_0
    return-void
.end method

.method public final onAttachedToWindow()V
    .locals 3

    .line 1
    invoke-super {p0}, Lw3/a;->onAttachedToWindow()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lx4/t;->z:Lv2/r;

    .line 5
    .line 6
    invoke-virtual {v0}, Lv2/r;->e()V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lx4/t;->m:Lx4/w;

    .line 10
    .line 11
    iget-boolean v0, v0, Lx4/w;->c:Z

    .line 12
    .line 13
    if-eqz v0, :cond_2

    .line 14
    .line 15
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 16
    .line 17
    const/16 v1, 0x21

    .line 18
    .line 19
    if-ge v0, v1, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    iget-object v0, p0, Lx4/t;->A:Lb/d0;

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    iget-object v0, p0, Lx4/t;->l:Lay0/a;

    .line 27
    .line 28
    new-instance v1, Lb/d0;

    .line 29
    .line 30
    const/4 v2, 0x3

    .line 31
    invoke-direct {v1, v0, v2}, Lb/d0;-><init>(Ljava/lang/Object;I)V

    .line 32
    .line 33
    .line 34
    iput-object v1, p0, Lx4/t;->A:Lb/d0;

    .line 35
    .line 36
    :cond_1
    iget-object v0, p0, Lx4/t;->A:Lb/d0;

    .line 37
    .line 38
    invoke-static {p0, v0}, Lb/k;->g(Lx4/t;Lb/d0;)V

    .line 39
    .line 40
    .line 41
    :cond_2
    :goto_0
    return-void
.end method

.method public final onDetachedFromWindow()V
    .locals 2

    .line 1
    invoke-super {p0}, Landroid/view/View;->onDetachedFromWindow()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lx4/t;->z:Lv2/r;

    .line 5
    .line 6
    iget-object v1, v0, Lv2/r;->h:Lrx/b;

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    invoke-virtual {v1}, Lrx/b;->d()V

    .line 11
    .line 12
    .line 13
    :cond_0
    invoke-virtual {v0}, Lv2/r;->a()V

    .line 14
    .line 15
    .line 16
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 17
    .line 18
    const/16 v1, 0x21

    .line 19
    .line 20
    if-lt v0, v1, :cond_1

    .line 21
    .line 22
    iget-object v0, p0, Lx4/t;->A:Lb/d0;

    .line 23
    .line 24
    invoke-static {p0, v0}, Lb/k;->h(Lx4/t;Lb/d0;)V

    .line 25
    .line 26
    .line 27
    :cond_1
    const/4 v0, 0x0

    .line 28
    iput-object v0, p0, Lx4/t;->A:Lb/d0;

    .line 29
    .line 30
    return-void
.end method

.method public final onTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 4

    .line 1
    iget-object v0, p0, Lx4/t;->m:Lx4/w;

    .line 2
    .line 3
    iget-boolean v0, v0, Lx4/w;->d:Z

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-super {p0, p1}, Landroid/view/View;->onTouchEvent(Landroid/view/MotionEvent;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 v0, 0x1

    .line 13
    if-eqz p1, :cond_3

    .line 14
    .line 15
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getAction()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-nez v1, :cond_3

    .line 20
    .line 21
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getX()F

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const/4 v2, 0x0

    .line 26
    cmpg-float v1, v1, v2

    .line 27
    .line 28
    if-ltz v1, :cond_1

    .line 29
    .line 30
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getX()F

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    int-to-float v3, v3

    .line 39
    cmpl-float v1, v1, v3

    .line 40
    .line 41
    if-gez v1, :cond_1

    .line 42
    .line 43
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getY()F

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    cmpg-float v1, v1, v2

    .line 48
    .line 49
    if-ltz v1, :cond_1

    .line 50
    .line 51
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getY()F

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    int-to-float v2, v2

    .line 60
    cmpl-float v1, v1, v2

    .line 61
    .line 62
    if-ltz v1, :cond_3

    .line 63
    .line 64
    :cond_1
    iget-object p0, p0, Lx4/t;->l:Lay0/a;

    .line 65
    .line 66
    if-eqz p0, :cond_2

    .line 67
    .line 68
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    :cond_2
    return v0

    .line 72
    :cond_3
    if-eqz p1, :cond_5

    .line 73
    .line 74
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getAction()I

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    const/4 v2, 0x4

    .line 79
    if-ne v1, v2, :cond_5

    .line 80
    .line 81
    iget-object p0, p0, Lx4/t;->l:Lay0/a;

    .line 82
    .line 83
    if-eqz p0, :cond_4

    .line 84
    .line 85
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    :cond_4
    return v0

    .line 89
    :cond_5
    invoke-super {p0, p1}, Landroid/view/View;->onTouchEvent(Landroid/view/MotionEvent;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    return p0
.end method

.method public setLayoutDirection(I)V
    .locals 0

    .line 1
    return-void
.end method

.method public final setParentLayoutDirection(Lt4/m;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx4/t;->t:Lt4/m;

    .line 2
    .line 3
    return-void
.end method

.method public final setPopupContentSize-fhxjrPA(Lt4/l;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lx4/t;->u:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final setPositionProvider(Lx4/v;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx4/t;->s:Lx4/v;

    .line 2
    .line 3
    return-void
.end method

.method public final setTestTag(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx4/t;->n:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method
