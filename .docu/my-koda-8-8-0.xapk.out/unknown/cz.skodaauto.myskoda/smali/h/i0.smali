.class public final Lh/i0;
.super Lkp/v9;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm/c;


# static fields
.field public static final y:Landroid/view/animation/AccelerateInterpolator;

.field public static final z:Landroid/view/animation/DecelerateInterpolator;


# instance fields
.field public a:Landroid/content/Context;

.field public b:Landroid/content/Context;

.field public c:Landroidx/appcompat/widget/ActionBarOverlayLayout;

.field public d:Landroidx/appcompat/widget/ActionBarContainer;

.field public e:Lm/f1;

.field public f:Landroidx/appcompat/widget/ActionBarContextView;

.field public final g:Landroid/view/View;

.field public h:Z

.field public i:Lh/h0;

.field public j:Lh/h0;

.field public k:Lb81/b;

.field public l:Z

.field public final m:Ljava/util/ArrayList;

.field public n:I

.field public o:Z

.field public p:Z

.field public q:Z

.field public r:Z

.field public s:Lk/j;

.field public t:Z

.field public u:Z

.field public final v:Lh/g0;

.field public final w:Lh/g0;

.field public final x:Lbu/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Landroid/view/animation/AccelerateInterpolator;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/view/animation/AccelerateInterpolator;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh/i0;->y:Landroid/view/animation/AccelerateInterpolator;

    .line 7
    .line 8
    new-instance v0, Landroid/view/animation/DecelerateInterpolator;

    .line 9
    .line 10
    invoke-direct {v0}, Landroid/view/animation/DecelerateInterpolator;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lh/i0;->z:Landroid/view/animation/DecelerateInterpolator;

    .line 14
    .line 15
    return-void
.end method

.method public constructor <init>(Landroid/app/Activity;Z)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 3
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lh/i0;->m:Ljava/util/ArrayList;

    const/4 v0, 0x0

    .line 4
    iput v0, p0, Lh/i0;->n:I

    const/4 v0, 0x1

    .line 5
    iput-boolean v0, p0, Lh/i0;->o:Z

    .line 6
    iput-boolean v0, p0, Lh/i0;->r:Z

    .line 7
    new-instance v0, Lh/g0;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Lh/g0;-><init>(Lh/i0;I)V

    iput-object v0, p0, Lh/i0;->v:Lh/g0;

    .line 8
    new-instance v0, Lh/g0;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Lh/g0;-><init>(Lh/i0;I)V

    iput-object v0, p0, Lh/i0;->w:Lh/g0;

    .line 9
    new-instance v0, Lbu/c;

    const/16 v1, 0x1b

    invoke-direct {v0, p0, v1}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Lh/i0;->x:Lbu/c;

    .line 10
    invoke-virtual {p1}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    move-result-object p1

    .line 11
    invoke-virtual {p1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    .line 12
    invoke-virtual {p0, p1}, Lh/i0;->e(Landroid/view/View;)V

    if-nez p2, :cond_0

    const p2, 0x1020002

    .line 13
    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object p1

    iput-object p1, p0, Lh/i0;->g:Landroid/view/View;

    :cond_0
    return-void
.end method

.method public constructor <init>(Landroid/app/Dialog;)V
    .locals 2

    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 16
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lh/i0;->m:Ljava/util/ArrayList;

    const/4 v0, 0x0

    .line 17
    iput v0, p0, Lh/i0;->n:I

    const/4 v0, 0x1

    .line 18
    iput-boolean v0, p0, Lh/i0;->o:Z

    .line 19
    iput-boolean v0, p0, Lh/i0;->r:Z

    .line 20
    new-instance v0, Lh/g0;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Lh/g0;-><init>(Lh/i0;I)V

    iput-object v0, p0, Lh/i0;->v:Lh/g0;

    .line 21
    new-instance v0, Lh/g0;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Lh/g0;-><init>(Lh/i0;I)V

    iput-object v0, p0, Lh/i0;->w:Lh/g0;

    .line 22
    new-instance v0, Lbu/c;

    const/16 v1, 0x1b

    invoke-direct {v0, p0, v1}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Lh/i0;->x:Lbu/c;

    .line 23
    invoke-virtual {p1}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object p1

    invoke-virtual {p1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    invoke-virtual {p0, p1}, Lh/i0;->e(Landroid/view/View;)V

    return-void
.end method


# virtual methods
.method public final c(Z)V
    .locals 9

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_1

    .line 3
    .line 4
    iget-boolean v1, p0, Lh/i0;->q:Z

    .line 5
    .line 6
    if-nez v1, :cond_3

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    iput-boolean v1, p0, Lh/i0;->q:Z

    .line 10
    .line 11
    iget-object v2, p0, Lh/i0;->c:Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 12
    .line 13
    if-eqz v2, :cond_0

    .line 14
    .line 15
    invoke-virtual {v2, v1}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->setShowingForActionMode(Z)V

    .line 16
    .line 17
    .line 18
    :cond_0
    invoke-virtual {p0, v0}, Lh/i0;->h(Z)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    iget-boolean v1, p0, Lh/i0;->q:Z

    .line 23
    .line 24
    if-eqz v1, :cond_3

    .line 25
    .line 26
    iput-boolean v0, p0, Lh/i0;->q:Z

    .line 27
    .line 28
    iget-object v1, p0, Lh/i0;->c:Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 29
    .line 30
    if-eqz v1, :cond_2

    .line 31
    .line 32
    invoke-virtual {v1, v0}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->setShowingForActionMode(Z)V

    .line 33
    .line 34
    .line 35
    :cond_2
    invoke-virtual {p0, v0}, Lh/i0;->h(Z)V

    .line 36
    .line 37
    .line 38
    :cond_3
    :goto_0
    iget-object v1, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 39
    .line 40
    invoke-virtual {v1}, Landroid/view/View;->isLaidOut()Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    const/16 v2, 0x8

    .line 45
    .line 46
    const/4 v3, 0x4

    .line 47
    if-eqz v1, :cond_7

    .line 48
    .line 49
    const-wide/16 v4, 0xc8

    .line 50
    .line 51
    const-wide/16 v6, 0x64

    .line 52
    .line 53
    if-eqz p1, :cond_4

    .line 54
    .line 55
    iget-object p1, p0, Lh/i0;->e:Lm/f1;

    .line 56
    .line 57
    check-cast p1, Lm/w2;

    .line 58
    .line 59
    iget-object v1, p1, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 60
    .line 61
    invoke-static {v1}, Ld6/r0;->a(Landroid/view/View;)Ld6/w0;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    const/4 v2, 0x0

    .line 66
    invoke-virtual {v1, v2}, Ld6/w0;->a(F)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v1, v6, v7}, Ld6/w0;->c(J)V

    .line 70
    .line 71
    .line 72
    new-instance v2, Lk/i;

    .line 73
    .line 74
    invoke-direct {v2, p1, v3}, Lk/i;-><init>(Lm/w2;I)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v1, v2}, Ld6/w0;->d(Ld6/x0;)V

    .line 78
    .line 79
    .line 80
    iget-object p0, p0, Lh/i0;->f:Landroidx/appcompat/widget/ActionBarContextView;

    .line 81
    .line 82
    invoke-virtual {p0, v0, v4, v5}, Landroidx/appcompat/widget/ActionBarContextView;->i(IJ)Ld6/w0;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    goto :goto_1

    .line 87
    :cond_4
    iget-object p1, p0, Lh/i0;->e:Lm/f1;

    .line 88
    .line 89
    check-cast p1, Lm/w2;

    .line 90
    .line 91
    iget-object v1, p1, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 92
    .line 93
    invoke-static {v1}, Ld6/r0;->a(Landroid/view/View;)Ld6/w0;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    const/high16 v3, 0x3f800000    # 1.0f

    .line 98
    .line 99
    invoke-virtual {v1, v3}, Ld6/w0;->a(F)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v1, v4, v5}, Ld6/w0;->c(J)V

    .line 103
    .line 104
    .line 105
    new-instance v3, Lk/i;

    .line 106
    .line 107
    invoke-direct {v3, p1, v0}, Lk/i;-><init>(Lm/w2;I)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v1, v3}, Ld6/w0;->d(Ld6/x0;)V

    .line 111
    .line 112
    .line 113
    iget-object p0, p0, Lh/i0;->f:Landroidx/appcompat/widget/ActionBarContextView;

    .line 114
    .line 115
    invoke-virtual {p0, v2, v6, v7}, Landroidx/appcompat/widget/ActionBarContextView;->i(IJ)Ld6/w0;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    move-object v8, v1

    .line 120
    move-object v1, p0

    .line 121
    move-object p0, v8

    .line 122
    :goto_1
    new-instance p1, Lk/j;

    .line 123
    .line 124
    invoke-direct {p1}, Lk/j;-><init>()V

    .line 125
    .line 126
    .line 127
    iget-object v0, p1, Lk/j;->a:Ljava/util/ArrayList;

    .line 128
    .line 129
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    iget-object v1, v1, Ld6/w0;->a:Ljava/lang/ref/WeakReference;

    .line 133
    .line 134
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    check-cast v1, Landroid/view/View;

    .line 139
    .line 140
    if-eqz v1, :cond_5

    .line 141
    .line 142
    invoke-virtual {v1}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    invoke-virtual {v1}, Landroid/view/ViewPropertyAnimator;->getDuration()J

    .line 147
    .line 148
    .line 149
    move-result-wide v1

    .line 150
    goto :goto_2

    .line 151
    :cond_5
    const-wide/16 v1, 0x0

    .line 152
    .line 153
    :goto_2
    iget-object v3, p0, Ld6/w0;->a:Ljava/lang/ref/WeakReference;

    .line 154
    .line 155
    invoke-virtual {v3}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v3

    .line 159
    check-cast v3, Landroid/view/View;

    .line 160
    .line 161
    if-eqz v3, :cond_6

    .line 162
    .line 163
    invoke-virtual {v3}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    .line 164
    .line 165
    .line 166
    move-result-object v3

    .line 167
    invoke-virtual {v3, v1, v2}, Landroid/view/ViewPropertyAnimator;->setStartDelay(J)Landroid/view/ViewPropertyAnimator;

    .line 168
    .line 169
    .line 170
    :cond_6
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    invoke-virtual {p1}, Lk/j;->b()V

    .line 174
    .line 175
    .line 176
    return-void

    .line 177
    :cond_7
    if-eqz p1, :cond_8

    .line 178
    .line 179
    iget-object p1, p0, Lh/i0;->e:Lm/f1;

    .line 180
    .line 181
    check-cast p1, Lm/w2;

    .line 182
    .line 183
    iget-object p1, p1, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 184
    .line 185
    invoke-virtual {p1, v3}, Landroid/view/View;->setVisibility(I)V

    .line 186
    .line 187
    .line 188
    iget-object p0, p0, Lh/i0;->f:Landroidx/appcompat/widget/ActionBarContextView;

    .line 189
    .line 190
    invoke-virtual {p0, v0}, Landroidx/appcompat/widget/ActionBarContextView;->setVisibility(I)V

    .line 191
    .line 192
    .line 193
    return-void

    .line 194
    :cond_8
    iget-object p1, p0, Lh/i0;->e:Lm/f1;

    .line 195
    .line 196
    check-cast p1, Lm/w2;

    .line 197
    .line 198
    iget-object p1, p1, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 199
    .line 200
    invoke-virtual {p1, v0}, Landroid/view/View;->setVisibility(I)V

    .line 201
    .line 202
    .line 203
    iget-object p0, p0, Lh/i0;->f:Landroidx/appcompat/widget/ActionBarContextView;

    .line 204
    .line 205
    invoke-virtual {p0, v2}, Landroidx/appcompat/widget/ActionBarContextView;->setVisibility(I)V

    .line 206
    .line 207
    .line 208
    return-void
.end method

.method public final d()Landroid/content/Context;
    .locals 4

    .line 1
    iget-object v0, p0, Lh/i0;->b:Landroid/content/Context;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    new-instance v0, Landroid/util/TypedValue;

    .line 6
    .line 7
    invoke-direct {v0}, Landroid/util/TypedValue;-><init>()V

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, Lh/i0;->a:Landroid/content/Context;

    .line 11
    .line 12
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    const v2, 0x7f04000d

    .line 17
    .line 18
    .line 19
    const/4 v3, 0x1

    .line 20
    invoke-virtual {v1, v2, v0, v3}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 21
    .line 22
    .line 23
    iget v0, v0, Landroid/util/TypedValue;->resourceId:I

    .line 24
    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    new-instance v1, Landroid/view/ContextThemeWrapper;

    .line 28
    .line 29
    iget-object v2, p0, Lh/i0;->a:Landroid/content/Context;

    .line 30
    .line 31
    invoke-direct {v1, v2, v0}, Landroid/view/ContextThemeWrapper;-><init>(Landroid/content/Context;I)V

    .line 32
    .line 33
    .line 34
    iput-object v1, p0, Lh/i0;->b:Landroid/content/Context;

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    iget-object v0, p0, Lh/i0;->a:Landroid/content/Context;

    .line 38
    .line 39
    iput-object v0, p0, Lh/i0;->b:Landroid/content/Context;

    .line 40
    .line 41
    :cond_1
    :goto_0
    iget-object p0, p0, Lh/i0;->b:Landroid/content/Context;

    .line 42
    .line 43
    return-object p0
.end method

.method public final e(Landroid/view/View;)V
    .locals 6

    .line 1
    const v0, 0x7f0a00ff

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 9
    .line 10
    iput-object v0, p0, Lh/i0;->c:Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0, p0}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->setActionBarVisibilityCallback(Lm/c;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    const v0, 0x7f0a0033

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    instance-of v1, v0, Lm/f1;

    .line 25
    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    check-cast v0, Lm/f1;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    instance-of v1, v0, Landroidx/appcompat/widget/Toolbar;

    .line 32
    .line 33
    if-eqz v1, :cond_8

    .line 34
    .line 35
    check-cast v0, Landroidx/appcompat/widget/Toolbar;

    .line 36
    .line 37
    invoke-virtual {v0}, Landroidx/appcompat/widget/Toolbar;->getWrapper()Lm/f1;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    :goto_0
    iput-object v0, p0, Lh/i0;->e:Lm/f1;

    .line 42
    .line 43
    const v0, 0x7f0a003b

    .line 44
    .line 45
    .line 46
    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    check-cast v0, Landroidx/appcompat/widget/ActionBarContextView;

    .line 51
    .line 52
    iput-object v0, p0, Lh/i0;->f:Landroidx/appcompat/widget/ActionBarContextView;

    .line 53
    .line 54
    const v0, 0x7f0a0035

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    check-cast p1, Landroidx/appcompat/widget/ActionBarContainer;

    .line 62
    .line 63
    iput-object p1, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 64
    .line 65
    iget-object v0, p0, Lh/i0;->e:Lm/f1;

    .line 66
    .line 67
    if-eqz v0, :cond_7

    .line 68
    .line 69
    iget-object v1, p0, Lh/i0;->f:Landroidx/appcompat/widget/ActionBarContextView;

    .line 70
    .line 71
    if-eqz v1, :cond_7

    .line 72
    .line 73
    if-eqz p1, :cond_7

    .line 74
    .line 75
    check-cast v0, Lm/w2;

    .line 76
    .line 77
    iget-object p1, v0, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 78
    .line 79
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    iput-object p1, p0, Lh/i0;->a:Landroid/content/Context;

    .line 84
    .line 85
    iget-object v0, p0, Lh/i0;->e:Lm/f1;

    .line 86
    .line 87
    check-cast v0, Lm/w2;

    .line 88
    .line 89
    iget v0, v0, Lm/w2;->b:I

    .line 90
    .line 91
    and-int/lit8 v0, v0, 0x4

    .line 92
    .line 93
    const/4 v1, 0x1

    .line 94
    const/4 v2, 0x0

    .line 95
    if-eqz v0, :cond_2

    .line 96
    .line 97
    move v0, v1

    .line 98
    goto :goto_1

    .line 99
    :cond_2
    move v0, v2

    .line 100
    :goto_1
    if-eqz v0, :cond_3

    .line 101
    .line 102
    iput-boolean v1, p0, Lh/i0;->h:Z

    .line 103
    .line 104
    :cond_3
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    iget v3, v3, Landroid/content/pm/ApplicationInfo;->targetSdkVersion:I

    .line 109
    .line 110
    const/16 v4, 0xe

    .line 111
    .line 112
    iget-object v0, p0, Lh/i0;->e:Lm/f1;

    .line 113
    .line 114
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    const/high16 v0, 0x7f050000

    .line 122
    .line 123
    invoke-virtual {p1, v0}, Landroid/content/res/Resources;->getBoolean(I)Z

    .line 124
    .line 125
    .line 126
    move-result p1

    .line 127
    invoke-virtual {p0, p1}, Lh/i0;->g(Z)V

    .line 128
    .line 129
    .line 130
    iget-object p1, p0, Lh/i0;->a:Landroid/content/Context;

    .line 131
    .line 132
    sget-object v0, Lg/a;->a:[I

    .line 133
    .line 134
    const v3, 0x7f040008

    .line 135
    .line 136
    .line 137
    const/4 v5, 0x0

    .line 138
    invoke-virtual {p1, v5, v0, v3, v2}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-virtual {p1, v4, v2}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 143
    .line 144
    .line 145
    move-result v0

    .line 146
    if-eqz v0, :cond_5

    .line 147
    .line 148
    iget-object v0, p0, Lh/i0;->c:Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 149
    .line 150
    iget-boolean v3, v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;->j:Z

    .line 151
    .line 152
    if-eqz v3, :cond_4

    .line 153
    .line 154
    iput-boolean v1, p0, Lh/i0;->u:Z

    .line 155
    .line 156
    invoke-virtual {v0, v1}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->setHideOnContentScrollEnabled(Z)V

    .line 157
    .line 158
    .line 159
    goto :goto_2

    .line 160
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 161
    .line 162
    const-string p1, "Action bar must be in overlay mode (Window.FEATURE_OVERLAY_ACTION_BAR) to enable hide on content scroll"

    .line 163
    .line 164
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    throw p0

    .line 168
    :cond_5
    :goto_2
    const/16 v0, 0xc

    .line 169
    .line 170
    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    if-eqz v0, :cond_6

    .line 175
    .line 176
    int-to-float v0, v0

    .line 177
    iget-object p0, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 178
    .line 179
    sget-object v1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 180
    .line 181
    invoke-static {p0, v0}, Ld6/k0;->i(Landroid/view/View;F)V

    .line 182
    .line 183
    .line 184
    :cond_6
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    .line 185
    .line 186
    .line 187
    return-void

    .line 188
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 189
    .line 190
    const-class p1, Lh/i0;

    .line 191
    .line 192
    invoke-virtual {p1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object p1

    .line 196
    const-string v0, " can only be used with a compatible window decor layout"

    .line 197
    .line 198
    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object p1

    .line 202
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    throw p0

    .line 206
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 207
    .line 208
    if-eqz v0, :cond_9

    .line 209
    .line 210
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 211
    .line 212
    .line 213
    move-result-object p1

    .line 214
    invoke-virtual {p1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object p1

    .line 218
    goto :goto_3

    .line 219
    :cond_9
    const-string p1, "null"

    .line 220
    .line 221
    :goto_3
    const-string v0, "Can\'t make a decor toolbar out of "

    .line 222
    .line 223
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object p1

    .line 227
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    throw p0
.end method

.method public final f(Z)V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lh/i0;->h:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    const/4 v0, 0x4

    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    move p1, v0

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p1, 0x0

    .line 11
    :goto_0
    iget-object v1, p0, Lh/i0;->e:Lm/f1;

    .line 12
    .line 13
    check-cast v1, Lm/w2;

    .line 14
    .line 15
    iget v2, v1, Lm/w2;->b:I

    .line 16
    .line 17
    const/4 v3, 0x1

    .line 18
    iput-boolean v3, p0, Lh/i0;->h:Z

    .line 19
    .line 20
    and-int/lit8 p0, p1, 0x4

    .line 21
    .line 22
    and-int/lit8 p1, v2, -0x5

    .line 23
    .line 24
    or-int/2addr p0, p1

    .line 25
    invoke-virtual {v1, p0}, Lm/w2;->a(I)V

    .line 26
    .line 27
    .line 28
    :cond_1
    return-void
.end method

.method public final g(Z)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    iget-object p1, p0, Lh/i0;->e:Lm/f1;

    .line 5
    .line 6
    check-cast p1, Lm/w2;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget-object p1, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Landroidx/appcompat/widget/ActionBarContainer;->setTabContainer(Lm/k2;)V

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    iget-object p1, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 18
    .line 19
    invoke-virtual {p1, v0}, Landroidx/appcompat/widget/ActionBarContainer;->setTabContainer(Lm/k2;)V

    .line 20
    .line 21
    .line 22
    iget-object p1, p0, Lh/i0;->e:Lm/f1;

    .line 23
    .line 24
    check-cast p1, Lm/w2;

    .line 25
    .line 26
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p1, p0, Lh/i0;->e:Lm/f1;

    .line 30
    .line 31
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    iget-object p1, p0, Lh/i0;->e:Lm/f1;

    .line 35
    .line 36
    check-cast p1, Lm/w2;

    .line 37
    .line 38
    iget-object p1, p1, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    invoke-virtual {p1, v0}, Landroidx/appcompat/widget/Toolbar;->setCollapsible(Z)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Lh/i0;->c:Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 45
    .line 46
    invoke-virtual {p0, v0}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->setHasNonEmbeddedTabs(Z)V

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method public final h(Z)V
    .locals 11

    .line 1
    iget-boolean v0, p0, Lh/i0;->p:Z

    .line 2
    .line 3
    iget-boolean v1, p0, Lh/i0;->q:Z

    .line 4
    .line 5
    const-wide/16 v2, 0xfa

    .line 6
    .line 7
    const/4 v4, 0x0

    .line 8
    const/high16 v5, 0x3f800000    # 1.0f

    .line 9
    .line 10
    iget-object v6, p0, Lh/i0;->x:Lbu/c;

    .line 11
    .line 12
    iget-object v7, p0, Lh/i0;->g:Landroid/view/View;

    .line 13
    .line 14
    const/4 v8, 0x1

    .line 15
    const/4 v9, 0x0

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    goto/16 :goto_0

    .line 19
    .line 20
    :cond_0
    if-eqz v0, :cond_c

    .line 21
    .line 22
    iget-boolean v0, p0, Lh/i0;->r:Z

    .line 23
    .line 24
    if-eqz v0, :cond_19

    .line 25
    .line 26
    iput-boolean v9, p0, Lh/i0;->r:Z

    .line 27
    .line 28
    iget-object v0, p0, Lh/i0;->s:Lk/j;

    .line 29
    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    invoke-virtual {v0}, Lk/j;->a()V

    .line 33
    .line 34
    .line 35
    :cond_1
    iget v0, p0, Lh/i0;->n:I

    .line 36
    .line 37
    iget-object v1, p0, Lh/i0;->v:Lh/g0;

    .line 38
    .line 39
    if-nez v0, :cond_b

    .line 40
    .line 41
    iget-boolean v0, p0, Lh/i0;->t:Z

    .line 42
    .line 43
    if-nez v0, :cond_2

    .line 44
    .line 45
    if-eqz p1, :cond_b

    .line 46
    .line 47
    :cond_2
    iget-object v0, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 48
    .line 49
    invoke-virtual {v0, v5}, Landroid/view/View;->setAlpha(F)V

    .line 50
    .line 51
    .line 52
    iget-object v0, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 53
    .line 54
    invoke-virtual {v0, v8}, Landroidx/appcompat/widget/ActionBarContainer;->setTransitioning(Z)V

    .line 55
    .line 56
    .line 57
    new-instance v0, Lk/j;

    .line 58
    .line 59
    invoke-direct {v0}, Lk/j;-><init>()V

    .line 60
    .line 61
    .line 62
    iget-object v5, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 63
    .line 64
    invoke-virtual {v5}, Landroid/view/View;->getHeight()I

    .line 65
    .line 66
    .line 67
    move-result v5

    .line 68
    neg-int v5, v5

    .line 69
    int-to-float v5, v5

    .line 70
    if-eqz p1, :cond_3

    .line 71
    .line 72
    filled-new-array {v9, v9}, [I

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    iget-object v9, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 77
    .line 78
    invoke-virtual {v9, p1}, Landroid/view/View;->getLocationInWindow([I)V

    .line 79
    .line 80
    .line 81
    aget p1, p1, v8

    .line 82
    .line 83
    int-to-float p1, p1

    .line 84
    sub-float/2addr v5, p1

    .line 85
    :cond_3
    iget-object p1, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 86
    .line 87
    invoke-static {p1}, Ld6/r0;->a(Landroid/view/View;)Ld6/w0;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    invoke-virtual {p1, v5}, Ld6/w0;->e(F)V

    .line 92
    .line 93
    .line 94
    iget-object v8, p1, Ld6/w0;->a:Ljava/lang/ref/WeakReference;

    .line 95
    .line 96
    invoke-virtual {v8}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v8

    .line 100
    check-cast v8, Landroid/view/View;

    .line 101
    .line 102
    if-eqz v8, :cond_5

    .line 103
    .line 104
    if-eqz v6, :cond_4

    .line 105
    .line 106
    new-instance v4, Ld6/v0;

    .line 107
    .line 108
    invoke-direct {v4, v6, v8}, Ld6/v0;-><init>(Lbu/c;Landroid/view/View;)V

    .line 109
    .line 110
    .line 111
    :cond_4
    invoke-virtual {v8}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    .line 112
    .line 113
    .line 114
    move-result-object v6

    .line 115
    invoke-virtual {v6, v4}, Landroid/view/ViewPropertyAnimator;->setUpdateListener(Landroid/animation/ValueAnimator$AnimatorUpdateListener;)Landroid/view/ViewPropertyAnimator;

    .line 116
    .line 117
    .line 118
    :cond_5
    iget-boolean v4, v0, Lk/j;->e:Z

    .line 119
    .line 120
    iget-object v6, v0, Lk/j;->a:Ljava/util/ArrayList;

    .line 121
    .line 122
    if-nez v4, :cond_6

    .line 123
    .line 124
    invoke-virtual {v6, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    :cond_6
    iget-boolean p1, p0, Lh/i0;->o:Z

    .line 128
    .line 129
    if-eqz p1, :cond_7

    .line 130
    .line 131
    if-eqz v7, :cond_7

    .line 132
    .line 133
    invoke-static {v7}, Ld6/r0;->a(Landroid/view/View;)Ld6/w0;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    invoke-virtual {p1, v5}, Ld6/w0;->e(F)V

    .line 138
    .line 139
    .line 140
    iget-boolean v4, v0, Lk/j;->e:Z

    .line 141
    .line 142
    if-nez v4, :cond_7

    .line 143
    .line 144
    invoke-virtual {v6, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    :cond_7
    iget-boolean p1, v0, Lk/j;->e:Z

    .line 148
    .line 149
    if-nez p1, :cond_8

    .line 150
    .line 151
    sget-object v4, Lh/i0;->y:Landroid/view/animation/AccelerateInterpolator;

    .line 152
    .line 153
    iput-object v4, v0, Lk/j;->c:Landroid/view/animation/Interpolator;

    .line 154
    .line 155
    :cond_8
    if-nez p1, :cond_9

    .line 156
    .line 157
    iput-wide v2, v0, Lk/j;->b:J

    .line 158
    .line 159
    :cond_9
    if-nez p1, :cond_a

    .line 160
    .line 161
    iput-object v1, v0, Lk/j;->d:Ld6/x0;

    .line 162
    .line 163
    :cond_a
    iput-object v0, p0, Lh/i0;->s:Lk/j;

    .line 164
    .line 165
    invoke-virtual {v0}, Lk/j;->b()V

    .line 166
    .line 167
    .line 168
    return-void

    .line 169
    :cond_b
    invoke-virtual {v1}, Lh/g0;->c()V

    .line 170
    .line 171
    .line 172
    return-void

    .line 173
    :cond_c
    :goto_0
    iget-boolean v0, p0, Lh/i0;->r:Z

    .line 174
    .line 175
    if-nez v0, :cond_19

    .line 176
    .line 177
    iput-boolean v8, p0, Lh/i0;->r:Z

    .line 178
    .line 179
    iget-object v0, p0, Lh/i0;->s:Lk/j;

    .line 180
    .line 181
    if-eqz v0, :cond_d

    .line 182
    .line 183
    invoke-virtual {v0}, Lk/j;->a()V

    .line 184
    .line 185
    .line 186
    :cond_d
    iget-object v0, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 187
    .line 188
    invoke-virtual {v0, v9}, Landroidx/appcompat/widget/ActionBarContainer;->setVisibility(I)V

    .line 189
    .line 190
    .line 191
    iget v0, p0, Lh/i0;->n:I

    .line 192
    .line 193
    iget-object v1, p0, Lh/i0;->w:Lh/g0;

    .line 194
    .line 195
    const/4 v10, 0x0

    .line 196
    if-nez v0, :cond_17

    .line 197
    .line 198
    iget-boolean v0, p0, Lh/i0;->t:Z

    .line 199
    .line 200
    if-nez v0, :cond_e

    .line 201
    .line 202
    if-eqz p1, :cond_17

    .line 203
    .line 204
    :cond_e
    iget-object v0, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 205
    .line 206
    invoke-virtual {v0, v10}, Landroid/view/View;->setTranslationY(F)V

    .line 207
    .line 208
    .line 209
    iget-object v0, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 210
    .line 211
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 212
    .line 213
    .line 214
    move-result v0

    .line 215
    neg-int v0, v0

    .line 216
    int-to-float v0, v0

    .line 217
    if-eqz p1, :cond_f

    .line 218
    .line 219
    filled-new-array {v9, v9}, [I

    .line 220
    .line 221
    .line 222
    move-result-object p1

    .line 223
    iget-object v5, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 224
    .line 225
    invoke-virtual {v5, p1}, Landroid/view/View;->getLocationInWindow([I)V

    .line 226
    .line 227
    .line 228
    aget p1, p1, v8

    .line 229
    .line 230
    int-to-float p1, p1

    .line 231
    sub-float/2addr v0, p1

    .line 232
    :cond_f
    iget-object p1, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 233
    .line 234
    invoke-virtual {p1, v0}, Landroid/view/View;->setTranslationY(F)V

    .line 235
    .line 236
    .line 237
    new-instance p1, Lk/j;

    .line 238
    .line 239
    invoke-direct {p1}, Lk/j;-><init>()V

    .line 240
    .line 241
    .line 242
    iget-object v5, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 243
    .line 244
    invoke-static {v5}, Ld6/r0;->a(Landroid/view/View;)Ld6/w0;

    .line 245
    .line 246
    .line 247
    move-result-object v5

    .line 248
    invoke-virtual {v5, v10}, Ld6/w0;->e(F)V

    .line 249
    .line 250
    .line 251
    iget-object v8, v5, Ld6/w0;->a:Ljava/lang/ref/WeakReference;

    .line 252
    .line 253
    invoke-virtual {v8}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v8

    .line 257
    check-cast v8, Landroid/view/View;

    .line 258
    .line 259
    if-eqz v8, :cond_11

    .line 260
    .line 261
    if-eqz v6, :cond_10

    .line 262
    .line 263
    new-instance v4, Ld6/v0;

    .line 264
    .line 265
    invoke-direct {v4, v6, v8}, Ld6/v0;-><init>(Lbu/c;Landroid/view/View;)V

    .line 266
    .line 267
    .line 268
    :cond_10
    invoke-virtual {v8}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    .line 269
    .line 270
    .line 271
    move-result-object v6

    .line 272
    invoke-virtual {v6, v4}, Landroid/view/ViewPropertyAnimator;->setUpdateListener(Landroid/animation/ValueAnimator$AnimatorUpdateListener;)Landroid/view/ViewPropertyAnimator;

    .line 273
    .line 274
    .line 275
    :cond_11
    iget-boolean v4, p1, Lk/j;->e:Z

    .line 276
    .line 277
    iget-object v6, p1, Lk/j;->a:Ljava/util/ArrayList;

    .line 278
    .line 279
    if-nez v4, :cond_12

    .line 280
    .line 281
    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    :cond_12
    iget-boolean v4, p0, Lh/i0;->o:Z

    .line 285
    .line 286
    if-eqz v4, :cond_13

    .line 287
    .line 288
    if-eqz v7, :cond_13

    .line 289
    .line 290
    invoke-virtual {v7, v0}, Landroid/view/View;->setTranslationY(F)V

    .line 291
    .line 292
    .line 293
    invoke-static {v7}, Ld6/r0;->a(Landroid/view/View;)Ld6/w0;

    .line 294
    .line 295
    .line 296
    move-result-object v0

    .line 297
    invoke-virtual {v0, v10}, Ld6/w0;->e(F)V

    .line 298
    .line 299
    .line 300
    iget-boolean v4, p1, Lk/j;->e:Z

    .line 301
    .line 302
    if-nez v4, :cond_13

    .line 303
    .line 304
    invoke-virtual {v6, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 305
    .line 306
    .line 307
    :cond_13
    iget-boolean v0, p1, Lk/j;->e:Z

    .line 308
    .line 309
    if-nez v0, :cond_14

    .line 310
    .line 311
    sget-object v4, Lh/i0;->z:Landroid/view/animation/DecelerateInterpolator;

    .line 312
    .line 313
    iput-object v4, p1, Lk/j;->c:Landroid/view/animation/Interpolator;

    .line 314
    .line 315
    :cond_14
    if-nez v0, :cond_15

    .line 316
    .line 317
    iput-wide v2, p1, Lk/j;->b:J

    .line 318
    .line 319
    :cond_15
    if-nez v0, :cond_16

    .line 320
    .line 321
    iput-object v1, p1, Lk/j;->d:Ld6/x0;

    .line 322
    .line 323
    :cond_16
    iput-object p1, p0, Lh/i0;->s:Lk/j;

    .line 324
    .line 325
    invoke-virtual {p1}, Lk/j;->b()V

    .line 326
    .line 327
    .line 328
    goto :goto_1

    .line 329
    :cond_17
    iget-object p1, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 330
    .line 331
    invoke-virtual {p1, v5}, Landroid/view/View;->setAlpha(F)V

    .line 332
    .line 333
    .line 334
    iget-object p1, p0, Lh/i0;->d:Landroidx/appcompat/widget/ActionBarContainer;

    .line 335
    .line 336
    invoke-virtual {p1, v10}, Landroid/view/View;->setTranslationY(F)V

    .line 337
    .line 338
    .line 339
    iget-boolean p1, p0, Lh/i0;->o:Z

    .line 340
    .line 341
    if-eqz p1, :cond_18

    .line 342
    .line 343
    if-eqz v7, :cond_18

    .line 344
    .line 345
    invoke-virtual {v7, v10}, Landroid/view/View;->setTranslationY(F)V

    .line 346
    .line 347
    .line 348
    :cond_18
    invoke-virtual {v1}, Lh/g0;->c()V

    .line 349
    .line 350
    .line 351
    :goto_1
    iget-object p0, p0, Lh/i0;->c:Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 352
    .line 353
    if-eqz p0, :cond_19

    .line 354
    .line 355
    sget-object p1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 356
    .line 357
    invoke-static {p0}, Ld6/i0;->c(Landroid/view/View;)V

    .line 358
    .line 359
    .line 360
    :cond_19
    return-void
.end method
