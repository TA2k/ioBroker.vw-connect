.class public final Lh/f;
.super Lb/t;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/content/DialogInterface;
.implements Lh/j;


# instance fields
.field public g:Lh/z;

.field public final h:Lh/a0;

.field public final i:Lh/d;


# direct methods
.method public constructor <init>(Landroid/view/ContextThemeWrapper;I)V
    .locals 4

    .line 1
    invoke-static {p1, p2}, Lh/f;->e(Landroid/content/Context;I)I

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    const/4 v0, 0x1

    .line 6
    const v1, 0x7f0401bb

    .line 7
    .line 8
    .line 9
    if-nez p2, :cond_0

    .line 10
    .line 11
    new-instance v2, Landroid/util/TypedValue;

    .line 12
    .line 13
    invoke-direct {v2}, Landroid/util/TypedValue;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    invoke-virtual {v3, v1, v2, v0}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 21
    .line 22
    .line 23
    iget v2, v2, Landroid/util/TypedValue;->resourceId:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move v2, p2

    .line 27
    :goto_0
    invoke-direct {p0, p1, v2}, Lb/t;-><init>(Landroid/content/Context;I)V

    .line 28
    .line 29
    .line 30
    new-instance v2, Lh/a0;

    .line 31
    .line 32
    invoke-direct {v2, p0}, Lh/a0;-><init>(Lh/f;)V

    .line 33
    .line 34
    .line 35
    iput-object v2, p0, Lh/f;->h:Lh/a0;

    .line 36
    .line 37
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    if-nez p2, :cond_1

    .line 42
    .line 43
    new-instance p2, Landroid/util/TypedValue;

    .line 44
    .line 45
    invoke-direct {p2}, Landroid/util/TypedValue;-><init>()V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    invoke-virtual {p1, v1, p2, v0}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 53
    .line 54
    .line 55
    iget p2, p2, Landroid/util/TypedValue;->resourceId:I

    .line 56
    .line 57
    :cond_1
    move-object p1, v2

    .line 58
    check-cast p1, Lh/z;

    .line 59
    .line 60
    iput p2, p1, Lh/z;->W:I

    .line 61
    .line 62
    invoke-virtual {v2}, Lh/n;->g()V

    .line 63
    .line 64
    .line 65
    new-instance p1, Lh/d;

    .line 66
    .line 67
    invoke-virtual {p0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-direct {p1, p2, p0, v0}, Lh/d;-><init>(Landroid/content/Context;Lh/f;Landroid/view/Window;)V

    .line 76
    .line 77
    .line 78
    iput-object p1, p0, Lh/f;->i:Lh/d;

    .line 79
    .line 80
    return-void
.end method

.method public static e(Landroid/content/Context;I)I
    .locals 2

    .line 1
    ushr-int/lit8 v0, p1, 0x18

    .line 2
    .line 3
    and-int/lit16 v0, v0, 0xff

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    if-lt v0, v1, :cond_0

    .line 7
    .line 8
    return p1

    .line 9
    :cond_0
    new-instance p1, Landroid/util/TypedValue;

    .line 10
    .line 11
    invoke-direct {p1}, Landroid/util/TypedValue;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const v0, 0x7f04002f

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, v0, p1, v1}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 22
    .line 23
    .line 24
    iget p0, p1, Landroid/util/TypedValue;->resourceId:I

    .line 25
    .line 26
    return p0
.end method


# virtual methods
.method public final addContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lb/t;->b()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lh/z;

    .line 9
    .line 10
    invoke-virtual {p0}, Lh/z;->A()V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lh/z;->D:Landroid/view/ViewGroup;

    .line 14
    .line 15
    const v1, 0x1020002

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, v1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Landroid/view/ViewGroup;

    .line 23
    .line 24
    invoke-virtual {v0, p1, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 25
    .line 26
    .line 27
    iget-object p1, p0, Lh/z;->p:Lh/u;

    .line 28
    .line 29
    iget-object p0, p0, Lh/z;->o:Landroid/view/Window;

    .line 30
    .line 31
    invoke-virtual {p0}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {p1, p0}, Lh/u;->a(Landroid/view/Window$Callback;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public final c()Lh/n;
    .locals 3

    .line 1
    iget-object v0, p0, Lh/f;->g:Lh/z;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lh/n;->d:Lfv/o;

    .line 6
    .line 7
    new-instance v0, Lh/z;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-direct {v0, v1, v2, p0, p0}, Lh/z;-><init>(Landroid/content/Context;Landroid/view/Window;Lh/j;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lh/f;->g:Lh/z;

    .line 21
    .line 22
    :cond_0
    iget-object p0, p0, Lh/f;->g:Lh/z;

    .line 23
    .line 24
    return-object p0
.end method

.method public final d(Landroid/os/Bundle;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lh/n;->d()V

    .line 6
    .line 7
    .line 8
    invoke-super {p0, p1}, Lb/t;->onCreate(Landroid/os/Bundle;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p0}, Lh/n;->g()V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final dismiss()V
    .locals 0

    .line 1
    invoke-super {p0}, Landroid/app/Dialog;->dismiss()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-virtual {p0}, Lh/n;->h()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final dispatchKeyEvent(Landroid/view/KeyEvent;)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lh/f;->h:Lh/a0;

    .line 9
    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_0
    iget-object p0, p0, Lh/a0;->d:Lh/f;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lh/f;->g(Landroid/view/KeyEvent;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0
.end method

.method public final f(Ljava/lang/CharSequence;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/app/Dialog;->setTitle(Ljava/lang/CharSequence;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-virtual {p0, p1}, Lh/n;->p(Ljava/lang/CharSequence;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final findViewById(I)Landroid/view/View;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lh/z;

    .line 6
    .line 7
    invoke-virtual {p0}, Lh/z;->A()V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lh/z;->o:Landroid/view/Window;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public final g(Landroid/view/KeyEvent;)Z
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/app/Dialog;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final invalidateOptionsMenu()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lh/n;->e()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final onCreate(Landroid/os/Bundle;)V
    .locals 16

    .line 1
    invoke-virtual/range {p0 .. p1}, Lh/f;->d(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    move-object/from16 v0, p0

    .line 5
    .line 6
    iget-object v0, v0, Lh/f;->i:Lh/d;

    .line 7
    .line 8
    iget v1, v0, Lh/d;->y:I

    .line 9
    .line 10
    iget-object v2, v0, Lh/d;->b:Lh/f;

    .line 11
    .line 12
    invoke-virtual {v2, v1}, Lh/f;->setContentView(I)V

    .line 13
    .line 14
    .line 15
    iget-object v1, v0, Lh/d;->a:Landroid/content/Context;

    .line 16
    .line 17
    iget-object v2, v0, Lh/d;->c:Landroid/view/Window;

    .line 18
    .line 19
    const v3, 0x7f0a0253

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v3}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    const v4, 0x7f0a02ea

    .line 27
    .line 28
    .line 29
    invoke-virtual {v3, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    const v6, 0x7f0a00f0

    .line 34
    .line 35
    .line 36
    invoke-virtual {v3, v6}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 37
    .line 38
    .line 39
    move-result-object v7

    .line 40
    const v8, 0x7f0a0070

    .line 41
    .line 42
    .line 43
    invoke-virtual {v3, v8}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 44
    .line 45
    .line 46
    move-result-object v9

    .line 47
    const v10, 0x7f0a00f9

    .line 48
    .line 49
    .line 50
    invoke-virtual {v3, v10}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    check-cast v3, Landroid/view/ViewGroup;

    .line 55
    .line 56
    iget-object v10, v0, Lh/d;->f:Landroid/view/View;

    .line 57
    .line 58
    if-eqz v10, :cond_0

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    const/4 v10, 0x0

    .line 62
    :goto_0
    const/4 v13, 0x0

    .line 63
    if-eqz v10, :cond_1

    .line 64
    .line 65
    const/4 v14, 0x1

    .line 66
    goto :goto_1

    .line 67
    :cond_1
    move v14, v13

    .line 68
    :goto_1
    if-eqz v14, :cond_2

    .line 69
    .line 70
    invoke-static {v10}, Lh/d;->a(Landroid/view/View;)Z

    .line 71
    .line 72
    .line 73
    move-result v15

    .line 74
    if-nez v15, :cond_3

    .line 75
    .line 76
    :cond_2
    const/high16 v15, 0x20000

    .line 77
    .line 78
    invoke-virtual {v2, v15, v15}, Landroid/view/Window;->setFlags(II)V

    .line 79
    .line 80
    .line 81
    :cond_3
    const/16 v15, 0x8

    .line 82
    .line 83
    const/4 v11, -0x1

    .line 84
    if-eqz v14, :cond_5

    .line 85
    .line 86
    const v14, 0x7f0a00f8

    .line 87
    .line 88
    .line 89
    invoke-virtual {v2, v14}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    .line 90
    .line 91
    .line 92
    move-result-object v14

    .line 93
    check-cast v14, Landroid/widget/FrameLayout;

    .line 94
    .line 95
    new-instance v12, Landroid/view/ViewGroup$LayoutParams;

    .line 96
    .line 97
    invoke-direct {v12, v11, v11}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v14, v10, v12}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 101
    .line 102
    .line 103
    iget-boolean v10, v0, Lh/d;->g:Z

    .line 104
    .line 105
    if-eqz v10, :cond_4

    .line 106
    .line 107
    invoke-virtual {v14, v13, v13, v13, v13}, Landroid/view/View;->setPadding(IIII)V

    .line 108
    .line 109
    .line 110
    :cond_4
    iget-object v10, v0, Lh/d;->e:Landroidx/appcompat/app/AlertController$RecycleListView;

    .line 111
    .line 112
    if-eqz v10, :cond_6

    .line 113
    .line 114
    invoke-virtual {v3}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 115
    .line 116
    .line 117
    move-result-object v10

    .line 118
    check-cast v10, Lm/q1;

    .line 119
    .line 120
    const/4 v12, 0x0

    .line 121
    iput v12, v10, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_5
    invoke-virtual {v3, v15}, Landroid/view/View;->setVisibility(I)V

    .line 125
    .line 126
    .line 127
    :cond_6
    :goto_2
    invoke-virtual {v3, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 128
    .line 129
    .line 130
    move-result-object v4

    .line 131
    invoke-virtual {v3, v6}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 132
    .line 133
    .line 134
    move-result-object v6

    .line 135
    invoke-virtual {v3, v8}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 136
    .line 137
    .line 138
    move-result-object v8

    .line 139
    invoke-static {v4, v5}, Lh/d;->b(Landroid/view/View;Landroid/view/View;)Landroid/view/ViewGroup;

    .line 140
    .line 141
    .line 142
    move-result-object v4

    .line 143
    invoke-static {v6, v7}, Lh/d;->b(Landroid/view/View;Landroid/view/View;)Landroid/view/ViewGroup;

    .line 144
    .line 145
    .line 146
    move-result-object v5

    .line 147
    invoke-static {v8, v9}, Lh/d;->b(Landroid/view/View;Landroid/view/View;)Landroid/view/ViewGroup;

    .line 148
    .line 149
    .line 150
    move-result-object v6

    .line 151
    const v7, 0x7f0a0282

    .line 152
    .line 153
    .line 154
    invoke-virtual {v2, v7}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    .line 155
    .line 156
    .line 157
    move-result-object v7

    .line 158
    check-cast v7, Landroidx/core/widget/NestedScrollView;

    .line 159
    .line 160
    iput-object v7, v0, Lh/d;->q:Landroidx/core/widget/NestedScrollView;

    .line 161
    .line 162
    invoke-virtual {v7, v13}, Landroid/view/View;->setFocusable(Z)V

    .line 163
    .line 164
    .line 165
    iget-object v7, v0, Lh/d;->q:Landroidx/core/widget/NestedScrollView;

    .line 166
    .line 167
    invoke-virtual {v7, v13}, Landroidx/core/widget/NestedScrollView;->setNestedScrollingEnabled(Z)V

    .line 168
    .line 169
    .line 170
    const v7, 0x102000b

    .line 171
    .line 172
    .line 173
    invoke-virtual {v5, v7}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 174
    .line 175
    .line 176
    move-result-object v7

    .line 177
    check-cast v7, Landroid/widget/TextView;

    .line 178
    .line 179
    iput-object v7, v0, Lh/d;->u:Landroid/widget/TextView;

    .line 180
    .line 181
    if-nez v7, :cond_7

    .line 182
    .line 183
    goto :goto_3

    .line 184
    :cond_7
    invoke-virtual {v7, v15}, Landroid/view/View;->setVisibility(I)V

    .line 185
    .line 186
    .line 187
    iget-object v7, v0, Lh/d;->q:Landroidx/core/widget/NestedScrollView;

    .line 188
    .line 189
    iget-object v8, v0, Lh/d;->u:Landroid/widget/TextView;

    .line 190
    .line 191
    invoke-virtual {v7, v8}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 192
    .line 193
    .line 194
    iget-object v7, v0, Lh/d;->e:Landroidx/appcompat/app/AlertController$RecycleListView;

    .line 195
    .line 196
    if-eqz v7, :cond_8

    .line 197
    .line 198
    iget-object v7, v0, Lh/d;->q:Landroidx/core/widget/NestedScrollView;

    .line 199
    .line 200
    invoke-virtual {v7}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 201
    .line 202
    .line 203
    move-result-object v7

    .line 204
    check-cast v7, Landroid/view/ViewGroup;

    .line 205
    .line 206
    iget-object v8, v0, Lh/d;->q:Landroidx/core/widget/NestedScrollView;

    .line 207
    .line 208
    invoke-virtual {v7, v8}, Landroid/view/ViewGroup;->indexOfChild(Landroid/view/View;)I

    .line 209
    .line 210
    .line 211
    move-result v8

    .line 212
    invoke-virtual {v7, v8}, Landroid/view/ViewGroup;->removeViewAt(I)V

    .line 213
    .line 214
    .line 215
    iget-object v9, v0, Lh/d;->e:Landroidx/appcompat/app/AlertController$RecycleListView;

    .line 216
    .line 217
    new-instance v10, Landroid/view/ViewGroup$LayoutParams;

    .line 218
    .line 219
    invoke-direct {v10, v11, v11}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v7, v9, v8, v10}, Landroid/view/ViewGroup;->addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V

    .line 223
    .line 224
    .line 225
    goto :goto_3

    .line 226
    :cond_8
    invoke-virtual {v5, v15}, Landroid/view/View;->setVisibility(I)V

    .line 227
    .line 228
    .line 229
    :goto_3
    const v7, 0x1020019

    .line 230
    .line 231
    .line 232
    invoke-virtual {v6, v7}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 233
    .line 234
    .line 235
    move-result-object v7

    .line 236
    check-cast v7, Landroid/widget/Button;

    .line 237
    .line 238
    iput-object v7, v0, Lh/d;->h:Landroid/widget/Button;

    .line 239
    .line 240
    iget-object v8, v0, Lh/d;->E:Lcom/google/android/material/datepicker/t;

    .line 241
    .line 242
    invoke-virtual {v7, v8}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 243
    .line 244
    .line 245
    iget-object v7, v0, Lh/d;->i:Ljava/lang/CharSequence;

    .line 246
    .line 247
    invoke-static {v7}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 248
    .line 249
    .line 250
    move-result v7

    .line 251
    if-eqz v7, :cond_9

    .line 252
    .line 253
    iget-object v7, v0, Lh/d;->h:Landroid/widget/Button;

    .line 254
    .line 255
    invoke-virtual {v7, v15}, Landroid/view/View;->setVisibility(I)V

    .line 256
    .line 257
    .line 258
    move v7, v13

    .line 259
    goto :goto_4

    .line 260
    :cond_9
    iget-object v7, v0, Lh/d;->h:Landroid/widget/Button;

    .line 261
    .line 262
    iget-object v9, v0, Lh/d;->i:Ljava/lang/CharSequence;

    .line 263
    .line 264
    invoke-virtual {v7, v9}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 265
    .line 266
    .line 267
    iget-object v7, v0, Lh/d;->h:Landroid/widget/Button;

    .line 268
    .line 269
    invoke-virtual {v7, v13}, Landroid/view/View;->setVisibility(I)V

    .line 270
    .line 271
    .line 272
    const/4 v7, 0x1

    .line 273
    :goto_4
    const v9, 0x102001a

    .line 274
    .line 275
    .line 276
    invoke-virtual {v6, v9}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 277
    .line 278
    .line 279
    move-result-object v9

    .line 280
    check-cast v9, Landroid/widget/Button;

    .line 281
    .line 282
    iput-object v9, v0, Lh/d;->k:Landroid/widget/Button;

    .line 283
    .line 284
    invoke-virtual {v9, v8}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 285
    .line 286
    .line 287
    iget-object v9, v0, Lh/d;->l:Ljava/lang/CharSequence;

    .line 288
    .line 289
    invoke-static {v9}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 290
    .line 291
    .line 292
    move-result v9

    .line 293
    if-eqz v9, :cond_a

    .line 294
    .line 295
    iget-object v9, v0, Lh/d;->k:Landroid/widget/Button;

    .line 296
    .line 297
    invoke-virtual {v9, v15}, Landroid/view/View;->setVisibility(I)V

    .line 298
    .line 299
    .line 300
    goto :goto_5

    .line 301
    :cond_a
    iget-object v9, v0, Lh/d;->k:Landroid/widget/Button;

    .line 302
    .line 303
    iget-object v10, v0, Lh/d;->l:Ljava/lang/CharSequence;

    .line 304
    .line 305
    invoke-virtual {v9, v10}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 306
    .line 307
    .line 308
    iget-object v9, v0, Lh/d;->k:Landroid/widget/Button;

    .line 309
    .line 310
    invoke-virtual {v9, v13}, Landroid/view/View;->setVisibility(I)V

    .line 311
    .line 312
    .line 313
    or-int/lit8 v7, v7, 0x2

    .line 314
    .line 315
    :goto_5
    const v9, 0x102001b

    .line 316
    .line 317
    .line 318
    invoke-virtual {v6, v9}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 319
    .line 320
    .line 321
    move-result-object v9

    .line 322
    check-cast v9, Landroid/widget/Button;

    .line 323
    .line 324
    iput-object v9, v0, Lh/d;->n:Landroid/widget/Button;

    .line 325
    .line 326
    invoke-virtual {v9, v8}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 327
    .line 328
    .line 329
    iget-object v8, v0, Lh/d;->o:Ljava/lang/CharSequence;

    .line 330
    .line 331
    invoke-static {v8}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 332
    .line 333
    .line 334
    move-result v8

    .line 335
    if-eqz v8, :cond_b

    .line 336
    .line 337
    iget-object v8, v0, Lh/d;->n:Landroid/widget/Button;

    .line 338
    .line 339
    invoke-virtual {v8, v15}, Landroid/view/View;->setVisibility(I)V

    .line 340
    .line 341
    .line 342
    goto :goto_6

    .line 343
    :cond_b
    iget-object v8, v0, Lh/d;->n:Landroid/widget/Button;

    .line 344
    .line 345
    iget-object v9, v0, Lh/d;->o:Ljava/lang/CharSequence;

    .line 346
    .line 347
    invoke-virtual {v8, v9}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 348
    .line 349
    .line 350
    iget-object v8, v0, Lh/d;->n:Landroid/widget/Button;

    .line 351
    .line 352
    invoke-virtual {v8, v13}, Landroid/view/View;->setVisibility(I)V

    .line 353
    .line 354
    .line 355
    or-int/lit8 v7, v7, 0x4

    .line 356
    .line 357
    :goto_6
    new-instance v8, Landroid/util/TypedValue;

    .line 358
    .line 359
    invoke-direct {v8}, Landroid/util/TypedValue;-><init>()V

    .line 360
    .line 361
    .line 362
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 363
    .line 364
    .line 365
    move-result-object v1

    .line 366
    const v9, 0x7f04002d

    .line 367
    .line 368
    .line 369
    const/4 v10, 0x1

    .line 370
    invoke-virtual {v1, v9, v8, v10}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 371
    .line 372
    .line 373
    iget v1, v8, Landroid/util/TypedValue;->data:I

    .line 374
    .line 375
    const/4 v8, 0x2

    .line 376
    if-eqz v1, :cond_e

    .line 377
    .line 378
    const/high16 v1, 0x3f000000    # 0.5f

    .line 379
    .line 380
    if-ne v7, v10, :cond_c

    .line 381
    .line 382
    iget-object v9, v0, Lh/d;->h:Landroid/widget/Button;

    .line 383
    .line 384
    invoke-virtual {v9}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 385
    .line 386
    .line 387
    move-result-object v12

    .line 388
    check-cast v12, Landroid/widget/LinearLayout$LayoutParams;

    .line 389
    .line 390
    iput v10, v12, Landroid/widget/LinearLayout$LayoutParams;->gravity:I

    .line 391
    .line 392
    iput v1, v12, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 393
    .line 394
    invoke-virtual {v9, v12}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 395
    .line 396
    .line 397
    goto :goto_7

    .line 398
    :cond_c
    if-ne v7, v8, :cond_d

    .line 399
    .line 400
    iget-object v9, v0, Lh/d;->k:Landroid/widget/Button;

    .line 401
    .line 402
    invoke-virtual {v9}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 403
    .line 404
    .line 405
    move-result-object v12

    .line 406
    check-cast v12, Landroid/widget/LinearLayout$LayoutParams;

    .line 407
    .line 408
    iput v10, v12, Landroid/widget/LinearLayout$LayoutParams;->gravity:I

    .line 409
    .line 410
    iput v1, v12, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 411
    .line 412
    invoke-virtual {v9, v12}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 413
    .line 414
    .line 415
    goto :goto_7

    .line 416
    :cond_d
    const/4 v9, 0x4

    .line 417
    if-ne v7, v9, :cond_e

    .line 418
    .line 419
    iget-object v9, v0, Lh/d;->n:Landroid/widget/Button;

    .line 420
    .line 421
    invoke-virtual {v9}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 422
    .line 423
    .line 424
    move-result-object v12

    .line 425
    check-cast v12, Landroid/widget/LinearLayout$LayoutParams;

    .line 426
    .line 427
    iput v10, v12, Landroid/widget/LinearLayout$LayoutParams;->gravity:I

    .line 428
    .line 429
    iput v1, v12, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 430
    .line 431
    invoke-virtual {v9, v12}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 432
    .line 433
    .line 434
    :cond_e
    :goto_7
    if-eqz v7, :cond_f

    .line 435
    .line 436
    goto :goto_8

    .line 437
    :cond_f
    invoke-virtual {v6, v15}, Landroid/view/View;->setVisibility(I)V

    .line 438
    .line 439
    .line 440
    :goto_8
    iget-object v1, v0, Lh/d;->v:Landroid/view/View;

    .line 441
    .line 442
    const v7, 0x7f0a02e7

    .line 443
    .line 444
    .line 445
    if-eqz v1, :cond_10

    .line 446
    .line 447
    new-instance v1, Landroid/view/ViewGroup$LayoutParams;

    .line 448
    .line 449
    const/4 v9, -0x2

    .line 450
    invoke-direct {v1, v11, v9}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    .line 451
    .line 452
    .line 453
    iget-object v9, v0, Lh/d;->v:Landroid/view/View;

    .line 454
    .line 455
    invoke-virtual {v4, v9, v13, v1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V

    .line 456
    .line 457
    .line 458
    invoke-virtual {v2, v7}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    .line 459
    .line 460
    .line 461
    move-result-object v1

    .line 462
    invoke-virtual {v1, v15}, Landroid/view/View;->setVisibility(I)V

    .line 463
    .line 464
    .line 465
    goto :goto_9

    .line 466
    :cond_10
    const v1, 0x1020006

    .line 467
    .line 468
    .line 469
    invoke-virtual {v2, v1}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    .line 470
    .line 471
    .line 472
    move-result-object v1

    .line 473
    check-cast v1, Landroid/widget/ImageView;

    .line 474
    .line 475
    iput-object v1, v0, Lh/d;->s:Landroid/widget/ImageView;

    .line 476
    .line 477
    iget-object v1, v0, Lh/d;->d:Ljava/lang/CharSequence;

    .line 478
    .line 479
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 480
    .line 481
    .line 482
    move-result v1

    .line 483
    if-nez v1, :cond_12

    .line 484
    .line 485
    iget-boolean v1, v0, Lh/d;->C:Z

    .line 486
    .line 487
    if-eqz v1, :cond_12

    .line 488
    .line 489
    const v1, 0x7f0a004a

    .line 490
    .line 491
    .line 492
    invoke-virtual {v2, v1}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    .line 493
    .line 494
    .line 495
    move-result-object v1

    .line 496
    check-cast v1, Landroid/widget/TextView;

    .line 497
    .line 498
    iput-object v1, v0, Lh/d;->t:Landroid/widget/TextView;

    .line 499
    .line 500
    iget-object v7, v0, Lh/d;->d:Ljava/lang/CharSequence;

    .line 501
    .line 502
    invoke-virtual {v1, v7}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 503
    .line 504
    .line 505
    iget-object v1, v0, Lh/d;->r:Landroid/graphics/drawable/Drawable;

    .line 506
    .line 507
    if-eqz v1, :cond_11

    .line 508
    .line 509
    iget-object v7, v0, Lh/d;->s:Landroid/widget/ImageView;

    .line 510
    .line 511
    invoke-virtual {v7, v1}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 512
    .line 513
    .line 514
    goto :goto_9

    .line 515
    :cond_11
    iget-object v1, v0, Lh/d;->t:Landroid/widget/TextView;

    .line 516
    .line 517
    iget-object v7, v0, Lh/d;->s:Landroid/widget/ImageView;

    .line 518
    .line 519
    invoke-virtual {v7}, Landroid/view/View;->getPaddingLeft()I

    .line 520
    .line 521
    .line 522
    move-result v7

    .line 523
    iget-object v9, v0, Lh/d;->s:Landroid/widget/ImageView;

    .line 524
    .line 525
    invoke-virtual {v9}, Landroid/view/View;->getPaddingTop()I

    .line 526
    .line 527
    .line 528
    move-result v9

    .line 529
    iget-object v10, v0, Lh/d;->s:Landroid/widget/ImageView;

    .line 530
    .line 531
    invoke-virtual {v10}, Landroid/view/View;->getPaddingRight()I

    .line 532
    .line 533
    .line 534
    move-result v10

    .line 535
    iget-object v12, v0, Lh/d;->s:Landroid/widget/ImageView;

    .line 536
    .line 537
    invoke-virtual {v12}, Landroid/view/View;->getPaddingBottom()I

    .line 538
    .line 539
    .line 540
    move-result v12

    .line 541
    invoke-virtual {v1, v7, v9, v10, v12}, Landroid/widget/TextView;->setPadding(IIII)V

    .line 542
    .line 543
    .line 544
    iget-object v1, v0, Lh/d;->s:Landroid/widget/ImageView;

    .line 545
    .line 546
    invoke-virtual {v1, v15}, Landroid/widget/ImageView;->setVisibility(I)V

    .line 547
    .line 548
    .line 549
    goto :goto_9

    .line 550
    :cond_12
    invoke-virtual {v2, v7}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    .line 551
    .line 552
    .line 553
    move-result-object v1

    .line 554
    invoke-virtual {v1, v15}, Landroid/view/View;->setVisibility(I)V

    .line 555
    .line 556
    .line 557
    iget-object v1, v0, Lh/d;->s:Landroid/widget/ImageView;

    .line 558
    .line 559
    invoke-virtual {v1, v15}, Landroid/widget/ImageView;->setVisibility(I)V

    .line 560
    .line 561
    .line 562
    invoke-virtual {v4, v15}, Landroid/view/View;->setVisibility(I)V

    .line 563
    .line 564
    .line 565
    :goto_9
    invoke-virtual {v3}, Landroid/view/View;->getVisibility()I

    .line 566
    .line 567
    .line 568
    move-result v1

    .line 569
    if-eq v1, v15, :cond_13

    .line 570
    .line 571
    const/4 v10, 0x1

    .line 572
    goto :goto_a

    .line 573
    :cond_13
    move v10, v13

    .line 574
    :goto_a
    if-eqz v4, :cond_14

    .line 575
    .line 576
    invoke-virtual {v4}, Landroid/view/View;->getVisibility()I

    .line 577
    .line 578
    .line 579
    move-result v1

    .line 580
    if-eq v1, v15, :cond_14

    .line 581
    .line 582
    const/4 v1, 0x1

    .line 583
    goto :goto_b

    .line 584
    :cond_14
    move v1, v13

    .line 585
    :goto_b
    invoke-virtual {v6}, Landroid/view/View;->getVisibility()I

    .line 586
    .line 587
    .line 588
    move-result v3

    .line 589
    if-eq v3, v15, :cond_15

    .line 590
    .line 591
    const/4 v3, 0x1

    .line 592
    goto :goto_c

    .line 593
    :cond_15
    move v3, v13

    .line 594
    :goto_c
    if-nez v3, :cond_16

    .line 595
    .line 596
    const v6, 0x7f0a02d6

    .line 597
    .line 598
    .line 599
    invoke-virtual {v5, v6}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 600
    .line 601
    .line 602
    move-result-object v6

    .line 603
    if-eqz v6, :cond_16

    .line 604
    .line 605
    invoke-virtual {v6, v13}, Landroid/view/View;->setVisibility(I)V

    .line 606
    .line 607
    .line 608
    :cond_16
    if-eqz v1, :cond_19

    .line 609
    .line 610
    iget-object v6, v0, Lh/d;->q:Landroidx/core/widget/NestedScrollView;

    .line 611
    .line 612
    if-eqz v6, :cond_17

    .line 613
    .line 614
    const/4 v7, 0x1

    .line 615
    invoke-virtual {v6, v7}, Landroid/view/ViewGroup;->setClipToPadding(Z)V

    .line 616
    .line 617
    .line 618
    :cond_17
    iget-object v6, v0, Lh/d;->e:Landroidx/appcompat/app/AlertController$RecycleListView;

    .line 619
    .line 620
    if-eqz v6, :cond_18

    .line 621
    .line 622
    const v6, 0x7f0a02e6

    .line 623
    .line 624
    .line 625
    invoke-virtual {v4, v6}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 626
    .line 627
    .line 628
    move-result-object v4

    .line 629
    goto :goto_d

    .line 630
    :cond_18
    const/4 v4, 0x0

    .line 631
    :goto_d
    if-eqz v4, :cond_1a

    .line 632
    .line 633
    invoke-virtual {v4, v13}, Landroid/view/View;->setVisibility(I)V

    .line 634
    .line 635
    .line 636
    goto :goto_e

    .line 637
    :cond_19
    const v4, 0x7f0a02d7

    .line 638
    .line 639
    .line 640
    invoke-virtual {v5, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 641
    .line 642
    .line 643
    move-result-object v4

    .line 644
    if-eqz v4, :cond_1a

    .line 645
    .line 646
    invoke-virtual {v4, v13}, Landroid/view/View;->setVisibility(I)V

    .line 647
    .line 648
    .line 649
    :cond_1a
    :goto_e
    iget-object v4, v0, Lh/d;->e:Landroidx/appcompat/app/AlertController$RecycleListView;

    .line 650
    .line 651
    if-eqz v4, :cond_1e

    .line 652
    .line 653
    if-eqz v3, :cond_1b

    .line 654
    .line 655
    if-nez v1, :cond_1e

    .line 656
    .line 657
    :cond_1b
    invoke-virtual {v4}, Landroid/view/View;->getPaddingLeft()I

    .line 658
    .line 659
    .line 660
    move-result v6

    .line 661
    if-eqz v1, :cond_1c

    .line 662
    .line 663
    invoke-virtual {v4}, Landroid/view/View;->getPaddingTop()I

    .line 664
    .line 665
    .line 666
    move-result v7

    .line 667
    goto :goto_f

    .line 668
    :cond_1c
    iget v7, v4, Landroidx/appcompat/app/AlertController$RecycleListView;->d:I

    .line 669
    .line 670
    :goto_f
    invoke-virtual {v4}, Landroid/view/View;->getPaddingRight()I

    .line 671
    .line 672
    .line 673
    move-result v9

    .line 674
    if-eqz v3, :cond_1d

    .line 675
    .line 676
    invoke-virtual {v4}, Landroid/view/View;->getPaddingBottom()I

    .line 677
    .line 678
    .line 679
    move-result v12

    .line 680
    goto :goto_10

    .line 681
    :cond_1d
    iget v12, v4, Landroidx/appcompat/app/AlertController$RecycleListView;->e:I

    .line 682
    .line 683
    :goto_10
    invoke-virtual {v4, v6, v7, v9, v12}, Landroid/view/View;->setPadding(IIII)V

    .line 684
    .line 685
    .line 686
    :cond_1e
    if-nez v10, :cond_22

    .line 687
    .line 688
    iget-object v4, v0, Lh/d;->e:Landroidx/appcompat/app/AlertController$RecycleListView;

    .line 689
    .line 690
    if-eqz v4, :cond_1f

    .line 691
    .line 692
    goto :goto_11

    .line 693
    :cond_1f
    iget-object v4, v0, Lh/d;->q:Landroidx/core/widget/NestedScrollView;

    .line 694
    .line 695
    :goto_11
    if-eqz v4, :cond_22

    .line 696
    .line 697
    if-eqz v3, :cond_20

    .line 698
    .line 699
    move v13, v8

    .line 700
    :cond_20
    or-int/2addr v1, v13

    .line 701
    const v3, 0x7f0a0281

    .line 702
    .line 703
    .line 704
    invoke-virtual {v2, v3}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    .line 705
    .line 706
    .line 707
    move-result-object v3

    .line 708
    const v6, 0x7f0a0280

    .line 709
    .line 710
    .line 711
    invoke-virtual {v2, v6}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    .line 712
    .line 713
    .line 714
    move-result-object v2

    .line 715
    sget-object v6, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 716
    .line 717
    const/4 v6, 0x3

    .line 718
    invoke-static {v4, v1, v6}, Ld6/l0;->b(Landroid/view/View;II)V

    .line 719
    .line 720
    .line 721
    if-eqz v3, :cond_21

    .line 722
    .line 723
    invoke-virtual {v5, v3}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 724
    .line 725
    .line 726
    :cond_21
    if-eqz v2, :cond_22

    .line 727
    .line 728
    invoke-virtual {v5, v2}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 729
    .line 730
    .line 731
    :cond_22
    iget-object v1, v0, Lh/d;->e:Landroidx/appcompat/app/AlertController$RecycleListView;

    .line 732
    .line 733
    if-eqz v1, :cond_23

    .line 734
    .line 735
    iget-object v2, v0, Lh/d;->w:Landroid/widget/ListAdapter;

    .line 736
    .line 737
    if-eqz v2, :cond_23

    .line 738
    .line 739
    invoke-virtual {v1, v2}, Landroid/widget/ListView;->setAdapter(Landroid/widget/ListAdapter;)V

    .line 740
    .line 741
    .line 742
    iget v0, v0, Lh/d;->x:I

    .line 743
    .line 744
    if-le v0, v11, :cond_23

    .line 745
    .line 746
    const/4 v7, 0x1

    .line 747
    invoke-virtual {v1, v0, v7}, Landroid/widget/AbsListView;->setItemChecked(IZ)V

    .line 748
    .line 749
    .line 750
    invoke-virtual {v1, v0}, Landroid/widget/ListView;->setSelection(I)V

    .line 751
    .line 752
    .line 753
    :cond_23
    return-void
.end method

.method public final onKeyDown(ILandroid/view/KeyEvent;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lh/f;->i:Lh/d;

    .line 2
    .line 3
    iget-object v0, v0, Lh/d;->q:Landroidx/core/widget/NestedScrollView;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0, p2}, Landroidx/core/widget/NestedScrollView;->j(Landroid/view/KeyEvent;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    invoke-super {p0, p1, p2}, Landroid/app/Dialog;->onKeyDown(ILandroid/view/KeyEvent;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public final onKeyUp(ILandroid/view/KeyEvent;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lh/f;->i:Lh/d;

    .line 2
    .line 3
    iget-object v0, v0, Lh/d;->q:Landroidx/core/widget/NestedScrollView;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0, p2}, Landroidx/core/widget/NestedScrollView;->j(Landroid/view/KeyEvent;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    invoke-super {p0, p1, p2}, Landroid/app/Dialog;->onKeyUp(ILandroid/view/KeyEvent;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public final onStop()V
    .locals 1

    .line 1
    invoke-super {p0}, Lb/t;->onStop()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lh/z;

    .line 9
    .line 10
    invoke-virtual {p0}, Lh/z;->E()V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lh/z;->r:Lh/i0;

    .line 14
    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-boolean v0, p0, Lh/i0;->t:Z

    .line 19
    .line 20
    iget-object p0, p0, Lh/i0;->s:Lk/j;

    .line 21
    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Lk/j;->a()V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method public final setContentView(I)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lb/t;->b()V

    .line 2
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    move-result-object p0

    invoke-virtual {p0, p1}, Lh/n;->k(I)V

    return-void
.end method

.method public final setContentView(Landroid/view/View;)V
    .locals 0

    .line 3
    invoke-virtual {p0}, Lb/t;->b()V

    .line 4
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    move-result-object p0

    invoke-virtual {p0, p1}, Lh/n;->n(Landroid/view/View;)V

    return-void
.end method

.method public final setContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 0

    .line 5
    invoke-virtual {p0}, Lb/t;->b()V

    .line 6
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    move-result-object p0

    invoke-virtual {p0, p1, p2}, Lh/n;->o(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    return-void
.end method

.method public final setTitle(I)V
    .locals 1

    .line 1
    invoke-super {p0, p1}, Landroid/app/Dialog;->setTitle(I)V

    .line 2
    invoke-virtual {p0}, Lh/f;->c()Lh/n;

    move-result-object v0

    invoke-virtual {p0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    move-result-object p0

    invoke-virtual {p0, p1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0}, Lh/n;->p(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public final setTitle(Ljava/lang/CharSequence;)V
    .locals 0

    .line 3
    invoke-virtual {p0, p1}, Lh/f;->f(Ljava/lang/CharSequence;)V

    .line 4
    iget-object p0, p0, Lh/f;->i:Lh/d;

    iput-object p1, p0, Lh/d;->d:Ljava/lang/CharSequence;

    .line 5
    iget-object p0, p0, Lh/d;->t:Landroid/widget/TextView;

    if-eqz p0, :cond_0

    .line 6
    invoke-virtual {p0, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    :cond_0
    return-void
.end method
