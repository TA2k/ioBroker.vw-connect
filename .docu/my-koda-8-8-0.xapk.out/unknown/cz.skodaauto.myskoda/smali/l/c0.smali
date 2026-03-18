.class public final Ll/c0;
.super Ll/t;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/widget/PopupWindow$OnDismissListener;
.implements Landroid/view/View$OnKeyListener;


# instance fields
.field public final e:Landroid/content/Context;

.field public final f:Ll/l;

.field public final g:Ll/i;

.field public final h:Z

.field public final i:I

.field public final j:I

.field public final k:Lm/e2;

.field public final l:Ll/d;

.field public final m:Le3/d;

.field public n:Landroid/widget/PopupWindow$OnDismissListener;

.field public o:Landroid/view/View;

.field public p:Landroid/view/View;

.field public q:Ll/w;

.field public r:Landroid/view/ViewTreeObserver;

.field public s:Z

.field public t:Z

.field public u:I

.field public v:I

.field public w:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Ll/l;Landroid/view/View;IZ)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ll/d;

    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    invoke-direct {v0, p0, v1}, Ll/d;-><init>(Ljava/lang/Object;I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Ll/c0;->l:Ll/d;

    .line 11
    .line 12
    new-instance v0, Le3/d;

    .line 13
    .line 14
    const/4 v1, 0x4

    .line 15
    invoke-direct {v0, p0, v1}, Le3/d;-><init>(Ljava/lang/Object;I)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Ll/c0;->m:Le3/d;

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    iput v0, p0, Ll/c0;->v:I

    .line 22
    .line 23
    iput-object p1, p0, Ll/c0;->e:Landroid/content/Context;

    .line 24
    .line 25
    iput-object p2, p0, Ll/c0;->f:Ll/l;

    .line 26
    .line 27
    iput-boolean p5, p0, Ll/c0;->h:Z

    .line 28
    .line 29
    invoke-static {p1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    new-instance v2, Ll/i;

    .line 34
    .line 35
    const v3, 0x7f0d0013

    .line 36
    .line 37
    .line 38
    invoke-direct {v2, p2, v1, p5, v3}, Ll/i;-><init>(Ll/l;Landroid/view/LayoutInflater;ZI)V

    .line 39
    .line 40
    .line 41
    iput-object v2, p0, Ll/c0;->g:Ll/i;

    .line 42
    .line 43
    iput p4, p0, Ll/c0;->j:I

    .line 44
    .line 45
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 46
    .line 47
    .line 48
    move-result-object p5

    .line 49
    invoke-virtual {p5}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    iget v1, v1, Landroid/util/DisplayMetrics;->widthPixels:I

    .line 54
    .line 55
    div-int/lit8 v1, v1, 0x2

    .line 56
    .line 57
    const v2, 0x7f070017

    .line 58
    .line 59
    .line 60
    invoke-virtual {p5, v2}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 61
    .line 62
    .line 63
    move-result p5

    .line 64
    invoke-static {v1, p5}, Ljava/lang/Math;->max(II)I

    .line 65
    .line 66
    .line 67
    move-result p5

    .line 68
    iput p5, p0, Ll/c0;->i:I

    .line 69
    .line 70
    iput-object p3, p0, Ll/c0;->o:Landroid/view/View;

    .line 71
    .line 72
    new-instance p3, Lm/e2;

    .line 73
    .line 74
    const/4 p5, 0x0

    .line 75
    invoke-direct {p3, p1, p5, p4, v0}, Lm/z1;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V

    .line 76
    .line 77
    .line 78
    iput-object p3, p0, Ll/c0;->k:Lm/e2;

    .line 79
    .line 80
    invoke-virtual {p2, p0, p1}, Ll/l;->b(Ll/x;Landroid/content/Context;)V

    .line 81
    .line 82
    .line 83
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Ll/c0;->s:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Ll/c0;->k:Lm/e2;

    .line 6
    .line 7
    iget-object p0, p0, Lm/z1;->C:Lm/z;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/widget/PopupWindow;->isShowing()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final b()V
    .locals 7

    .line 1
    invoke-virtual {p0}, Ll/c0;->a()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget-boolean v0, p0, Ll/c0;->s:Z

    .line 9
    .line 10
    if-nez v0, :cond_7

    .line 11
    .line 12
    iget-object v0, p0, Ll/c0;->o:Landroid/view/View;

    .line 13
    .line 14
    if-eqz v0, :cond_7

    .line 15
    .line 16
    iput-object v0, p0, Ll/c0;->p:Landroid/view/View;

    .line 17
    .line 18
    iget-object v0, p0, Ll/c0;->k:Lm/e2;

    .line 19
    .line 20
    iget-object v1, v0, Lm/z1;->C:Lm/z;

    .line 21
    .line 22
    iget-object v2, v0, Lm/z1;->C:Lm/z;

    .line 23
    .line 24
    invoke-virtual {v1, p0}, Landroid/widget/PopupWindow;->setOnDismissListener(Landroid/widget/PopupWindow$OnDismissListener;)V

    .line 25
    .line 26
    .line 27
    iput-object p0, v0, Lm/z1;->s:Landroid/widget/AdapterView$OnItemClickListener;

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    iput-boolean v1, v0, Lm/z1;->B:Z

    .line 31
    .line 32
    invoke-virtual {v2, v1}, Landroid/widget/PopupWindow;->setFocusable(Z)V

    .line 33
    .line 34
    .line 35
    iget-object v3, p0, Ll/c0;->p:Landroid/view/View;

    .line 36
    .line 37
    iget-object v4, p0, Ll/c0;->r:Landroid/view/ViewTreeObserver;

    .line 38
    .line 39
    const/4 v5, 0x0

    .line 40
    if-nez v4, :cond_1

    .line 41
    .line 42
    move v4, v1

    .line 43
    goto :goto_0

    .line 44
    :cond_1
    move v4, v5

    .line 45
    :goto_0
    invoke-virtual {v3}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 46
    .line 47
    .line 48
    move-result-object v6

    .line 49
    iput-object v6, p0, Ll/c0;->r:Landroid/view/ViewTreeObserver;

    .line 50
    .line 51
    if-eqz v4, :cond_2

    .line 52
    .line 53
    iget-object v4, p0, Ll/c0;->l:Ll/d;

    .line 54
    .line 55
    invoke-virtual {v6, v4}, Landroid/view/ViewTreeObserver;->addOnGlobalLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    .line 56
    .line 57
    .line 58
    :cond_2
    iget-object v4, p0, Ll/c0;->m:Le3/d;

    .line 59
    .line 60
    invoke-virtual {v3, v4}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 61
    .line 62
    .line 63
    iput-object v3, v0, Lm/z1;->r:Landroid/view/View;

    .line 64
    .line 65
    iget v3, p0, Ll/c0;->v:I

    .line 66
    .line 67
    iput v3, v0, Lm/z1;->o:I

    .line 68
    .line 69
    iget-boolean v3, p0, Ll/c0;->t:Z

    .line 70
    .line 71
    iget-object v4, p0, Ll/c0;->e:Landroid/content/Context;

    .line 72
    .line 73
    iget-object v6, p0, Ll/c0;->g:Ll/i;

    .line 74
    .line 75
    if-nez v3, :cond_3

    .line 76
    .line 77
    iget v3, p0, Ll/c0;->i:I

    .line 78
    .line 79
    invoke-static {v6, v4, v3}, Ll/t;->l(Landroid/widget/ListAdapter;Landroid/content/Context;I)I

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    iput v3, p0, Ll/c0;->u:I

    .line 84
    .line 85
    iput-boolean v1, p0, Ll/c0;->t:Z

    .line 86
    .line 87
    :cond_3
    iget v1, p0, Ll/c0;->u:I

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Lm/z1;->r(I)V

    .line 90
    .line 91
    .line 92
    const/4 v1, 0x2

    .line 93
    invoke-virtual {v2, v1}, Landroid/widget/PopupWindow;->setInputMethodMode(I)V

    .line 94
    .line 95
    .line 96
    iget-object v1, p0, Ll/t;->d:Landroid/graphics/Rect;

    .line 97
    .line 98
    const/4 v2, 0x0

    .line 99
    if-eqz v1, :cond_4

    .line 100
    .line 101
    new-instance v3, Landroid/graphics/Rect;

    .line 102
    .line 103
    invoke-direct {v3, v1}, Landroid/graphics/Rect;-><init>(Landroid/graphics/Rect;)V

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_4
    move-object v3, v2

    .line 108
    :goto_1
    iput-object v3, v0, Lm/z1;->A:Landroid/graphics/Rect;

    .line 109
    .line 110
    invoke-virtual {v0}, Lm/z1;->b()V

    .line 111
    .line 112
    .line 113
    iget-object v1, v0, Lm/z1;->f:Lm/m1;

    .line 114
    .line 115
    invoke-virtual {v1, p0}, Landroid/view/View;->setOnKeyListener(Landroid/view/View$OnKeyListener;)V

    .line 116
    .line 117
    .line 118
    iget-boolean v3, p0, Ll/c0;->w:Z

    .line 119
    .line 120
    if-eqz v3, :cond_6

    .line 121
    .line 122
    iget-object p0, p0, Ll/c0;->f:Ll/l;

    .line 123
    .line 124
    iget-object v3, p0, Ll/l;->m:Ljava/lang/CharSequence;

    .line 125
    .line 126
    if-eqz v3, :cond_6

    .line 127
    .line 128
    invoke-static {v4}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 129
    .line 130
    .line 131
    move-result-object v3

    .line 132
    const v4, 0x7f0d0012

    .line 133
    .line 134
    .line 135
    invoke-virtual {v3, v4, v1, v5}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    .line 136
    .line 137
    .line 138
    move-result-object v3

    .line 139
    check-cast v3, Landroid/widget/FrameLayout;

    .line 140
    .line 141
    const v4, 0x1020016

    .line 142
    .line 143
    .line 144
    invoke-virtual {v3, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 145
    .line 146
    .line 147
    move-result-object v4

    .line 148
    check-cast v4, Landroid/widget/TextView;

    .line 149
    .line 150
    if-eqz v4, :cond_5

    .line 151
    .line 152
    iget-object p0, p0, Ll/l;->m:Ljava/lang/CharSequence;

    .line 153
    .line 154
    invoke-virtual {v4, p0}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 155
    .line 156
    .line 157
    :cond_5
    invoke-virtual {v3, v5}, Landroid/view/View;->setEnabled(Z)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {v1, v3, v2, v5}, Landroid/widget/ListView;->addHeaderView(Landroid/view/View;Ljava/lang/Object;Z)V

    .line 161
    .line 162
    .line 163
    :cond_6
    invoke-virtual {v0, v6}, Lm/z1;->l(Landroid/widget/ListAdapter;)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {v0}, Lm/z1;->b()V

    .line 167
    .line 168
    .line 169
    return-void

    .line 170
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 171
    .line 172
    const-string v0, "StandardMenuPopup cannot be used without an anchor"

    .line 173
    .line 174
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    throw p0
.end method

.method public final c()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Ll/c0;->t:Z

    .line 3
    .line 4
    iget-object p0, p0, Ll/c0;->g:Ll/i;

    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0}, Ll/i;->notifyDataSetChanged()V

    .line 9
    .line 10
    .line 11
    :cond_0
    return-void
.end method

.method public final d(Ll/l;Z)V
    .locals 1

    .line 1
    iget-object v0, p0, Ll/c0;->f:Ll/l;

    .line 2
    .line 3
    if-eq p1, v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    invoke-virtual {p0}, Ll/c0;->dismiss()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Ll/c0;->q:Ll/w;

    .line 10
    .line 11
    if-eqz p0, :cond_1

    .line 12
    .line 13
    invoke-interface {p0, p1, p2}, Ll/w;->d(Ll/l;Z)V

    .line 14
    .line 15
    .line 16
    :cond_1
    :goto_0
    return-void
.end method

.method public final dismiss()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ll/c0;->a()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Ll/c0;->k:Lm/e2;

    .line 8
    .line 9
    invoke-virtual {p0}, Lm/z1;->dismiss()V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final e(Ll/w;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ll/c0;->q:Ll/w;

    .line 2
    .line 3
    return-void
.end method

.method public final f(Ll/d0;)Z
    .locals 9

    .line 1
    invoke-virtual {p1}, Ll/l;->hasVisibleItems()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_8

    .line 7
    .line 8
    new-instance v2, Ll/v;

    .line 9
    .line 10
    iget-object v5, p0, Ll/c0;->p:Landroid/view/View;

    .line 11
    .line 12
    iget v7, p0, Ll/c0;->j:I

    .line 13
    .line 14
    const/4 v8, 0x0

    .line 15
    iget-object v3, p0, Ll/c0;->e:Landroid/content/Context;

    .line 16
    .line 17
    iget-boolean v6, p0, Ll/c0;->h:Z

    .line 18
    .line 19
    move-object v4, p1

    .line 20
    invoke-direct/range {v2 .. v8}, Ll/v;-><init>(Landroid/content/Context;Ll/l;Landroid/view/View;ZII)V

    .line 21
    .line 22
    .line 23
    iget-object p1, p0, Ll/c0;->q:Ll/w;

    .line 24
    .line 25
    iput-object p1, v2, Ll/v;->h:Ll/w;

    .line 26
    .line 27
    iget-object v0, v2, Ll/v;->i:Ll/t;

    .line 28
    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    invoke-interface {v0, p1}, Ll/x;->e(Ll/w;)V

    .line 32
    .line 33
    .line 34
    :cond_0
    iget-object p1, v4, Ll/l;->f:Ljava/util/ArrayList;

    .line 35
    .line 36
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    move v0, v1

    .line 41
    :goto_0
    const/4 v3, 0x1

    .line 42
    if-ge v0, p1, :cond_2

    .line 43
    .line 44
    invoke-virtual {v4, v0}, Ll/l;->getItem(I)Landroid/view/MenuItem;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    invoke-interface {v5}, Landroid/view/MenuItem;->isVisible()Z

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    if-eqz v6, :cond_1

    .line 53
    .line 54
    invoke-interface {v5}, Landroid/view/MenuItem;->getIcon()Landroid/graphics/drawable/Drawable;

    .line 55
    .line 56
    .line 57
    move-result-object v5

    .line 58
    if-eqz v5, :cond_1

    .line 59
    .line 60
    move p1, v3

    .line 61
    goto :goto_1

    .line 62
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_2
    move p1, v1

    .line 66
    :goto_1
    iput-boolean p1, v2, Ll/v;->g:Z

    .line 67
    .line 68
    iget-object v0, v2, Ll/v;->i:Ll/t;

    .line 69
    .line 70
    if-eqz v0, :cond_3

    .line 71
    .line 72
    invoke-virtual {v0, p1}, Ll/t;->o(Z)V

    .line 73
    .line 74
    .line 75
    :cond_3
    iget-object p1, p0, Ll/c0;->n:Landroid/widget/PopupWindow$OnDismissListener;

    .line 76
    .line 77
    iput-object p1, v2, Ll/v;->j:Landroid/widget/PopupWindow$OnDismissListener;

    .line 78
    .line 79
    const/4 p1, 0x0

    .line 80
    iput-object p1, p0, Ll/c0;->n:Landroid/widget/PopupWindow$OnDismissListener;

    .line 81
    .line 82
    iget-object p1, p0, Ll/c0;->f:Ll/l;

    .line 83
    .line 84
    invoke-virtual {p1, v1}, Ll/l;->c(Z)V

    .line 85
    .line 86
    .line 87
    iget-object p1, p0, Ll/c0;->k:Lm/e2;

    .line 88
    .line 89
    iget v0, p1, Lm/z1;->i:I

    .line 90
    .line 91
    invoke-virtual {p1}, Lm/z1;->k()I

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    iget v5, p0, Ll/c0;->v:I

    .line 96
    .line 97
    iget-object v6, p0, Ll/c0;->o:Landroid/view/View;

    .line 98
    .line 99
    invoke-virtual {v6}, Landroid/view/View;->getLayoutDirection()I

    .line 100
    .line 101
    .line 102
    move-result v6

    .line 103
    invoke-static {v5, v6}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 104
    .line 105
    .line 106
    move-result v5

    .line 107
    and-int/lit8 v5, v5, 0x7

    .line 108
    .line 109
    const/4 v6, 0x5

    .line 110
    if-ne v5, v6, :cond_4

    .line 111
    .line 112
    iget-object v5, p0, Ll/c0;->o:Landroid/view/View;

    .line 113
    .line 114
    invoke-virtual {v5}, Landroid/view/View;->getWidth()I

    .line 115
    .line 116
    .line 117
    move-result v5

    .line 118
    add-int/2addr v0, v5

    .line 119
    :cond_4
    invoke-virtual {v2}, Ll/v;->b()Z

    .line 120
    .line 121
    .line 122
    move-result v5

    .line 123
    if-eqz v5, :cond_5

    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_5
    iget-object v5, v2, Ll/v;->e:Landroid/view/View;

    .line 127
    .line 128
    if-nez v5, :cond_6

    .line 129
    .line 130
    goto :goto_3

    .line 131
    :cond_6
    invoke-virtual {v2, v0, p1, v3, v3}, Ll/v;->d(IIZZ)V

    .line 132
    .line 133
    .line 134
    :goto_2
    iget-object p0, p0, Ll/c0;->q:Ll/w;

    .line 135
    .line 136
    if-eqz p0, :cond_7

    .line 137
    .line 138
    invoke-interface {p0, v4}, Ll/w;->f(Ll/l;)Z

    .line 139
    .line 140
    .line 141
    :cond_7
    return v3

    .line 142
    :cond_8
    :goto_3
    return v1
.end method

.method public final i()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final k(Ll/l;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final m(Landroid/view/View;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ll/c0;->o:Landroid/view/View;

    .line 2
    .line 3
    return-void
.end method

.method public final n()Lm/m1;
    .locals 0

    .line 1
    iget-object p0, p0, Ll/c0;->k:Lm/e2;

    .line 2
    .line 3
    iget-object p0, p0, Lm/z1;->f:Lm/m1;

    .line 4
    .line 5
    return-object p0
.end method

.method public final o(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Ll/c0;->g:Ll/i;

    .line 2
    .line 3
    iput-boolean p1, p0, Ll/i;->c:Z

    .line 4
    .line 5
    return-void
.end method

.method public final onDismiss()V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Ll/c0;->s:Z

    .line 3
    .line 4
    iget-object v1, p0, Ll/c0;->f:Ll/l;

    .line 5
    .line 6
    invoke-virtual {v1, v0}, Ll/l;->c(Z)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Ll/c0;->r:Landroid/view/ViewTreeObserver;

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {v0}, Landroid/view/ViewTreeObserver;->isAlive()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    iget-object v0, p0, Ll/c0;->p:Landroid/view/View;

    .line 20
    .line 21
    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iput-object v0, p0, Ll/c0;->r:Landroid/view/ViewTreeObserver;

    .line 26
    .line 27
    :cond_0
    iget-object v0, p0, Ll/c0;->r:Landroid/view/ViewTreeObserver;

    .line 28
    .line 29
    iget-object v1, p0, Ll/c0;->l:Ll/d;

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->removeGlobalOnLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    .line 32
    .line 33
    .line 34
    const/4 v0, 0x0

    .line 35
    iput-object v0, p0, Ll/c0;->r:Landroid/view/ViewTreeObserver;

    .line 36
    .line 37
    :cond_1
    iget-object v0, p0, Ll/c0;->p:Landroid/view/View;

    .line 38
    .line 39
    iget-object v1, p0, Ll/c0;->m:Le3/d;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Ll/c0;->n:Landroid/widget/PopupWindow$OnDismissListener;

    .line 45
    .line 46
    if-eqz p0, :cond_2

    .line 47
    .line 48
    invoke-interface {p0}, Landroid/widget/PopupWindow$OnDismissListener;->onDismiss()V

    .line 49
    .line 50
    .line 51
    :cond_2
    return-void
.end method

.method public final onKey(Landroid/view/View;ILandroid/view/KeyEvent;)Z
    .locals 0

    .line 1
    invoke-virtual {p3}, Landroid/view/KeyEvent;->getAction()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 p3, 0x1

    .line 6
    if-ne p1, p3, :cond_0

    .line 7
    .line 8
    const/16 p1, 0x52

    .line 9
    .line 10
    if-ne p2, p1, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0}, Ll/c0;->dismiss()V

    .line 13
    .line 14
    .line 15
    return p3

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return p0
.end method

.method public final p(I)V
    .locals 0

    .line 1
    iput p1, p0, Ll/c0;->v:I

    .line 2
    .line 3
    return-void
.end method

.method public final q(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Ll/c0;->k:Lm/e2;

    .line 2
    .line 3
    iput p1, p0, Lm/z1;->i:I

    .line 4
    .line 5
    return-void
.end method

.method public final r(Landroid/widget/PopupWindow$OnDismissListener;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ll/c0;->n:Landroid/widget/PopupWindow$OnDismissListener;

    .line 2
    .line 3
    return-void
.end method

.method public final s(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Ll/c0;->w:Z

    .line 2
    .line 3
    return-void
.end method

.method public final t(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Ll/c0;->k:Lm/e2;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lm/z1;->h(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
