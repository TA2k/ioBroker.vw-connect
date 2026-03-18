.class public final Ll/f;
.super Ll/t;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnKeyListener;
.implements Landroid/widget/PopupWindow$OnDismissListener;


# instance fields
.field public A:Landroid/view/ViewTreeObserver;

.field public B:Landroid/widget/PopupWindow$OnDismissListener;

.field public C:Z

.field public final e:Landroid/content/Context;

.field public final f:I

.field public final g:I

.field public final h:Z

.field public final i:Landroid/os/Handler;

.field public final j:Ljava/util/ArrayList;

.field public final k:Ljava/util/ArrayList;

.field public final l:Ll/d;

.field public final m:Le3/d;

.field public final n:Lhu/q;

.field public o:I

.field public p:I

.field public q:Landroid/view/View;

.field public r:Landroid/view/View;

.field public s:I

.field public t:Z

.field public u:Z

.field public v:I

.field public w:I

.field public x:Z

.field public y:Z

.field public z:Ll/w;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/view/View;IZ)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ll/f;->j:Ljava/util/ArrayList;

    .line 10
    .line 11
    new-instance v0, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Ll/f;->k:Ljava/util/ArrayList;

    .line 17
    .line 18
    new-instance v0, Ll/d;

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    invoke-direct {v0, p0, v1}, Ll/d;-><init>(Ljava/lang/Object;I)V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Ll/f;->l:Ll/d;

    .line 25
    .line 26
    new-instance v0, Le3/d;

    .line 27
    .line 28
    const/4 v1, 0x3

    .line 29
    invoke-direct {v0, p0, v1}, Le3/d;-><init>(Ljava/lang/Object;I)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Ll/f;->m:Le3/d;

    .line 33
    .line 34
    new-instance v0, Lhu/q;

    .line 35
    .line 36
    const/16 v1, 0xe

    .line 37
    .line 38
    invoke-direct {v0, p0, v1}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    .line 39
    .line 40
    .line 41
    iput-object v0, p0, Ll/f;->n:Lhu/q;

    .line 42
    .line 43
    const/4 v0, 0x0

    .line 44
    iput v0, p0, Ll/f;->o:I

    .line 45
    .line 46
    iput v0, p0, Ll/f;->p:I

    .line 47
    .line 48
    iput-object p1, p0, Ll/f;->e:Landroid/content/Context;

    .line 49
    .line 50
    iput-object p2, p0, Ll/f;->q:Landroid/view/View;

    .line 51
    .line 52
    iput p3, p0, Ll/f;->g:I

    .line 53
    .line 54
    iput-boolean p4, p0, Ll/f;->h:Z

    .line 55
    .line 56
    iput-boolean v0, p0, Ll/f;->x:Z

    .line 57
    .line 58
    invoke-virtual {p2}, Landroid/view/View;->getLayoutDirection()I

    .line 59
    .line 60
    .line 61
    move-result p2

    .line 62
    const/4 p3, 0x1

    .line 63
    if-ne p2, p3, :cond_0

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    move v0, p3

    .line 67
    :goto_0
    iput v0, p0, Ll/f;->s:I

    .line 68
    .line 69
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-virtual {p1}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 74
    .line 75
    .line 76
    move-result-object p2

    .line 77
    iget p2, p2, Landroid/util/DisplayMetrics;->widthPixels:I

    .line 78
    .line 79
    div-int/lit8 p2, p2, 0x2

    .line 80
    .line 81
    const p3, 0x7f070017

    .line 82
    .line 83
    .line 84
    invoke-virtual {p1, p3}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    invoke-static {p2, p1}, Ljava/lang/Math;->max(II)I

    .line 89
    .line 90
    .line 91
    move-result p1

    .line 92
    iput p1, p0, Ll/f;->f:I

    .line 93
    .line 94
    new-instance p1, Landroid/os/Handler;

    .line 95
    .line 96
    invoke-direct {p1}, Landroid/os/Handler;-><init>()V

    .line 97
    .line 98
    .line 99
    iput-object p1, p0, Ll/f;->i:Landroid/os/Handler;

    .line 100
    .line 101
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 2

    .line 1
    iget-object p0, p0, Ll/f;->k:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    if-lez v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ll/e;

    .line 15
    .line 16
    iget-object p0, p0, Ll/e;->a:Lm/e2;

    .line 17
    .line 18
    iget-object p0, p0, Lm/z1;->C:Lm/z;

    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/widget/PopupWindow;->isShowing()Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    if-eqz p0, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x1

    .line 27
    return p0

    .line 28
    :cond_0
    return v1
.end method

.method public final b()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Ll/f;->a()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto :goto_2

    .line 8
    :cond_0
    iget-object v0, p0, Ll/f;->j:Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_1

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Ll/l;

    .line 25
    .line 26
    invoke-virtual {p0, v2}, Ll/f;->u(Ll/l;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Ll/f;->q:Landroid/view/View;

    .line 34
    .line 35
    iput-object v0, p0, Ll/f;->r:Landroid/view/View;

    .line 36
    .line 37
    if-eqz v0, :cond_4

    .line 38
    .line 39
    iget-object v1, p0, Ll/f;->A:Landroid/view/ViewTreeObserver;

    .line 40
    .line 41
    if-nez v1, :cond_2

    .line 42
    .line 43
    const/4 v1, 0x1

    .line 44
    goto :goto_1

    .line 45
    :cond_2
    const/4 v1, 0x0

    .line 46
    :goto_1
    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    iput-object v0, p0, Ll/f;->A:Landroid/view/ViewTreeObserver;

    .line 51
    .line 52
    if-eqz v1, :cond_3

    .line 53
    .line 54
    iget-object v1, p0, Ll/f;->l:Ll/d;

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->addOnGlobalLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    .line 57
    .line 58
    .line 59
    :cond_3
    iget-object v0, p0, Ll/f;->r:Landroid/view/View;

    .line 60
    .line 61
    iget-object p0, p0, Ll/f;->m:Le3/d;

    .line 62
    .line 63
    invoke-virtual {v0, p0}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 64
    .line 65
    .line 66
    :cond_4
    :goto_2
    return-void
.end method

.method public final c()V
    .locals 2

    .line 1
    iget-object p0, p0, Ll/f;->k:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Ll/e;

    .line 18
    .line 19
    iget-object v0, v0, Ll/e;->a:Lm/e2;

    .line 20
    .line 21
    iget-object v0, v0, Lm/z1;->f:Lm/m1;

    .line 22
    .line 23
    invoke-virtual {v0}, Landroid/widget/ListView;->getAdapter()Landroid/widget/ListAdapter;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    instance-of v1, v0, Landroid/widget/HeaderViewListAdapter;

    .line 28
    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    check-cast v0, Landroid/widget/HeaderViewListAdapter;

    .line 32
    .line 33
    invoke-virtual {v0}, Landroid/widget/HeaderViewListAdapter;->getWrappedAdapter()Landroid/widget/ListAdapter;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Ll/i;

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_0
    check-cast v0, Ll/i;

    .line 41
    .line 42
    :goto_1
    invoke-virtual {v0}, Ll/i;->notifyDataSetChanged()V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    return-void
.end method

.method public final d(Ll/l;Z)V
    .locals 6

    .line 1
    iget-object v0, p0, Ll/f;->k:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    move v3, v2

    .line 9
    :goto_0
    if-ge v3, v1, :cond_1

    .line 10
    .line 11
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    check-cast v4, Ll/e;

    .line 16
    .line 17
    iget-object v4, v4, Ll/e;->b:Ll/l;

    .line 18
    .line 19
    if-ne p1, v4, :cond_0

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    const/4 v3, -0x1

    .line 26
    :goto_1
    if-gez v3, :cond_2

    .line 27
    .line 28
    goto/16 :goto_4

    .line 29
    .line 30
    :cond_2
    add-int/lit8 v1, v3, 0x1

    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    if-ge v1, v4, :cond_3

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    check-cast v1, Ll/e;

    .line 43
    .line 44
    iget-object v1, v1, Ll/e;->b:Ll/l;

    .line 45
    .line 46
    invoke-virtual {v1, v2}, Ll/l;->c(Z)V

    .line 47
    .line 48
    .line 49
    :cond_3
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    check-cast v1, Ll/e;

    .line 54
    .line 55
    iget-object v3, v1, Ll/e;->b:Ll/l;

    .line 56
    .line 57
    iget-object v1, v1, Ll/e;->a:Lm/e2;

    .line 58
    .line 59
    iget-object v4, v1, Lm/z1;->C:Lm/z;

    .line 60
    .line 61
    invoke-virtual {v3, p0}, Ll/l;->r(Ll/x;)V

    .line 62
    .line 63
    .line 64
    iget-boolean v3, p0, Ll/f;->C:Z

    .line 65
    .line 66
    const/4 v5, 0x0

    .line 67
    if-eqz v3, :cond_4

    .line 68
    .line 69
    invoke-static {v4, v5}, Lm/b2;->b(Landroid/widget/PopupWindow;Landroid/transition/Transition;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v4, v2}, Landroid/widget/PopupWindow;->setAnimationStyle(I)V

    .line 73
    .line 74
    .line 75
    :cond_4
    invoke-virtual {v1}, Lm/z1;->dismiss()V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    const/4 v3, 0x1

    .line 83
    if-lez v1, :cond_5

    .line 84
    .line 85
    add-int/lit8 v4, v1, -0x1

    .line 86
    .line 87
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    check-cast v4, Ll/e;

    .line 92
    .line 93
    iget v4, v4, Ll/e;->c:I

    .line 94
    .line 95
    iput v4, p0, Ll/f;->s:I

    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_5
    iget-object v4, p0, Ll/f;->q:Landroid/view/View;

    .line 99
    .line 100
    invoke-virtual {v4}, Landroid/view/View;->getLayoutDirection()I

    .line 101
    .line 102
    .line 103
    move-result v4

    .line 104
    if-ne v4, v3, :cond_6

    .line 105
    .line 106
    move v4, v2

    .line 107
    goto :goto_2

    .line 108
    :cond_6
    move v4, v3

    .line 109
    :goto_2
    iput v4, p0, Ll/f;->s:I

    .line 110
    .line 111
    :goto_3
    if-nez v1, :cond_a

    .line 112
    .line 113
    invoke-virtual {p0}, Ll/f;->dismiss()V

    .line 114
    .line 115
    .line 116
    iget-object p2, p0, Ll/f;->z:Ll/w;

    .line 117
    .line 118
    if-eqz p2, :cond_7

    .line 119
    .line 120
    invoke-interface {p2, p1, v3}, Ll/w;->d(Ll/l;Z)V

    .line 121
    .line 122
    .line 123
    :cond_7
    iget-object p1, p0, Ll/f;->A:Landroid/view/ViewTreeObserver;

    .line 124
    .line 125
    if-eqz p1, :cond_9

    .line 126
    .line 127
    invoke-virtual {p1}, Landroid/view/ViewTreeObserver;->isAlive()Z

    .line 128
    .line 129
    .line 130
    move-result p1

    .line 131
    if-eqz p1, :cond_8

    .line 132
    .line 133
    iget-object p1, p0, Ll/f;->A:Landroid/view/ViewTreeObserver;

    .line 134
    .line 135
    iget-object p2, p0, Ll/f;->l:Ll/d;

    .line 136
    .line 137
    invoke-virtual {p1, p2}, Landroid/view/ViewTreeObserver;->removeGlobalOnLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    .line 138
    .line 139
    .line 140
    :cond_8
    iput-object v5, p0, Ll/f;->A:Landroid/view/ViewTreeObserver;

    .line 141
    .line 142
    :cond_9
    iget-object p1, p0, Ll/f;->r:Landroid/view/View;

    .line 143
    .line 144
    iget-object p2, p0, Ll/f;->m:Le3/d;

    .line 145
    .line 146
    invoke-virtual {p1, p2}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 147
    .line 148
    .line 149
    iget-object p0, p0, Ll/f;->B:Landroid/widget/PopupWindow$OnDismissListener;

    .line 150
    .line 151
    invoke-interface {p0}, Landroid/widget/PopupWindow$OnDismissListener;->onDismiss()V

    .line 152
    .line 153
    .line 154
    return-void

    .line 155
    :cond_a
    if-eqz p2, :cond_b

    .line 156
    .line 157
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    check-cast p0, Ll/e;

    .line 162
    .line 163
    iget-object p0, p0, Ll/e;->b:Ll/l;

    .line 164
    .line 165
    invoke-virtual {p0, v2}, Ll/l;->c(Z)V

    .line 166
    .line 167
    .line 168
    :cond_b
    :goto_4
    return-void
.end method

.method public final dismiss()V
    .locals 3

    .line 1
    iget-object p0, p0, Ll/f;->k:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-lez v0, :cond_1

    .line 8
    .line 9
    new-array v1, v0, [Ll/e;

    .line 10
    .line 11
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, [Ll/e;

    .line 16
    .line 17
    add-int/lit8 v0, v0, -0x1

    .line 18
    .line 19
    :goto_0
    if-ltz v0, :cond_1

    .line 20
    .line 21
    aget-object v1, p0, v0

    .line 22
    .line 23
    iget-object v2, v1, Ll/e;->a:Lm/e2;

    .line 24
    .line 25
    iget-object v2, v2, Lm/z1;->C:Lm/z;

    .line 26
    .line 27
    invoke-virtual {v2}, Landroid/widget/PopupWindow;->isShowing()Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-eqz v2, :cond_0

    .line 32
    .line 33
    iget-object v1, v1, Ll/e;->a:Lm/e2;

    .line 34
    .line 35
    invoke-virtual {v1}, Lm/z1;->dismiss()V

    .line 36
    .line 37
    .line 38
    :cond_0
    add-int/lit8 v0, v0, -0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    return-void
.end method

.method public final e(Ll/w;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ll/f;->z:Ll/w;

    .line 2
    .line 3
    return-void
.end method

.method public final f(Ll/d0;)Z
    .locals 4

    .line 1
    iget-object v0, p0, Ll/f;->k:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/4 v2, 0x1

    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    check-cast v1, Ll/e;

    .line 19
    .line 20
    iget-object v3, v1, Ll/e;->b:Ll/l;

    .line 21
    .line 22
    if-ne p1, v3, :cond_0

    .line 23
    .line 24
    iget-object p0, v1, Ll/e;->a:Lm/e2;

    .line 25
    .line 26
    iget-object p0, p0, Lm/z1;->f:Lm/m1;

    .line 27
    .line 28
    invoke-virtual {p0}, Landroid/view/View;->requestFocus()Z

    .line 29
    .line 30
    .line 31
    return v2

    .line 32
    :cond_1
    invoke-virtual {p1}, Ll/l;->hasVisibleItems()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_3

    .line 37
    .line 38
    invoke-virtual {p0, p1}, Ll/f;->k(Ll/l;)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Ll/f;->z:Ll/w;

    .line 42
    .line 43
    if-eqz p0, :cond_2

    .line 44
    .line 45
    invoke-interface {p0, p1}, Ll/w;->f(Ll/l;)Z

    .line 46
    .line 47
    .line 48
    :cond_2
    return v2

    .line 49
    :cond_3
    const/4 p0, 0x0

    .line 50
    return p0
.end method

.method public final i()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final k(Ll/l;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ll/f;->e:Landroid/content/Context;

    .line 2
    .line 3
    invoke-virtual {p1, p0, v0}, Ll/l;->b(Ll/x;Landroid/content/Context;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ll/f;->a()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ll/f;->u(Ll/l;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    iget-object p0, p0, Ll/f;->j:Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final m(Landroid/view/View;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ll/f;->q:Landroid/view/View;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Ll/f;->q:Landroid/view/View;

    .line 6
    .line 7
    iget v0, p0, Ll/f;->o:I

    .line 8
    .line 9
    invoke-virtual {p1}, Landroid/view/View;->getLayoutDirection()I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    invoke-static {v0, p1}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    iput p1, p0, Ll/f;->p:I

    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public final n()Lm/m1;
    .locals 1

    .line 1
    iget-object p0, p0, Ll/f;->k:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return-object p0

    .line 11
    :cond_0
    const/4 v0, 0x1

    .line 12
    invoke-static {p0, v0}, Lkx/a;->f(Ljava/util/ArrayList;I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Ll/e;

    .line 17
    .line 18
    iget-object p0, p0, Ll/e;->a:Lm/e2;

    .line 19
    .line 20
    iget-object p0, p0, Lm/z1;->f:Lm/m1;

    .line 21
    .line 22
    return-object p0
.end method

.method public final o(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Ll/f;->x:Z

    .line 2
    .line 3
    return-void
.end method

.method public final onDismiss()V
    .locals 5

    .line 1
    iget-object p0, p0, Ll/f;->k:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    move v2, v1

    .line 9
    :goto_0
    if-ge v2, v0, :cond_1

    .line 10
    .line 11
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    check-cast v3, Ll/e;

    .line 16
    .line 17
    iget-object v4, v3, Ll/e;->a:Lm/e2;

    .line 18
    .line 19
    iget-object v4, v4, Lm/z1;->C:Lm/z;

    .line 20
    .line 21
    invoke-virtual {v4}, Landroid/widget/PopupWindow;->isShowing()Z

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    if-nez v4, :cond_0

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    const/4 v3, 0x0

    .line 32
    :goto_1
    if-eqz v3, :cond_2

    .line 33
    .line 34
    iget-object p0, v3, Ll/e;->b:Ll/l;

    .line 35
    .line 36
    invoke-virtual {p0, v1}, Ll/l;->c(Z)V

    .line 37
    .line 38
    .line 39
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
    invoke-virtual {p0}, Ll/f;->dismiss()V

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
    .locals 1

    .line 1
    iget v0, p0, Ll/f;->o:I

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput p1, p0, Ll/f;->o:I

    .line 6
    .line 7
    iget-object v0, p0, Ll/f;->q:Landroid/view/View;

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/view/View;->getLayoutDirection()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-static {p1, v0}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    iput p1, p0, Ll/f;->p:I

    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public final q(I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Ll/f;->t:Z

    .line 3
    .line 4
    iput p1, p0, Ll/f;->v:I

    .line 5
    .line 6
    return-void
.end method

.method public final r(Landroid/widget/PopupWindow$OnDismissListener;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ll/f;->B:Landroid/widget/PopupWindow$OnDismissListener;

    .line 2
    .line 3
    return-void
.end method

.method public final s(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Ll/f;->y:Z

    .line 2
    .line 3
    return-void
.end method

.method public final t(I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Ll/f;->u:Z

    .line 3
    .line 4
    iput p1, p0, Ll/f;->w:I

    .line 5
    .line 6
    return-void
.end method

.method public final u(Ll/l;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Ll/f;->e:Landroid/content/Context;

    .line 6
    .line 7
    invoke-static {v2}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    new-instance v4, Ll/i;

    .line 12
    .line 13
    iget-boolean v5, v0, Ll/f;->h:Z

    .line 14
    .line 15
    const v6, 0x7f0d000b

    .line 16
    .line 17
    .line 18
    invoke-direct {v4, v1, v3, v5, v6}, Ll/i;-><init>(Ll/l;Landroid/view/LayoutInflater;ZI)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ll/f;->a()Z

    .line 22
    .line 23
    .line 24
    move-result v5

    .line 25
    const/4 v6, 0x0

    .line 26
    const/4 v7, 0x1

    .line 27
    if-nez v5, :cond_0

    .line 28
    .line 29
    iget-boolean v5, v0, Ll/f;->x:Z

    .line 30
    .line 31
    if-eqz v5, :cond_0

    .line 32
    .line 33
    iput-boolean v7, v4, Ll/i;->c:Z

    .line 34
    .line 35
    goto :goto_2

    .line 36
    :cond_0
    invoke-virtual {v0}, Ll/f;->a()Z

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    if-eqz v5, :cond_3

    .line 41
    .line 42
    iget-object v5, v1, Ll/l;->f:Ljava/util/ArrayList;

    .line 43
    .line 44
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 45
    .line 46
    .line 47
    move-result v5

    .line 48
    move v8, v6

    .line 49
    :goto_0
    if-ge v8, v5, :cond_2

    .line 50
    .line 51
    invoke-virtual {v1, v8}, Ll/l;->getItem(I)Landroid/view/MenuItem;

    .line 52
    .line 53
    .line 54
    move-result-object v9

    .line 55
    invoke-interface {v9}, Landroid/view/MenuItem;->isVisible()Z

    .line 56
    .line 57
    .line 58
    move-result v10

    .line 59
    if-eqz v10, :cond_1

    .line 60
    .line 61
    invoke-interface {v9}, Landroid/view/MenuItem;->getIcon()Landroid/graphics/drawable/Drawable;

    .line 62
    .line 63
    .line 64
    move-result-object v9

    .line 65
    if-eqz v9, :cond_1

    .line 66
    .line 67
    move v5, v7

    .line 68
    goto :goto_1

    .line 69
    :cond_1
    add-int/lit8 v8, v8, 0x1

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_2
    move v5, v6

    .line 73
    :goto_1
    iput-boolean v5, v4, Ll/i;->c:Z

    .line 74
    .line 75
    :cond_3
    :goto_2
    iget v5, v0, Ll/f;->f:I

    .line 76
    .line 77
    invoke-static {v4, v2, v5}, Ll/t;->l(Landroid/widget/ListAdapter;Landroid/content/Context;I)I

    .line 78
    .line 79
    .line 80
    move-result v5

    .line 81
    new-instance v8, Lm/e2;

    .line 82
    .line 83
    iget v9, v0, Ll/f;->g:I

    .line 84
    .line 85
    const/4 v10, 0x0

    .line 86
    invoke-direct {v8, v2, v10, v9, v6}, Lm/z1;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V

    .line 87
    .line 88
    .line 89
    iget-object v2, v0, Ll/f;->n:Lhu/q;

    .line 90
    .line 91
    iput-object v2, v8, Lm/e2;->D:Lhu/q;

    .line 92
    .line 93
    iput-object v0, v8, Lm/z1;->s:Landroid/widget/AdapterView$OnItemClickListener;

    .line 94
    .line 95
    iget-object v2, v8, Lm/z1;->C:Lm/z;

    .line 96
    .line 97
    invoke-virtual {v2, v0}, Landroid/widget/PopupWindow;->setOnDismissListener(Landroid/widget/PopupWindow$OnDismissListener;)V

    .line 98
    .line 99
    .line 100
    iget-object v2, v0, Ll/f;->q:Landroid/view/View;

    .line 101
    .line 102
    iput-object v2, v8, Lm/z1;->r:Landroid/view/View;

    .line 103
    .line 104
    iget v2, v0, Ll/f;->p:I

    .line 105
    .line 106
    iput v2, v8, Lm/z1;->o:I

    .line 107
    .line 108
    iput-boolean v7, v8, Lm/z1;->B:Z

    .line 109
    .line 110
    iget-object v2, v8, Lm/z1;->C:Lm/z;

    .line 111
    .line 112
    invoke-virtual {v2, v7}, Landroid/widget/PopupWindow;->setFocusable(Z)V

    .line 113
    .line 114
    .line 115
    iget-object v2, v8, Lm/z1;->C:Lm/z;

    .line 116
    .line 117
    const/4 v9, 0x2

    .line 118
    invoke-virtual {v2, v9}, Landroid/widget/PopupWindow;->setInputMethodMode(I)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v8, v4}, Lm/z1;->l(Landroid/widget/ListAdapter;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v8, v5}, Lm/z1;->r(I)V

    .line 125
    .line 126
    .line 127
    iget v2, v0, Ll/f;->p:I

    .line 128
    .line 129
    iput v2, v8, Lm/z1;->o:I

    .line 130
    .line 131
    iget-object v2, v0, Ll/f;->k:Ljava/util/ArrayList;

    .line 132
    .line 133
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 134
    .line 135
    .line 136
    move-result v4

    .line 137
    if-lez v4, :cond_c

    .line 138
    .line 139
    invoke-static {v2, v7}, Lkx/a;->f(Ljava/util/ArrayList;I)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v4

    .line 143
    check-cast v4, Ll/e;

    .line 144
    .line 145
    iget-object v11, v4, Ll/e;->b:Ll/l;

    .line 146
    .line 147
    iget-object v12, v11, Ll/l;->f:Ljava/util/ArrayList;

    .line 148
    .line 149
    invoke-virtual {v12}, Ljava/util/ArrayList;->size()I

    .line 150
    .line 151
    .line 152
    move-result v12

    .line 153
    move v13, v6

    .line 154
    :goto_3
    if-ge v13, v12, :cond_5

    .line 155
    .line 156
    invoke-virtual {v11, v13}, Ll/l;->getItem(I)Landroid/view/MenuItem;

    .line 157
    .line 158
    .line 159
    move-result-object v14

    .line 160
    invoke-interface {v14}, Landroid/view/MenuItem;->hasSubMenu()Z

    .line 161
    .line 162
    .line 163
    move-result v15

    .line 164
    if-eqz v15, :cond_4

    .line 165
    .line 166
    invoke-interface {v14}, Landroid/view/MenuItem;->getSubMenu()Landroid/view/SubMenu;

    .line 167
    .line 168
    .line 169
    move-result-object v15

    .line 170
    if-ne v1, v15, :cond_4

    .line 171
    .line 172
    goto :goto_4

    .line 173
    :cond_4
    add-int/lit8 v13, v13, 0x1

    .line 174
    .line 175
    goto :goto_3

    .line 176
    :cond_5
    move-object v14, v10

    .line 177
    :goto_4
    if-nez v14, :cond_6

    .line 178
    .line 179
    move/from16 v16, v7

    .line 180
    .line 181
    move-object v7, v10

    .line 182
    goto :goto_9

    .line 183
    :cond_6
    iget-object v11, v4, Ll/e;->a:Lm/e2;

    .line 184
    .line 185
    iget-object v11, v11, Lm/z1;->f:Lm/m1;

    .line 186
    .line 187
    invoke-virtual {v11}, Landroid/widget/ListView;->getAdapter()Landroid/widget/ListAdapter;

    .line 188
    .line 189
    .line 190
    move-result-object v12

    .line 191
    instance-of v13, v12, Landroid/widget/HeaderViewListAdapter;

    .line 192
    .line 193
    if-eqz v13, :cond_7

    .line 194
    .line 195
    check-cast v12, Landroid/widget/HeaderViewListAdapter;

    .line 196
    .line 197
    invoke-virtual {v12}, Landroid/widget/HeaderViewListAdapter;->getHeadersCount()I

    .line 198
    .line 199
    .line 200
    move-result v13

    .line 201
    invoke-virtual {v12}, Landroid/widget/HeaderViewListAdapter;->getWrappedAdapter()Landroid/widget/ListAdapter;

    .line 202
    .line 203
    .line 204
    move-result-object v12

    .line 205
    check-cast v12, Ll/i;

    .line 206
    .line 207
    goto :goto_5

    .line 208
    :cond_7
    check-cast v12, Ll/i;

    .line 209
    .line 210
    move v13, v6

    .line 211
    :goto_5
    invoke-virtual {v12}, Ll/i;->getCount()I

    .line 212
    .line 213
    .line 214
    move-result v15

    .line 215
    move/from16 v16, v7

    .line 216
    .line 217
    move v7, v6

    .line 218
    :goto_6
    const/4 v9, -0x1

    .line 219
    if-ge v7, v15, :cond_9

    .line 220
    .line 221
    invoke-virtual {v12, v7}, Ll/i;->b(I)Ll/n;

    .line 222
    .line 223
    .line 224
    move-result-object v10

    .line 225
    if-ne v14, v10, :cond_8

    .line 226
    .line 227
    goto :goto_7

    .line 228
    :cond_8
    add-int/lit8 v7, v7, 0x1

    .line 229
    .line 230
    const/4 v10, 0x0

    .line 231
    goto :goto_6

    .line 232
    :cond_9
    move v7, v9

    .line 233
    :goto_7
    if-ne v7, v9, :cond_a

    .line 234
    .line 235
    goto :goto_8

    .line 236
    :cond_a
    add-int/2addr v7, v13

    .line 237
    invoke-virtual {v11}, Landroid/widget/AdapterView;->getFirstVisiblePosition()I

    .line 238
    .line 239
    .line 240
    move-result v9

    .line 241
    sub-int/2addr v7, v9

    .line 242
    if-ltz v7, :cond_d

    .line 243
    .line 244
    invoke-virtual {v11}, Landroid/view/ViewGroup;->getChildCount()I

    .line 245
    .line 246
    .line 247
    move-result v9

    .line 248
    if-lt v7, v9, :cond_b

    .line 249
    .line 250
    goto :goto_8

    .line 251
    :cond_b
    invoke-virtual {v11, v7}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 252
    .line 253
    .line 254
    move-result-object v7

    .line 255
    goto :goto_9

    .line 256
    :cond_c
    move/from16 v16, v7

    .line 257
    .line 258
    const/4 v4, 0x0

    .line 259
    :cond_d
    :goto_8
    const/4 v7, 0x0

    .line 260
    :goto_9
    if-eqz v7, :cond_15

    .line 261
    .line 262
    iget-object v9, v8, Lm/z1;->C:Lm/z;

    .line 263
    .line 264
    invoke-static {v9, v6}, Lm/c2;->a(Landroid/widget/PopupWindow;Z)V

    .line 265
    .line 266
    .line 267
    iget-object v9, v8, Lm/z1;->C:Lm/z;

    .line 268
    .line 269
    const/4 v10, 0x0

    .line 270
    invoke-static {v9, v10}, Lm/b2;->a(Landroid/widget/PopupWindow;Landroid/transition/Transition;)V

    .line 271
    .line 272
    .line 273
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 274
    .line 275
    .line 276
    move-result v9

    .line 277
    add-int/lit8 v9, v9, -0x1

    .line 278
    .line 279
    invoke-virtual {v2, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object v9

    .line 283
    check-cast v9, Ll/e;

    .line 284
    .line 285
    iget-object v9, v9, Ll/e;->a:Lm/e2;

    .line 286
    .line 287
    iget-object v9, v9, Lm/z1;->f:Lm/m1;

    .line 288
    .line 289
    const/4 v10, 0x2

    .line 290
    new-array v10, v10, [I

    .line 291
    .line 292
    invoke-virtual {v9, v10}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 293
    .line 294
    .line 295
    new-instance v11, Landroid/graphics/Rect;

    .line 296
    .line 297
    invoke-direct {v11}, Landroid/graphics/Rect;-><init>()V

    .line 298
    .line 299
    .line 300
    iget-object v12, v0, Ll/f;->r:Landroid/view/View;

    .line 301
    .line 302
    invoke-virtual {v12, v11}, Landroid/view/View;->getWindowVisibleDisplayFrame(Landroid/graphics/Rect;)V

    .line 303
    .line 304
    .line 305
    iget v12, v0, Ll/f;->s:I

    .line 306
    .line 307
    move/from16 v13, v16

    .line 308
    .line 309
    if-ne v12, v13, :cond_10

    .line 310
    .line 311
    aget v10, v10, v6

    .line 312
    .line 313
    invoke-virtual {v9}, Landroid/view/View;->getWidth()I

    .line 314
    .line 315
    .line 316
    move-result v9

    .line 317
    add-int/2addr v9, v10

    .line 318
    add-int/2addr v9, v5

    .line 319
    iget v10, v11, Landroid/graphics/Rect;->right:I

    .line 320
    .line 321
    if-le v9, v10, :cond_f

    .line 322
    .line 323
    :cond_e
    move v13, v6

    .line 324
    const/4 v9, 0x1

    .line 325
    goto :goto_b

    .line 326
    :cond_f
    :goto_a
    const/4 v9, 0x1

    .line 327
    const/4 v13, 0x1

    .line 328
    goto :goto_b

    .line 329
    :cond_10
    aget v9, v10, v6

    .line 330
    .line 331
    sub-int/2addr v9, v5

    .line 332
    if-gez v9, :cond_e

    .line 333
    .line 334
    goto :goto_a

    .line 335
    :goto_b
    if-ne v13, v9, :cond_11

    .line 336
    .line 337
    const/4 v9, 0x1

    .line 338
    goto :goto_c

    .line 339
    :cond_11
    move v9, v6

    .line 340
    :goto_c
    iput v13, v0, Ll/f;->s:I

    .line 341
    .line 342
    iput-object v7, v8, Lm/z1;->r:Landroid/view/View;

    .line 343
    .line 344
    iget v10, v0, Ll/f;->p:I

    .line 345
    .line 346
    const/4 v11, 0x5

    .line 347
    and-int/2addr v10, v11

    .line 348
    if-ne v10, v11, :cond_13

    .line 349
    .line 350
    if-eqz v9, :cond_12

    .line 351
    .line 352
    goto :goto_d

    .line 353
    :cond_12
    invoke-virtual {v7}, Landroid/view/View;->getWidth()I

    .line 354
    .line 355
    .line 356
    move-result v5

    .line 357
    rsub-int/lit8 v5, v5, 0x0

    .line 358
    .line 359
    goto :goto_d

    .line 360
    :cond_13
    if-eqz v9, :cond_14

    .line 361
    .line 362
    invoke-virtual {v7}, Landroid/view/View;->getWidth()I

    .line 363
    .line 364
    .line 365
    move-result v5

    .line 366
    goto :goto_d

    .line 367
    :cond_14
    rsub-int/lit8 v5, v5, 0x0

    .line 368
    .line 369
    :goto_d
    iput v5, v8, Lm/z1;->i:I

    .line 370
    .line 371
    const/4 v9, 0x1

    .line 372
    iput-boolean v9, v8, Lm/z1;->n:Z

    .line 373
    .line 374
    iput-boolean v9, v8, Lm/z1;->m:Z

    .line 375
    .line 376
    invoke-virtual {v8, v6}, Lm/z1;->h(I)V

    .line 377
    .line 378
    .line 379
    goto :goto_f

    .line 380
    :cond_15
    iget-boolean v5, v0, Ll/f;->t:Z

    .line 381
    .line 382
    if-eqz v5, :cond_16

    .line 383
    .line 384
    iget v5, v0, Ll/f;->v:I

    .line 385
    .line 386
    iput v5, v8, Lm/z1;->i:I

    .line 387
    .line 388
    :cond_16
    iget-boolean v5, v0, Ll/f;->u:Z

    .line 389
    .line 390
    if-eqz v5, :cond_17

    .line 391
    .line 392
    iget v5, v0, Ll/f;->w:I

    .line 393
    .line 394
    invoke-virtual {v8, v5}, Lm/z1;->h(I)V

    .line 395
    .line 396
    .line 397
    :cond_17
    iget-object v5, v0, Ll/t;->d:Landroid/graphics/Rect;

    .line 398
    .line 399
    if-eqz v5, :cond_18

    .line 400
    .line 401
    new-instance v10, Landroid/graphics/Rect;

    .line 402
    .line 403
    invoke-direct {v10, v5}, Landroid/graphics/Rect;-><init>(Landroid/graphics/Rect;)V

    .line 404
    .line 405
    .line 406
    goto :goto_e

    .line 407
    :cond_18
    const/4 v10, 0x0

    .line 408
    :goto_e
    iput-object v10, v8, Lm/z1;->A:Landroid/graphics/Rect;

    .line 409
    .line 410
    :goto_f
    new-instance v5, Ll/e;

    .line 411
    .line 412
    iget v7, v0, Ll/f;->s:I

    .line 413
    .line 414
    invoke-direct {v5, v8, v1, v7}, Ll/e;-><init>(Lm/e2;Ll/l;I)V

    .line 415
    .line 416
    .line 417
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 418
    .line 419
    .line 420
    invoke-virtual {v8}, Lm/z1;->b()V

    .line 421
    .line 422
    .line 423
    iget-object v2, v8, Lm/z1;->f:Lm/m1;

    .line 424
    .line 425
    invoke-virtual {v2, v0}, Landroid/view/View;->setOnKeyListener(Landroid/view/View$OnKeyListener;)V

    .line 426
    .line 427
    .line 428
    if-nez v4, :cond_19

    .line 429
    .line 430
    iget-boolean v0, v0, Ll/f;->y:Z

    .line 431
    .line 432
    if-eqz v0, :cond_19

    .line 433
    .line 434
    iget-object v0, v1, Ll/l;->m:Ljava/lang/CharSequence;

    .line 435
    .line 436
    if-eqz v0, :cond_19

    .line 437
    .line 438
    const v0, 0x7f0d0012

    .line 439
    .line 440
    .line 441
    invoke-virtual {v3, v0, v2, v6}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    .line 442
    .line 443
    .line 444
    move-result-object v0

    .line 445
    check-cast v0, Landroid/widget/FrameLayout;

    .line 446
    .line 447
    const v3, 0x1020016

    .line 448
    .line 449
    .line 450
    invoke-virtual {v0, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 451
    .line 452
    .line 453
    move-result-object v3

    .line 454
    check-cast v3, Landroid/widget/TextView;

    .line 455
    .line 456
    invoke-virtual {v0, v6}, Landroid/view/View;->setEnabled(Z)V

    .line 457
    .line 458
    .line 459
    iget-object v1, v1, Ll/l;->m:Ljava/lang/CharSequence;

    .line 460
    .line 461
    invoke-virtual {v3, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 462
    .line 463
    .line 464
    const/4 v10, 0x0

    .line 465
    invoke-virtual {v2, v0, v10, v6}, Landroid/widget/ListView;->addHeaderView(Landroid/view/View;Ljava/lang/Object;Z)V

    .line 466
    .line 467
    .line 468
    invoke-virtual {v8}, Lm/z1;->b()V

    .line 469
    .line 470
    .line 471
    :cond_19
    return-void
.end method
