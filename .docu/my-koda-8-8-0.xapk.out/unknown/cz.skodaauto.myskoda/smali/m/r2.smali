.class public final Lm/r2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll/x;


# instance fields
.field public d:Ll/l;

.field public e:Ll/n;

.field public final synthetic f:Landroidx/appcompat/widget/Toolbar;


# direct methods
.method public constructor <init>(Landroidx/appcompat/widget/Toolbar;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lm/r2;->f:Landroidx/appcompat/widget/Toolbar;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final c()V
    .locals 4

    .line 1
    iget-object v0, p0, Lm/r2;->e:Ll/n;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    iget-object v0, p0, Lm/r2;->d:Ll/l;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    iget-object v0, v0, Ll/l;->f:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/4 v1, 0x0

    .line 16
    :goto_0
    if-ge v1, v0, :cond_1

    .line 17
    .line 18
    iget-object v2, p0, Lm/r2;->d:Ll/l;

    .line 19
    .line 20
    invoke-virtual {v2, v1}, Ll/l;->getItem(I)Landroid/view/MenuItem;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    iget-object v3, p0, Lm/r2;->e:Ll/n;

    .line 25
    .line 26
    if-ne v2, v3, :cond_0

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    iget-object v0, p0, Lm/r2;->e:Ll/n;

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Lm/r2;->g(Ll/n;)Z

    .line 35
    .line 36
    .line 37
    :cond_2
    :goto_1
    return-void
.end method

.method public final d(Ll/l;Z)V
    .locals 0

    .line 1
    return-void
.end method

.method public final f(Ll/d0;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final g(Ll/n;)Z
    .locals 6

    .line 1
    iget-object v0, p0, Lm/r2;->f:Landroidx/appcompat/widget/Toolbar;

    .line 2
    .line 3
    iget-object v1, v0, Landroidx/appcompat/widget/Toolbar;->l:Landroid/view/View;

    .line 4
    .line 5
    instance-of v2, v1, Lk/b;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    check-cast v1, Lk/b;

    .line 10
    .line 11
    check-cast v1, Ll/p;

    .line 12
    .line 13
    iget-object v1, v1, Ll/p;->d:Landroid/view/CollapsibleActionView;

    .line 14
    .line 15
    invoke-interface {v1}, Landroid/view/CollapsibleActionView;->onActionViewCollapsed()V

    .line 16
    .line 17
    .line 18
    :cond_0
    iget-object v1, v0, Landroidx/appcompat/widget/Toolbar;->l:Landroid/view/View;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 21
    .line 22
    .line 23
    iget-object v1, v0, Landroidx/appcompat/widget/Toolbar;->k:Lm/w;

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 26
    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    iput-object v1, v0, Landroidx/appcompat/widget/Toolbar;->l:Landroid/view/View;

    .line 30
    .line 31
    iget-object v2, v0, Landroidx/appcompat/widget/Toolbar;->H:Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    const/4 v4, 0x1

    .line 38
    sub-int/2addr v3, v4

    .line 39
    :goto_0
    if-ltz v3, :cond_1

    .line 40
    .line 41
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v5

    .line 45
    check-cast v5, Landroid/view/View;

    .line 46
    .line 47
    invoke-virtual {v0, v5}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 48
    .line 49
    .line 50
    add-int/lit8 v3, v3, -0x1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 54
    .line 55
    .line 56
    iput-object v1, p0, Lm/r2;->e:Ll/n;

    .line 57
    .line 58
    invoke-virtual {v0}, Landroid/view/View;->requestLayout()V

    .line 59
    .line 60
    .line 61
    const/4 p0, 0x0

    .line 62
    iput-boolean p0, p1, Ll/n;->C:Z

    .line 63
    .line 64
    iget-object p1, p1, Ll/n;->n:Ll/l;

    .line 65
    .line 66
    invoke-virtual {p1, p0}, Ll/l;->p(Z)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v0}, Landroidx/appcompat/widget/Toolbar;->t()V

    .line 70
    .line 71
    .line 72
    return v4
.end method

.method public final h(Ll/n;)Z
    .locals 5

    .line 1
    iget-object v0, p0, Lm/r2;->f:Landroidx/appcompat/widget/Toolbar;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroidx/appcompat/widget/Toolbar;->c()V

    .line 4
    .line 5
    .line 6
    iget-object v1, v0, Landroidx/appcompat/widget/Toolbar;->k:Lm/w;

    .line 7
    .line 8
    invoke-virtual {v1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    if-eq v1, v0, :cond_1

    .line 13
    .line 14
    instance-of v2, v1, Landroid/view/ViewGroup;

    .line 15
    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    check-cast v1, Landroid/view/ViewGroup;

    .line 19
    .line 20
    iget-object v2, v0, Landroidx/appcompat/widget/Toolbar;->k:Lm/w;

    .line 21
    .line 22
    invoke-virtual {v1, v2}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    iget-object v1, v0, Landroidx/appcompat/widget/Toolbar;->k:Lm/w;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 28
    .line 29
    .line 30
    :cond_1
    invoke-virtual {p1}, Ll/n;->getActionView()Landroid/view/View;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    iput-object v1, v0, Landroidx/appcompat/widget/Toolbar;->l:Landroid/view/View;

    .line 35
    .line 36
    iput-object p1, p0, Lm/r2;->e:Ll/n;

    .line 37
    .line 38
    invoke-virtual {v1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    const/4 v1, 0x2

    .line 43
    if-eq p0, v0, :cond_3

    .line 44
    .line 45
    instance-of v2, p0, Landroid/view/ViewGroup;

    .line 46
    .line 47
    if-eqz v2, :cond_2

    .line 48
    .line 49
    check-cast p0, Landroid/view/ViewGroup;

    .line 50
    .line 51
    iget-object v2, v0, Landroidx/appcompat/widget/Toolbar;->l:Landroid/view/View;

    .line 52
    .line 53
    invoke-virtual {p0, v2}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 54
    .line 55
    .line 56
    :cond_2
    invoke-static {}, Landroidx/appcompat/widget/Toolbar;->h()Lm/s2;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    iget v2, v0, Landroidx/appcompat/widget/Toolbar;->q:I

    .line 61
    .line 62
    and-int/lit8 v2, v2, 0x70

    .line 63
    .line 64
    const v3, 0x800003

    .line 65
    .line 66
    .line 67
    or-int/2addr v2, v3

    .line 68
    iput v2, p0, Lm/s2;->a:I

    .line 69
    .line 70
    iput v1, p0, Lm/s2;->b:I

    .line 71
    .line 72
    iget-object v2, v0, Landroidx/appcompat/widget/Toolbar;->l:Landroid/view/View;

    .line 73
    .line 74
    invoke-virtual {v2, p0}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 75
    .line 76
    .line 77
    iget-object p0, v0, Landroidx/appcompat/widget/Toolbar;->l:Landroid/view/View;

    .line 78
    .line 79
    invoke-virtual {v0, p0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 80
    .line 81
    .line 82
    :cond_3
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    const/4 v2, 0x1

    .line 87
    sub-int/2addr p0, v2

    .line 88
    :goto_0
    if-ltz p0, :cond_5

    .line 89
    .line 90
    invoke-virtual {v0, p0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    invoke-virtual {v3}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    check-cast v4, Lm/s2;

    .line 99
    .line 100
    iget v4, v4, Lm/s2;->b:I

    .line 101
    .line 102
    if-eq v4, v1, :cond_4

    .line 103
    .line 104
    iget-object v4, v0, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 105
    .line 106
    if-eq v3, v4, :cond_4

    .line 107
    .line 108
    invoke-virtual {v0, p0}, Landroid/view/ViewGroup;->removeViewAt(I)V

    .line 109
    .line 110
    .line 111
    iget-object v4, v0, Landroidx/appcompat/widget/Toolbar;->H:Ljava/util/ArrayList;

    .line 112
    .line 113
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    :cond_4
    add-int/lit8 p0, p0, -0x1

    .line 117
    .line 118
    goto :goto_0

    .line 119
    :cond_5
    invoke-virtual {v0}, Landroid/view/View;->requestLayout()V

    .line 120
    .line 121
    .line 122
    iput-boolean v2, p1, Ll/n;->C:Z

    .line 123
    .line 124
    iget-object p0, p1, Ll/n;->n:Ll/l;

    .line 125
    .line 126
    const/4 p1, 0x0

    .line 127
    invoke-virtual {p0, p1}, Ll/l;->p(Z)V

    .line 128
    .line 129
    .line 130
    iget-object p0, v0, Landroidx/appcompat/widget/Toolbar;->l:Landroid/view/View;

    .line 131
    .line 132
    instance-of p1, p0, Lk/b;

    .line 133
    .line 134
    if-eqz p1, :cond_6

    .line 135
    .line 136
    check-cast p0, Lk/b;

    .line 137
    .line 138
    check-cast p0, Ll/p;

    .line 139
    .line 140
    iget-object p0, p0, Ll/p;->d:Landroid/view/CollapsibleActionView;

    .line 141
    .line 142
    invoke-interface {p0}, Landroid/view/CollapsibleActionView;->onActionViewExpanded()V

    .line 143
    .line 144
    .line 145
    :cond_6
    invoke-virtual {v0}, Landroidx/appcompat/widget/Toolbar;->t()V

    .line 146
    .line 147
    .line 148
    return v2
.end method

.method public final i()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final j(Landroid/content/Context;Ll/l;)V
    .locals 1

    .line 1
    iget-object p1, p0, Lm/r2;->d:Ll/l;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lm/r2;->e:Ll/n;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p1, v0}, Ll/l;->d(Ll/n;)Z

    .line 10
    .line 11
    .line 12
    :cond_0
    iput-object p2, p0, Lm/r2;->d:Ll/l;

    .line 13
    .line 14
    return-void
.end method
