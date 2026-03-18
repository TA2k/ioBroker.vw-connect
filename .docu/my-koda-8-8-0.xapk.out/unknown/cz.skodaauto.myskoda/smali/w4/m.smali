.class public final Lw4/m;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc3/p;
.implements Landroid/view/ViewTreeObserver$OnGlobalFocusChangeListener;


# instance fields
.field public r:Landroid/view/View;

.field public s:Landroid/view/ViewTreeObserver;

.field public final t:Lw4/l;

.field public final u:Lw4/l;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lw4/l;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, p0, v1}, Lw4/l;-><init>(Lw4/m;I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lw4/m;->t:Lw4/l;

    .line 11
    .line 12
    new-instance v0, Lw4/l;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-direct {v0, p0, v1}, Lw4/l;-><init>(Lw4/m;I)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lw4/m;->u:Lw4/l;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final P0()V
    .locals 1

    .line 1
    invoke-static {p0}, Lv3/f;->z(Lv3/m;)Landroid/view/View;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iput-object v0, p0, Lw4/m;->s:Landroid/view/ViewTreeObserver;

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Landroid/view/ViewTreeObserver;->addOnGlobalFocusChangeListener(Landroid/view/ViewTreeObserver$OnGlobalFocusChangeListener;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final Q0()V
    .locals 2

    .line 1
    iget-object v0, p0, Lw4/m;->s:Landroid/view/ViewTreeObserver;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Landroid/view/ViewTreeObserver;->isAlive()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Landroid/view/ViewTreeObserver;->removeOnGlobalFocusChangeListener(Landroid/view/ViewTreeObserver$OnGlobalFocusChangeListener;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    const/4 v0, 0x0

    .line 15
    iput-object v0, p0, Lw4/m;->s:Landroid/view/ViewTreeObserver;

    .line 16
    .line 17
    invoke-static {p0}, Lv3/f;->z(Lv3/m;)Landroid/view/View;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {v1}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-virtual {v1, p0}, Landroid/view/ViewTreeObserver;->removeOnGlobalFocusChangeListener(Landroid/view/ViewTreeObserver$OnGlobalFocusChangeListener;)V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lw4/m;->r:Landroid/view/View;

    .line 29
    .line 30
    return-void
.end method

.method public final X0()Lc3/v;
    .locals 9

    .line 1
    iget-object v0, p0, Lx2/r;->d:Lx2/r;

    .line 2
    .line 3
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-string v0, "visitLocalDescendants called on an unattached node"

    .line 8
    .line 9
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lx2/r;->d:Lx2/r;

    .line 13
    .line 14
    iget v0, p0, Lx2/r;->g:I

    .line 15
    .line 16
    and-int/lit16 v0, v0, 0x400

    .line 17
    .line 18
    if-eqz v0, :cond_a

    .line 19
    .line 20
    iget-object p0, p0, Lx2/r;->i:Lx2/r;

    .line 21
    .line 22
    const/4 v0, 0x0

    .line 23
    move v1, v0

    .line 24
    :goto_0
    if-eqz p0, :cond_a

    .line 25
    .line 26
    iget v2, p0, Lx2/r;->f:I

    .line 27
    .line 28
    and-int/lit16 v2, v2, 0x400

    .line 29
    .line 30
    if-eqz v2, :cond_9

    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    move-object v3, p0

    .line 34
    move-object v4, v2

    .line 35
    :goto_1
    if-eqz v3, :cond_9

    .line 36
    .line 37
    instance-of v5, v3, Lc3/v;

    .line 38
    .line 39
    const/4 v6, 0x1

    .line 40
    if-eqz v5, :cond_2

    .line 41
    .line 42
    check-cast v3, Lc3/v;

    .line 43
    .line 44
    if-eqz v1, :cond_1

    .line 45
    .line 46
    return-object v3

    .line 47
    :cond_1
    move v1, v6

    .line 48
    goto :goto_4

    .line 49
    :cond_2
    iget v5, v3, Lx2/r;->f:I

    .line 50
    .line 51
    and-int/lit16 v5, v5, 0x400

    .line 52
    .line 53
    if-eqz v5, :cond_8

    .line 54
    .line 55
    instance-of v5, v3, Lv3/n;

    .line 56
    .line 57
    if-eqz v5, :cond_8

    .line 58
    .line 59
    move-object v5, v3

    .line 60
    check-cast v5, Lv3/n;

    .line 61
    .line 62
    iget-object v5, v5, Lv3/n;->s:Lx2/r;

    .line 63
    .line 64
    move v7, v0

    .line 65
    :goto_2
    if-eqz v5, :cond_7

    .line 66
    .line 67
    iget v8, v5, Lx2/r;->f:I

    .line 68
    .line 69
    and-int/lit16 v8, v8, 0x400

    .line 70
    .line 71
    if-eqz v8, :cond_6

    .line 72
    .line 73
    add-int/lit8 v7, v7, 0x1

    .line 74
    .line 75
    if-ne v7, v6, :cond_3

    .line 76
    .line 77
    move-object v3, v5

    .line 78
    goto :goto_3

    .line 79
    :cond_3
    if-nez v4, :cond_4

    .line 80
    .line 81
    new-instance v4, Ln2/b;

    .line 82
    .line 83
    const/16 v8, 0x10

    .line 84
    .line 85
    new-array v8, v8, [Lx2/r;

    .line 86
    .line 87
    invoke-direct {v4, v8}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    :cond_4
    if-eqz v3, :cond_5

    .line 91
    .line 92
    invoke-virtual {v4, v3}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    move-object v3, v2

    .line 96
    :cond_5
    invoke-virtual {v4, v5}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    :cond_6
    :goto_3
    iget-object v5, v5, Lx2/r;->i:Lx2/r;

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_7
    if-ne v7, v6, :cond_8

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_8
    :goto_4
    invoke-static {v4}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    goto :goto_1

    .line 110
    :cond_9
    iget-object p0, p0, Lx2/r;->i:Lx2/r;

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 114
    .line 115
    const-string v0, "Could not find focus target of embedded view wrapper"

    .line 116
    .line 117
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    throw p0
.end method

.method public final onGlobalFocusChanged(Landroid/view/View;Landroid/view/View;)V
    .locals 6

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v0, v0, Lv3/h0;->p:Lv3/o1;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto/16 :goto_2

    .line 10
    .line 11
    :cond_0
    invoke-static {p0}, Lw4/i;->c(Lx2/r;)Landroid/view/View;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lw3/t;

    .line 20
    .line 21
    invoke-virtual {v1}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    const/4 v3, 0x1

    .line 30
    const/4 v4, 0x0

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    invoke-virtual {p1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    if-nez v5, :cond_1

    .line 38
    .line 39
    invoke-static {v0, p1}, Lw4/i;->a(Landroid/view/View;Landroid/view/View;)Z

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    if-eqz p1, :cond_1

    .line 44
    .line 45
    move p1, v3

    .line 46
    goto :goto_0

    .line 47
    :cond_1
    move p1, v4

    .line 48
    :goto_0
    if-eqz p2, :cond_2

    .line 49
    .line 50
    invoke-virtual {p2, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    if-nez v2, :cond_2

    .line 55
    .line 56
    invoke-static {v0, p2}, Lw4/i;->a(Landroid/view/View;Landroid/view/View;)Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-eqz v0, :cond_2

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_2
    move v3, v4

    .line 64
    :goto_1
    if-eqz p1, :cond_3

    .line 65
    .line 66
    if-eqz v3, :cond_3

    .line 67
    .line 68
    iput-object p2, p0, Lw4/m;->r:Landroid/view/View;

    .line 69
    .line 70
    return-void

    .line 71
    :cond_3
    if-eqz v3, :cond_4

    .line 72
    .line 73
    iput-object p2, p0, Lw4/m;->r:Landroid/view/View;

    .line 74
    .line 75
    invoke-virtual {p0}, Lw4/m;->X0()Lc3/v;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-virtual {p0}, Lc3/v;->Z0()Lc3/u;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    invoke-virtual {p1}, Lc3/u;->a()Z

    .line 84
    .line 85
    .line 86
    move-result p1

    .line 87
    if-nez p1, :cond_5

    .line 88
    .line 89
    invoke-static {p0}, Lc3/f;->v(Lc3/v;)Z

    .line 90
    .line 91
    .line 92
    return-void

    .line 93
    :cond_4
    const/4 p2, 0x0

    .line 94
    if-eqz p1, :cond_6

    .line 95
    .line 96
    iput-object p2, p0, Lw4/m;->r:Landroid/view/View;

    .line 97
    .line 98
    invoke-virtual {p0}, Lw4/m;->X0()Lc3/v;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    invoke-virtual {p0}, Lc3/v;->Z0()Lc3/u;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-virtual {p0}, Lc3/u;->b()Z

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    if-eqz p0, :cond_5

    .line 111
    .line 112
    const/16 p0, 0x8

    .line 113
    .line 114
    check-cast v1, Lc3/l;

    .line 115
    .line 116
    invoke-virtual {v1, p0, v4, v4}, Lc3/l;->d(IZZ)Z

    .line 117
    .line 118
    .line 119
    :cond_5
    :goto_2
    return-void

    .line 120
    :cond_6
    iput-object p2, p0, Lw4/m;->r:Landroid/view/View;

    .line 121
    .line 122
    return-void
.end method

.method public final t(Lc3/m;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-interface {p1, v0}, Lc3/m;->b(Z)V

    .line 3
    .line 4
    .line 5
    iget-object v0, p0, Lw4/m;->t:Lw4/l;

    .line 6
    .line 7
    invoke-interface {p1, v0}, Lc3/m;->d(Lw4/l;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lw4/m;->u:Lw4/l;

    .line 11
    .line 12
    invoke-interface {p1, p0}, Lc3/m;->a(Lw4/l;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
