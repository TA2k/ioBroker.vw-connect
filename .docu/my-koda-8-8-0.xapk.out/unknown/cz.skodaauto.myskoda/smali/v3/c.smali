.class public final Lv3/c;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/y;
.implements Lv3/p;
.implements Lv3/x1;
.implements Lv3/t1;
.implements Lu3/e;
.implements Lu3/g;
.implements Lv3/r1;
.implements Lv3/x;
.implements Lv3/q;
.implements Lc3/e;
.implements Lc3/p;
.implements Lc3/r;
.implements Lv3/p1;
.implements Lb3/b;


# instance fields
.field public r:Lx2/q;

.field public s:Lu3/a;

.field public t:Ljava/util/HashSet;


# virtual methods
.method public final A()V
    .locals 1

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.PointerInputModifier"

    .line 4
    .line 5
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lp3/a0;

    .line 9
    .line 10
    iget-object p0, p0, Lp3/a0;->e:Lcom/google/firebase/messaging/w;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final C0(Lv3/j0;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string p1, "null cannot be cast to non-null type androidx.compose.ui.draw.DrawModifier"

    .line 4
    .line 5
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    throw p0
.end method

.method public final D(Lv3/p0;Lt3/p0;I)I
    .locals 4

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier"

    .line 4
    .line 5
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lt3/c0;

    .line 9
    .line 10
    new-instance v0, Lt3/l;

    .line 11
    .line 12
    sget-object v1, Lt3/t0;->d:Lt3/t0;

    .line 13
    .line 14
    sget-object v2, Lt3/u0;->e:Lt3/u0;

    .line 15
    .line 16
    const/4 v3, 0x1

    .line 17
    invoke-direct {v0, p2, v1, v2, v3}, Lt3/l;-><init>(Lt3/p0;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    .line 18
    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    const/16 v1, 0xd

    .line 22
    .line 23
    invoke-static {p3, p2, v1}, Lt4/b;->b(III)J

    .line 24
    .line 25
    .line 26
    move-result-wide p2

    .line 27
    new-instance v1, Lt3/x;

    .line 28
    .line 29
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-direct {v1, p1, v2}, Lt3/x;-><init>(Lt3/t;Lt4/m;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {p0, v1, v0, p2, p3}, Lt3/c0;->c(Lt3/s0;Lt3/p0;J)Lt3/r0;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-interface {p0}, Lt3/r0;->m()I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    return p0
.end method

.method public final E0()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.PointerInputModifier"

    .line 4
    .line 5
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lp3/a0;

    .line 9
    .line 10
    iget-object p0, p0, Lp3/a0;->e:Lcom/google/firebase/messaging/w;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0
.end method

.method public final F(Lc3/u;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string p1, "onFocusEvent called on wrong node"

    .line 4
    .line 5
    invoke-static {p1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    new-instance p0, Ljava/lang/ClassCastException;

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 14
    .line 15
    .line 16
    throw p0
.end method

.method public final F0(Lv3/p0;Lt3/p0;I)I
    .locals 4

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier"

    .line 4
    .line 5
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lt3/c0;

    .line 9
    .line 10
    new-instance v0, Lt3/l;

    .line 11
    .line 12
    sget-object v1, Lt3/t0;->e:Lt3/t0;

    .line 13
    .line 14
    sget-object v2, Lt3/u0;->d:Lt3/u0;

    .line 15
    .line 16
    const/4 v3, 0x1

    .line 17
    invoke-direct {v0, p2, v1, v2, v3}, Lt3/l;-><init>(Lt3/p0;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    .line 18
    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    const/4 v1, 0x7

    .line 22
    invoke-static {p2, p3, v1}, Lt4/b;->b(III)J

    .line 23
    .line 24
    .line 25
    move-result-wide p2

    .line 26
    new-instance v1, Lt3/x;

    .line 27
    .line 28
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    invoke-direct {v1, p1, v2}, Lt3/x;-><init>(Lt3/t;Lt4/m;)V

    .line 33
    .line 34
    .line 35
    invoke-interface {p0, v1, v0, p2, p3}, Lt3/c0;->c(Lt3/s0;Lt3/p0;J)Lt3/r0;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p0}, Lt3/r0;->o()I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    return p0
.end method

.method public final G()Llp/e1;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/c;->s:Lu3/a;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    sget-object p0, Lu3/b;->a:Lu3/b;

    .line 7
    .line 8
    return-object p0
.end method

.method public final J(Lv3/p0;Lt3/p0;I)I
    .locals 4

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier"

    .line 4
    .line 5
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lt3/c0;

    .line 9
    .line 10
    new-instance v0, Lt3/l;

    .line 11
    .line 12
    sget-object v1, Lt3/t0;->e:Lt3/t0;

    .line 13
    .line 14
    sget-object v2, Lt3/u0;->e:Lt3/u0;

    .line 15
    .line 16
    const/4 v3, 0x1

    .line 17
    invoke-direct {v0, p2, v1, v2, v3}, Lt3/l;-><init>(Lt3/p0;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    .line 18
    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    const/16 v1, 0xd

    .line 22
    .line 23
    invoke-static {p3, p2, v1}, Lt4/b;->b(III)J

    .line 24
    .line 25
    .line 26
    move-result-wide p2

    .line 27
    new-instance v1, Lt3/x;

    .line 28
    .line 29
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-direct {v1, p1, v2}, Lt3/x;-><init>(Lt3/t;Lt4/m;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {p0, v1, v0, p2, p3}, Lt3/c0;->c(Lt3/s0;Lt3/p0;J)Lt3/r0;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-interface {p0}, Lt3/r0;->m()I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    return p0
.end method

.method public final K(Lv3/f1;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string p1, "null cannot be cast to non-null type androidx.compose.ui.layout.OnGloballyPositionedModifier"

    .line 4
    .line 5
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lo1/d;

    .line 9
    .line 10
    iget-object p1, p0, Lo1/d;->c:Ljava/util/ArrayList;

    .line 11
    .line 12
    iget-boolean v0, p0, Lo1/d;->b:Z

    .line 13
    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    const/4 v0, 0x1

    .line 17
    iput-boolean v0, p0, Lo1/d;->b:Z

    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    const/4 v0, 0x0

    .line 24
    :goto_0
    if-ge v0, p0, :cond_0

    .line 25
    .line 26
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Lkotlin/coroutines/Continuation;

    .line 31
    .line 32
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-interface {v1, v2}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    add-int/lit8 v0, v0, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    invoke-virtual {p1}, Ljava/util/ArrayList;->clear()V

    .line 41
    .line 42
    .line 43
    :cond_1
    return-void
.end method

.method public final P0()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, v0}, Lv3/c;->X0(Z)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final Q0()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv3/c;->Y0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final R(Lt3/y;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final X(Lv3/p0;Lt3/p0;I)I
    .locals 4

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier"

    .line 4
    .line 5
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lt3/c0;

    .line 9
    .line 10
    new-instance v0, Lt3/l;

    .line 11
    .line 12
    sget-object v1, Lt3/t0;->d:Lt3/t0;

    .line 13
    .line 14
    sget-object v2, Lt3/u0;->d:Lt3/u0;

    .line 15
    .line 16
    const/4 v3, 0x1

    .line 17
    invoke-direct {v0, p2, v1, v2, v3}, Lt3/l;-><init>(Lt3/p0;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    .line 18
    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    const/4 v1, 0x7

    .line 22
    invoke-static {p2, p3, v1}, Lt4/b;->b(III)J

    .line 23
    .line 24
    .line 25
    move-result-wide p2

    .line 26
    new-instance v1, Lt3/x;

    .line 27
    .line 28
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    invoke-direct {v1, p1, v2}, Lt3/x;-><init>(Lt3/t;Lt4/m;)V

    .line 33
    .line 34
    .line 35
    invoke-interface {p0, v1, v0, p2, p3}, Lt3/c0;->c(Lt3/s0;Lt3/p0;J)Lt3/r0;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p0}, Lt3/r0;->o()I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    return p0
.end method

.method public final X0(Z)V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string v0, "initializeModifier called on unattached node"

    .line 6
    .line 7
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object v0, p0, Lv3/c;->r:Lx2/q;

    .line 11
    .line 12
    iget v1, p0, Lx2/r;->f:I

    .line 13
    .line 14
    and-int/lit8 v1, v1, 0x20

    .line 15
    .line 16
    if-eqz v1, :cond_4

    .line 17
    .line 18
    instance-of v1, v0, Lu3/c;

    .line 19
    .line 20
    if-eqz v1, :cond_2

    .line 21
    .line 22
    new-instance v1, Lv3/b;

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    invoke-direct {v1, p0, v2}, Lv3/b;-><init>(Lv3/c;I)V

    .line 26
    .line 27
    .line 28
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    check-cast v2, Lw3/t;

    .line 33
    .line 34
    iget-object v2, v2, Lw3/t;->H1:Landroidx/collection/l0;

    .line 35
    .line 36
    invoke-virtual {v2, v1}, Landroidx/collection/l0;->f(Ljava/lang/Object;)I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-ltz v3, :cond_1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    invoke-virtual {v2, v1}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    :cond_2
    :goto_0
    instance-of v1, v0, Lu3/f;

    .line 47
    .line 48
    if-eqz v1, :cond_4

    .line 49
    .line 50
    move-object v1, v0

    .line 51
    check-cast v1, Lu3/f;

    .line 52
    .line 53
    iget-object v2, p0, Lv3/c;->s:Lu3/a;

    .line 54
    .line 55
    if-eqz v2, :cond_3

    .line 56
    .line 57
    invoke-interface {v1}, Lu3/f;->getKey()Lu3/h;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    invoke-virtual {v2, v3}, Lu3/a;->a(Lu3/h;)Z

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    if-eqz v3, :cond_3

    .line 66
    .line 67
    iput-object v1, v2, Lu3/a;->a:Lu3/f;

    .line 68
    .line 69
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    check-cast v2, Lw3/t;

    .line 74
    .line 75
    invoke-virtual {v2}, Lw3/t;->getModifierLocalManager()Lu3/d;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    invoke-interface {v1}, Lu3/f;->getKey()Lu3/h;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    iget-object v3, v2, Lu3/d;->b:Ln2/b;

    .line 84
    .line 85
    invoke-virtual {v3, p0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    iget-object v3, v2, Lu3/d;->c:Ln2/b;

    .line 89
    .line 90
    invoke-virtual {v3, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v2}, Lu3/d;->a()V

    .line 94
    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_3
    new-instance v2, Lu3/a;

    .line 98
    .line 99
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 100
    .line 101
    .line 102
    iput-object v1, v2, Lu3/a;->a:Lu3/f;

    .line 103
    .line 104
    iput-object v2, p0, Lv3/c;->s:Lu3/a;

    .line 105
    .line 106
    invoke-static {p0}, Lv3/f;->d(Lv3/c;)Z

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    if-eqz v2, :cond_4

    .line 111
    .line 112
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    check-cast v2, Lw3/t;

    .line 117
    .line 118
    invoke-virtual {v2}, Lw3/t;->getModifierLocalManager()Lu3/d;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    invoke-interface {v1}, Lu3/f;->getKey()Lu3/h;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    iget-object v3, v2, Lu3/d;->b:Ln2/b;

    .line 127
    .line 128
    invoke-virtual {v3, p0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    iget-object v3, v2, Lu3/d;->c:Ln2/b;

    .line 132
    .line 133
    invoke-virtual {v3, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v2}, Lu3/d;->a()V

    .line 137
    .line 138
    .line 139
    :cond_4
    :goto_1
    iget v1, p0, Lx2/r;->f:I

    .line 140
    .line 141
    and-int/lit8 v1, v1, 0x4

    .line 142
    .line 143
    const/4 v2, 0x2

    .line 144
    if-eqz v1, :cond_5

    .line 145
    .line 146
    if-nez p1, :cond_5

    .line 147
    .line 148
    invoke-static {p0, v2}, Lv3/f;->v(Lv3/m;I)Lv3/f1;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    invoke-virtual {v1}, Lv3/f1;->m1()V

    .line 153
    .line 154
    .line 155
    :cond_5
    iget v1, p0, Lx2/r;->f:I

    .line 156
    .line 157
    and-int/2addr v1, v2

    .line 158
    if-eqz v1, :cond_7

    .line 159
    .line 160
    invoke-static {p0}, Lv3/f;->d(Lv3/c;)Z

    .line 161
    .line 162
    .line 163
    move-result v1

    .line 164
    if-eqz v1, :cond_6

    .line 165
    .line 166
    iget-object v1, p0, Lx2/r;->k:Lv3/f1;

    .line 167
    .line 168
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    move-object v3, v1

    .line 172
    check-cast v3, Lv3/a0;

    .line 173
    .line 174
    invoke-virtual {v3, p0}, Lv3/a0;->I1(Lv3/y;)V

    .line 175
    .line 176
    .line 177
    iget-object v1, v1, Lv3/f1;->L:Lv3/n1;

    .line 178
    .line 179
    if-eqz v1, :cond_6

    .line 180
    .line 181
    check-cast v1, Lw3/o1;

    .line 182
    .line 183
    invoke-virtual {v1}, Lw3/o1;->invalidate()V

    .line 184
    .line 185
    .line 186
    :cond_6
    if-nez p1, :cond_7

    .line 187
    .line 188
    invoke-static {p0, v2}, Lv3/f;->v(Lv3/m;I)Lv3/f1;

    .line 189
    .line 190
    .line 191
    move-result-object p1

    .line 192
    invoke-virtual {p1}, Lv3/f1;->m1()V

    .line 193
    .line 194
    .line 195
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 196
    .line 197
    .line 198
    move-result-object p1

    .line 199
    invoke-virtual {p1}, Lv3/h0;->E()V

    .line 200
    .line 201
    .line 202
    :cond_7
    instance-of p1, v0, Lm1/r;

    .line 203
    .line 204
    if-eqz p1, :cond_8

    .line 205
    .line 206
    move-object p1, v0

    .line 207
    check-cast p1, Lm1/r;

    .line 208
    .line 209
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 210
    .line 211
    .line 212
    move-result-object v1

    .line 213
    iget v2, p1, Lm1/r;->b:I

    .line 214
    .line 215
    packed-switch v2, :pswitch_data_0

    .line 216
    .line 217
    .line 218
    iget-object p1, p1, Lm1/r;->c:Lg1/q2;

    .line 219
    .line 220
    check-cast p1, Lp1/v;

    .line 221
    .line 222
    iget-object p1, p1, Lp1/v;->y:Ll2/j1;

    .line 223
    .line 224
    invoke-virtual {p1, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 225
    .line 226
    .line 227
    goto :goto_2

    .line 228
    :pswitch_0
    iget-object p1, p1, Lm1/r;->c:Lg1/q2;

    .line 229
    .line 230
    check-cast p1, Ln1/v;

    .line 231
    .line 232
    iput-object v1, p1, Ln1/v;->j:Lv3/h0;

    .line 233
    .line 234
    goto :goto_2

    .line 235
    :pswitch_1
    iget-object p1, p1, Lm1/r;->c:Lg1/q2;

    .line 236
    .line 237
    check-cast p1, Lm1/t;

    .line 238
    .line 239
    iput-object v1, p1, Lm1/t;->k:Lv3/h0;

    .line 240
    .line 241
    :cond_8
    :goto_2
    iget p1, p0, Lx2/r;->f:I

    .line 242
    .line 243
    and-int/lit16 p1, p1, 0x100

    .line 244
    .line 245
    if-eqz p1, :cond_9

    .line 246
    .line 247
    instance-of p1, v0, Lo1/d;

    .line 248
    .line 249
    if-eqz p1, :cond_9

    .line 250
    .line 251
    invoke-static {p0}, Lv3/f;->d(Lv3/c;)Z

    .line 252
    .line 253
    .line 254
    move-result p1

    .line 255
    if-eqz p1, :cond_9

    .line 256
    .line 257
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 258
    .line 259
    .line 260
    move-result-object p1

    .line 261
    invoke-virtual {p1}, Lv3/h0;->E()V

    .line 262
    .line 263
    .line 264
    :cond_9
    iget p1, p0, Lx2/r;->f:I

    .line 265
    .line 266
    and-int/lit8 v1, p1, 0x10

    .line 267
    .line 268
    if-eqz v1, :cond_a

    .line 269
    .line 270
    instance-of v1, v0, Lp3/a0;

    .line 271
    .line 272
    if-eqz v1, :cond_a

    .line 273
    .line 274
    check-cast v0, Lp3/a0;

    .line 275
    .line 276
    iget-object v0, v0, Lp3/a0;->e:Lcom/google/firebase/messaging/w;

    .line 277
    .line 278
    iget-object v1, p0, Lx2/r;->k:Lv3/f1;

    .line 279
    .line 280
    iput-object v1, v0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 281
    .line 282
    :cond_a
    and-int/lit8 p1, p1, 0x8

    .line 283
    .line 284
    if-eqz p1, :cond_b

    .line 285
    .line 286
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 287
    .line 288
    .line 289
    move-result-object p0

    .line 290
    check-cast p0, Lw3/t;

    .line 291
    .line 292
    invoke-virtual {p0}, Lw3/t;->y()V

    .line 293
    .line 294
    .line 295
    :cond_b
    return-void

    .line 296
    nop

    .line 297
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final Y0()V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string v0, "unInitializeModifier called on unattached node"

    .line 6
    .line 7
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object v0, p0, Lv3/c;->r:Lx2/q;

    .line 11
    .line 12
    iget v1, p0, Lx2/r;->f:I

    .line 13
    .line 14
    and-int/lit8 v1, v1, 0x20

    .line 15
    .line 16
    if-eqz v1, :cond_2

    .line 17
    .line 18
    instance-of v1, v0, Lu3/f;

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v1, Lw3/t;

    .line 27
    .line 28
    invoke-virtual {v1}, Lw3/t;->getModifierLocalManager()Lu3/d;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    move-object v2, v0

    .line 33
    check-cast v2, Lu3/f;

    .line 34
    .line 35
    invoke-interface {v2}, Lu3/f;->getKey()Lu3/h;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    iget-object v3, v1, Lu3/d;->d:Ln2/b;

    .line 40
    .line 41
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    invoke-virtual {v3, v4}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    iget-object v3, v1, Lu3/d;->e:Ln2/b;

    .line 49
    .line 50
    invoke-virtual {v3, v2}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1}, Lu3/d;->a()V

    .line 54
    .line 55
    .line 56
    :cond_1
    instance-of v1, v0, Lu3/c;

    .line 57
    .line 58
    if-eqz v1, :cond_2

    .line 59
    .line 60
    check-cast v0, Lu3/c;

    .line 61
    .line 62
    sget-object v1, Lv3/f;->a:Lv3/d;

    .line 63
    .line 64
    invoke-interface {v0, v1}, Lu3/c;->e(Lu3/g;)V

    .line 65
    .line 66
    .line 67
    :cond_2
    iget v0, p0, Lx2/r;->f:I

    .line 68
    .line 69
    and-int/lit8 v0, v0, 0x8

    .line 70
    .line 71
    if-eqz v0, :cond_3

    .line 72
    .line 73
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    check-cast p0, Lw3/t;

    .line 78
    .line 79
    invoke-virtual {p0}, Lw3/t;->y()V

    .line 80
    .line 81
    .line 82
    :cond_3
    return-void
.end method

.method public final Z0()V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lv3/c;->t:Ljava/util/HashSet;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/util/HashSet;->clear()V

    .line 8
    .line 9
    .line 10
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Lw3/t;

    .line 15
    .line 16
    invoke-virtual {v0}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sget-object v1, Lv3/e;->g:Lv3/e;

    .line 21
    .line 22
    new-instance v2, Lv3/b;

    .line 23
    .line 24
    const/4 v3, 0x1

    .line 25
    invoke-direct {v2, p0, v3}, Lv3/b;-><init>(Lv3/c;I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0, p0, v1, v2}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 29
    .line 30
    .line 31
    :cond_0
    return-void
.end method

.method public final a()Lt4/c;
    .locals 0

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv3/h0;->A:Lt4/c;

    .line 6
    .line 7
    return-object p0
.end method

.method public final a0(Ld4/l;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v0, v0, Lv3/c;->r:Lx2/q;

    .line 6
    .line 7
    const-string v2, "null cannot be cast to non-null type androidx.compose.ui.semantics.SemanticsModifier"

    .line 8
    .line 9
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    check-cast v0, Ld4/m;

    .line 13
    .line 14
    invoke-interface {v0}, Ld4/m;->i()Ld4/l;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v2, "null cannot be cast to non-null type androidx.compose.ui.semantics.SemanticsConfiguration"

    .line 19
    .line 20
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v2, v1, Ld4/l;->d:Landroidx/collection/q0;

    .line 24
    .line 25
    iget-boolean v3, v0, Ld4/l;->f:Z

    .line 26
    .line 27
    const/4 v4, 0x1

    .line 28
    if-eqz v3, :cond_0

    .line 29
    .line 30
    iput-boolean v4, v1, Ld4/l;->f:Z

    .line 31
    .line 32
    :cond_0
    iget-boolean v3, v0, Ld4/l;->g:Z

    .line 33
    .line 34
    if-eqz v3, :cond_1

    .line 35
    .line 36
    iput-boolean v4, v1, Ld4/l;->g:Z

    .line 37
    .line 38
    :cond_1
    iget-object v0, v0, Ld4/l;->d:Landroidx/collection/q0;

    .line 39
    .line 40
    iget-object v1, v0, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 41
    .line 42
    iget-object v3, v0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 43
    .line 44
    iget-object v0, v0, Landroidx/collection/q0;->a:[J

    .line 45
    .line 46
    array-length v4, v0

    .line 47
    add-int/lit8 v4, v4, -0x2

    .line 48
    .line 49
    if-ltz v4, :cond_8

    .line 50
    .line 51
    const/4 v6, 0x0

    .line 52
    :goto_0
    aget-wide v7, v0, v6

    .line 53
    .line 54
    not-long v9, v7

    .line 55
    const/4 v11, 0x7

    .line 56
    shl-long/2addr v9, v11

    .line 57
    and-long/2addr v9, v7

    .line 58
    const-wide v11, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 59
    .line 60
    .line 61
    .line 62
    .line 63
    and-long/2addr v9, v11

    .line 64
    cmp-long v9, v9, v11

    .line 65
    .line 66
    if-eqz v9, :cond_7

    .line 67
    .line 68
    sub-int v9, v6, v4

    .line 69
    .line 70
    not-int v9, v9

    .line 71
    ushr-int/lit8 v9, v9, 0x1f

    .line 72
    .line 73
    const/16 v10, 0x8

    .line 74
    .line 75
    rsub-int/lit8 v9, v9, 0x8

    .line 76
    .line 77
    const/4 v11, 0x0

    .line 78
    :goto_1
    if-ge v11, v9, :cond_6

    .line 79
    .line 80
    const-wide/16 v12, 0xff

    .line 81
    .line 82
    and-long/2addr v12, v7

    .line 83
    const-wide/16 v14, 0x80

    .line 84
    .line 85
    cmp-long v12, v12, v14

    .line 86
    .line 87
    if-gez v12, :cond_5

    .line 88
    .line 89
    shl-int/lit8 v12, v6, 0x3

    .line 90
    .line 91
    add-int/2addr v12, v11

    .line 92
    aget-object v13, v1, v12

    .line 93
    .line 94
    aget-object v12, v3, v12

    .line 95
    .line 96
    check-cast v13, Ld4/z;

    .line 97
    .line 98
    invoke-virtual {v2, v13}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v14

    .line 102
    if-nez v14, :cond_2

    .line 103
    .line 104
    invoke-virtual {v2, v13, v12}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_2
    instance-of v14, v12, Ld4/a;

    .line 109
    .line 110
    if-eqz v14, :cond_5

    .line 111
    .line 112
    invoke-virtual {v2, v13}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v14

    .line 116
    const-string v15, "null cannot be cast to non-null type androidx.compose.ui.semantics.AccessibilityAction<*>"

    .line 117
    .line 118
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    check-cast v14, Ld4/a;

    .line 122
    .line 123
    new-instance v15, Ld4/a;

    .line 124
    .line 125
    iget-object v5, v14, Ld4/a;->a:Ljava/lang/String;

    .line 126
    .line 127
    if-nez v5, :cond_3

    .line 128
    .line 129
    move-object v5, v12

    .line 130
    check-cast v5, Ld4/a;

    .line 131
    .line 132
    iget-object v5, v5, Ld4/a;->a:Ljava/lang/String;

    .line 133
    .line 134
    :cond_3
    iget-object v14, v14, Ld4/a;->b:Llx0/e;

    .line 135
    .line 136
    if-nez v14, :cond_4

    .line 137
    .line 138
    check-cast v12, Ld4/a;

    .line 139
    .line 140
    iget-object v14, v12, Ld4/a;->b:Llx0/e;

    .line 141
    .line 142
    :cond_4
    invoke-direct {v15, v5, v14}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v2, v13, v15}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    :cond_5
    :goto_2
    shr-long/2addr v7, v10

    .line 149
    add-int/lit8 v11, v11, 0x1

    .line 150
    .line 151
    goto :goto_1

    .line 152
    :cond_6
    if-ne v9, v10, :cond_8

    .line 153
    .line 154
    :cond_7
    if-eq v6, v4, :cond_8

    .line 155
    .line 156
    add-int/lit8 v6, v6, 0x1

    .line 157
    .line 158
    goto :goto_0

    .line 159
    :cond_8
    return-void
.end method

.method public final b(Lu3/h;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget-object v0, p0, Lv3/c;->t:Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lx2/r;->d:Lx2/r;

    .line 7
    .line 8
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    const-string v0, "visitAncestors called on an unattached node"

    .line 13
    .line 14
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    iget-object v0, p0, Lx2/r;->d:Lx2/r;

    .line 18
    .line 19
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 20
    .line 21
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :goto_0
    if-eqz p0, :cond_b

    .line 26
    .line 27
    iget-object v1, p0, Lv3/h0;->H:Lg1/q;

    .line 28
    .line 29
    iget-object v1, v1, Lg1/q;->g:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v1, Lx2/r;

    .line 32
    .line 33
    iget v1, v1, Lx2/r;->g:I

    .line 34
    .line 35
    and-int/lit8 v1, v1, 0x20

    .line 36
    .line 37
    const/4 v2, 0x0

    .line 38
    if-eqz v1, :cond_9

    .line 39
    .line 40
    :goto_1
    if-eqz v0, :cond_9

    .line 41
    .line 42
    iget v1, v0, Lx2/r;->f:I

    .line 43
    .line 44
    and-int/lit8 v1, v1, 0x20

    .line 45
    .line 46
    if-eqz v1, :cond_8

    .line 47
    .line 48
    move-object v1, v0

    .line 49
    move-object v3, v2

    .line 50
    :goto_2
    if-eqz v1, :cond_8

    .line 51
    .line 52
    instance-of v4, v1, Lu3/e;

    .line 53
    .line 54
    if-eqz v4, :cond_1

    .line 55
    .line 56
    check-cast v1, Lu3/e;

    .line 57
    .line 58
    invoke-interface {v1}, Lu3/e;->G()Llp/e1;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    invoke-virtual {v4, p1}, Llp/e1;->a(Lu3/h;)Z

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    if-eqz v4, :cond_7

    .line 67
    .line 68
    invoke-interface {v1}, Lu3/e;->G()Llp/e1;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-virtual {p0, p1}, Llp/e1;->b(Lu3/h;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0

    .line 77
    :cond_1
    iget v4, v1, Lx2/r;->f:I

    .line 78
    .line 79
    and-int/lit8 v4, v4, 0x20

    .line 80
    .line 81
    if-eqz v4, :cond_7

    .line 82
    .line 83
    instance-of v4, v1, Lv3/n;

    .line 84
    .line 85
    if-eqz v4, :cond_7

    .line 86
    .line 87
    move-object v4, v1

    .line 88
    check-cast v4, Lv3/n;

    .line 89
    .line 90
    iget-object v4, v4, Lv3/n;->s:Lx2/r;

    .line 91
    .line 92
    const/4 v5, 0x0

    .line 93
    :goto_3
    const/4 v6, 0x1

    .line 94
    if-eqz v4, :cond_6

    .line 95
    .line 96
    iget v7, v4, Lx2/r;->f:I

    .line 97
    .line 98
    and-int/lit8 v7, v7, 0x20

    .line 99
    .line 100
    if-eqz v7, :cond_5

    .line 101
    .line 102
    add-int/lit8 v5, v5, 0x1

    .line 103
    .line 104
    if-ne v5, v6, :cond_2

    .line 105
    .line 106
    move-object v1, v4

    .line 107
    goto :goto_4

    .line 108
    :cond_2
    if-nez v3, :cond_3

    .line 109
    .line 110
    new-instance v3, Ln2/b;

    .line 111
    .line 112
    const/16 v6, 0x10

    .line 113
    .line 114
    new-array v6, v6, [Lx2/r;

    .line 115
    .line 116
    invoke-direct {v3, v6}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    :cond_3
    if-eqz v1, :cond_4

    .line 120
    .line 121
    invoke-virtual {v3, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    move-object v1, v2

    .line 125
    :cond_4
    invoke-virtual {v3, v4}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :cond_5
    :goto_4
    iget-object v4, v4, Lx2/r;->i:Lx2/r;

    .line 129
    .line 130
    goto :goto_3

    .line 131
    :cond_6
    if-ne v5, v6, :cond_7

    .line 132
    .line 133
    goto :goto_2

    .line 134
    :cond_7
    invoke-static {v3}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    goto :goto_2

    .line 139
    :cond_8
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_9
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    if-eqz p0, :cond_a

    .line 147
    .line 148
    iget-object v0, p0, Lv3/h0;->H:Lg1/q;

    .line 149
    .line 150
    if-eqz v0, :cond_a

    .line 151
    .line 152
    iget-object v0, v0, Lg1/q;->f:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v0, Lv3/z1;

    .line 155
    .line 156
    goto/16 :goto_0

    .line 157
    .line 158
    :cond_a
    move-object v0, v2

    .line 159
    goto/16 :goto_0

    .line 160
    .line 161
    :cond_b
    iget-object p0, p1, Lu3/h;->a:Lay0/a;

    .line 162
    .line 163
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    return-object p0
.end method

.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 1

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier"

    .line 4
    .line 5
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lt3/c0;

    .line 9
    .line 10
    invoke-interface {p0, p1, p2, p3, p4}, Lt3/c0;->c(Lt3/s0;Lt3/p0;J)Lt3/r0;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public final d()V
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    instance-of v0, v0, Lp3/a0;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lv3/c;->l0()V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final e()J
    .locals 2

    .line 1
    const/16 v0, 0x80

    .line 2
    .line 3
    invoke-static {p0, v0}, Lv3/f;->v(Lv3/m;I)Lv3/f1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-wide v0, p0, Lt3/e1;->f:J

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkp/f9;->c(J)J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    return-wide v0
.end method

.method public final e0()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getLayoutDirection()Lt4/m;
    .locals 0

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv3/h0;->B:Lt4/m;

    .line 6
    .line 7
    return-object p0
.end method

.method public final h(J)V
    .locals 0

    .line 1
    return-void
.end method

.method public final l(Lt4/c;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string p1, "null cannot be cast to non-null type androidx.compose.ui.layout.ParentDataModifier"

    .line 4
    .line 5
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lt3/b1;

    .line 9
    .line 10
    invoke-interface {p0}, Lt3/b1;->f()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public final l0()V
    .locals 11

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.PointerInputModifier"

    .line 4
    .line 5
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lp3/a0;

    .line 9
    .line 10
    iget-object p0, p0, Lp3/a0;->e:Lcom/google/firebase/messaging/w;

    .line 11
    .line 12
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v0, Lp3/y;

    .line 15
    .line 16
    iget-object v1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v1, Lp3/a0;

    .line 19
    .line 20
    sget-object v2, Lp3/y;->e:Lp3/y;

    .line 21
    .line 22
    if-ne v0, v2, :cond_0

    .line 23
    .line 24
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 25
    .line 26
    .line 27
    move-result-wide v3

    .line 28
    new-instance v0, Lp3/z;

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    invoke-direct {v0, v1, v2}, Lp3/z;-><init>(Lp3/a0;I)V

    .line 32
    .line 33
    .line 34
    const/4 v9, 0x0

    .line 35
    const/4 v10, 0x0

    .line 36
    const/4 v7, 0x3

    .line 37
    const/4 v8, 0x0

    .line 38
    move-wide v5, v3

    .line 39
    invoke-static/range {v3 .. v10}, Landroid/view/MotionEvent;->obtain(JJIFFI)Landroid/view/MotionEvent;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    const/4 v3, 0x0

    .line 44
    invoke-virtual {v2, v3}, Landroid/view/MotionEvent;->setSource(I)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0, v2}, Lp3/z;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v2}, Landroid/view/MotionEvent;->recycle()V

    .line 51
    .line 52
    .line 53
    sget-object v0, Lp3/y;->d:Lp3/y;

    .line 54
    .line 55
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 56
    .line 57
    iput-boolean v3, v1, Lp3/a0;->d:Z

    .line 58
    .line 59
    const/4 v0, 0x0

    .line 60
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 61
    .line 62
    :cond_0
    return-void
.end method

.method public final m0()V
    .locals 0

    .line 1
    invoke-static {p0}, Lv3/f;->m(Lv3/p;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final t(Lc3/m;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string p1, "applyFocusProperties called on wrong node"

    .line 4
    .line 5
    invoke-static {p1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    new-instance p0, Ljava/lang/ClassCastException;

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 14
    .line 15
    .line 16
    throw p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final v0(Lp3/k;Lp3/l;J)V
    .locals 9

    .line 1
    iget-object p0, p0, Lv3/c;->r:Lx2/q;

    .line 2
    .line 3
    const-string p3, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.PointerInputModifier"

    .line 4
    .line 5
    invoke-static {p0, p3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lp3/a0;

    .line 9
    .line 10
    iget-object p0, p0, Lp3/a0;->e:Lcom/google/firebase/messaging/w;

    .line 11
    .line 12
    iget-object p3, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p3, Lp3/a0;

    .line 15
    .line 16
    iget-object p4, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v0, p4

    .line 19
    check-cast v0, Ljava/util/Collection;

    .line 20
    .line 21
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const/4 v2, 0x0

    .line 26
    move v3, v2

    .line 27
    :goto_0
    const/4 v4, 0x1

    .line 28
    if-ge v3, v1, :cond_1

    .line 29
    .line 30
    invoke-interface {p4, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v5

    .line 34
    check-cast v5, Lp3/t;

    .line 35
    .line 36
    invoke-static {v5}, Lp3/s;->b(Lp3/t;)Z

    .line 37
    .line 38
    .line 39
    move-result v6

    .line 40
    if-nez v6, :cond_0

    .line 41
    .line 42
    invoke-static {v5}, Lp3/s;->d(Lp3/t;)Z

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    if-nez v5, :cond_0

    .line 47
    .line 48
    add-int/lit8 v3, v3, 0x1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    move v1, v2

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    move v1, v4

    .line 54
    :goto_1
    if-eqz v1, :cond_4

    .line 55
    .line 56
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    move v5, v2

    .line 61
    :goto_2
    if-ge v5, v3, :cond_3

    .line 62
    .line 63
    invoke-interface {p4, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v6

    .line 67
    check-cast v6, Lp3/t;

    .line 68
    .line 69
    invoke-virtual {v6}, Lp3/t;->b()Z

    .line 70
    .line 71
    .line 72
    move-result v6

    .line 73
    if-eqz v6, :cond_2

    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_2
    add-int/lit8 v5, v5, 0x1

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_3
    move v3, v4

    .line 80
    goto :goto_4

    .line 81
    :cond_4
    :goto_3
    move v3, v2

    .line 82
    :goto_4
    iget-boolean v5, p3, Lp3/a0;->d:Z

    .line 83
    .line 84
    if-nez v5, :cond_8

    .line 85
    .line 86
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 87
    .line 88
    .line 89
    move-result v5

    .line 90
    move v6, v2

    .line 91
    :goto_5
    if-ge v6, v5, :cond_6

    .line 92
    .line 93
    invoke-interface {p4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v7

    .line 97
    check-cast v7, Lp3/t;

    .line 98
    .line 99
    invoke-static {v7}, Lp3/s;->b(Lp3/t;)Z

    .line 100
    .line 101
    .line 102
    move-result v8

    .line 103
    if-nez v8, :cond_8

    .line 104
    .line 105
    invoke-static {v7}, Lp3/s;->d(Lp3/t;)Z

    .line 106
    .line 107
    .line 108
    move-result v7

    .line 109
    if-eqz v7, :cond_5

    .line 110
    .line 111
    goto :goto_6

    .line 112
    :cond_5
    add-int/lit8 v6, v6, 0x1

    .line 113
    .line 114
    goto :goto_5

    .line 115
    :cond_6
    if-eqz v3, :cond_7

    .line 116
    .line 117
    goto :goto_6

    .line 118
    :cond_7
    move v3, v2

    .line 119
    goto :goto_7

    .line 120
    :cond_8
    :goto_6
    move v3, v4

    .line 121
    :goto_7
    iget-object v5, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v5, Lp3/y;

    .line 124
    .line 125
    sget-object v6, Lp3/y;->f:Lp3/y;

    .line 126
    .line 127
    if-eq v5, v6, :cond_d

    .line 128
    .line 129
    sget-object v5, Lp3/l;->d:Lp3/l;

    .line 130
    .line 131
    if-ne p2, v5, :cond_b

    .line 132
    .line 133
    if-eqz v3, :cond_b

    .line 134
    .line 135
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 136
    .line 137
    if-eqz v1, :cond_a

    .line 138
    .line 139
    iget-boolean v5, p3, Lp3/a0;->d:Z

    .line 140
    .line 141
    if-eqz v5, :cond_9

    .line 142
    .line 143
    goto :goto_8

    .line 144
    :cond_9
    move v5, v2

    .line 145
    goto :goto_9

    .line 146
    :cond_a
    :goto_8
    move v5, v4

    .line 147
    :goto_9
    invoke-virtual {p0, p1, v5}, Lcom/google/firebase/messaging/w;->f(Lp3/k;Z)V

    .line 148
    .line 149
    .line 150
    :cond_b
    sget-object v5, Lp3/l;->e:Lp3/l;

    .line 151
    .line 152
    if-ne p2, v5, :cond_c

    .line 153
    .line 154
    if-eqz v1, :cond_c

    .line 155
    .line 156
    iget-object v5, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v5, Lp3/k;

    .line 159
    .line 160
    invoke-virtual {p1, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v5

    .line 164
    if-eqz v5, :cond_c

    .line 165
    .line 166
    iget-boolean v5, p3, Lp3/a0;->d:Z

    .line 167
    .line 168
    if-eqz v5, :cond_c

    .line 169
    .line 170
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 171
    .line 172
    .line 173
    move-result v5

    .line 174
    move v6, v2

    .line 175
    :goto_a
    if-ge v6, v5, :cond_c

    .line 176
    .line 177
    invoke-interface {p4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v7

    .line 181
    check-cast v7, Lp3/t;

    .line 182
    .line 183
    invoke-virtual {v7}, Lp3/t;->a()V

    .line 184
    .line 185
    .line 186
    add-int/lit8 v6, v6, 0x1

    .line 187
    .line 188
    goto :goto_a

    .line 189
    :cond_c
    sget-object v5, Lp3/l;->f:Lp3/l;

    .line 190
    .line 191
    if-ne p2, v5, :cond_d

    .line 192
    .line 193
    if-nez v3, :cond_d

    .line 194
    .line 195
    iget-object v3, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast v3, Lp3/k;

    .line 198
    .line 199
    invoke-virtual {p1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v3

    .line 203
    if-nez v3, :cond_d

    .line 204
    .line 205
    invoke-virtual {p0, p1, v4}, Lcom/google/firebase/messaging/w;->f(Lp3/k;Z)V

    .line 206
    .line 207
    .line 208
    :cond_d
    sget-object v3, Lp3/l;->f:Lp3/l;

    .line 209
    .line 210
    if-ne p2, v3, :cond_12

    .line 211
    .line 212
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 213
    .line 214
    .line 215
    move-result p2

    .line 216
    move v3, v2

    .line 217
    :goto_b
    if-ge v3, p2, :cond_f

    .line 218
    .line 219
    invoke-interface {p4, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v4

    .line 223
    check-cast v4, Lp3/t;

    .line 224
    .line 225
    invoke-static {v4}, Lp3/s;->d(Lp3/t;)Z

    .line 226
    .line 227
    .line 228
    move-result v4

    .line 229
    if-nez v4, :cond_e

    .line 230
    .line 231
    goto :goto_c

    .line 232
    :cond_e
    add-int/lit8 v3, v3, 0x1

    .line 233
    .line 234
    goto :goto_b

    .line 235
    :cond_f
    sget-object p2, Lp3/y;->d:Lp3/y;

    .line 236
    .line 237
    iput-object p2, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 238
    .line 239
    iget-object p2, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 240
    .line 241
    check-cast p2, Lp3/a0;

    .line 242
    .line 243
    iput-boolean v2, p2, Lp3/a0;->d:Z

    .line 244
    .line 245
    const/4 p2, 0x0

    .line 246
    iput-object p2, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 247
    .line 248
    :goto_c
    iget-object p2, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 249
    .line 250
    check-cast p2, Lp3/k;

    .line 251
    .line 252
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 253
    .line 254
    .line 255
    move-result p2

    .line 256
    if-eqz p2, :cond_12

    .line 257
    .line 258
    if-eqz v1, :cond_12

    .line 259
    .line 260
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 261
    .line 262
    .line 263
    move-result p2

    .line 264
    move v1, v2

    .line 265
    :goto_d
    if-ge v1, p2, :cond_11

    .line 266
    .line 267
    invoke-interface {p4, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v3

    .line 271
    check-cast v3, Lp3/t;

    .line 272
    .line 273
    invoke-virtual {v3}, Lp3/t;->b()Z

    .line 274
    .line 275
    .line 276
    move-result v3

    .line 277
    if-eqz v3, :cond_10

    .line 278
    .line 279
    iget-boolean p2, p3, Lp3/a0;->d:Z

    .line 280
    .line 281
    if-nez p2, :cond_11

    .line 282
    .line 283
    invoke-virtual {p0, p1}, Lcom/google/firebase/messaging/w;->s(Lp3/k;)V

    .line 284
    .line 285
    .line 286
    return-void

    .line 287
    :cond_10
    add-int/lit8 v1, v1, 0x1

    .line 288
    .line 289
    goto :goto_d

    .line 290
    :cond_11
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 291
    .line 292
    .line 293
    move-result p0

    .line 294
    :goto_e
    if-ge v2, p0, :cond_12

    .line 295
    .line 296
    invoke-interface {p4, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object p1

    .line 300
    check-cast p1, Lp3/t;

    .line 301
    .line 302
    invoke-virtual {p1}, Lp3/t;->a()V

    .line 303
    .line 304
    .line 305
    add-int/lit8 v2, v2, 0x1

    .line 306
    .line 307
    goto :goto_e

    .line 308
    :cond_12
    return-void
.end method
