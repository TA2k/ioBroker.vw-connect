.class public final Lg1/p2;
.super Lg1/d1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ln3/d;
.implements Lv3/x1;
.implements Lv3/l;


# instance fields
.field public C:Le1/j;

.field public D:Lg1/j1;

.field public final E:Lo3/d;

.field public final F:Lg1/f2;

.field public final G:Lg1/d0;

.field public final H:Lg1/u2;

.field public final I:Lg1/l2;

.field public final J:Lg1/y;

.field public K:La71/a0;

.field public L:Lg1/m2;

.field public M:Lb0/d1;


# direct methods
.method public constructor <init>(Le1/j;Lg1/u;Lg1/j1;Lg1/w1;Lg1/q2;Li1/l;ZZ)V
    .locals 10

    .line 1
    move/from16 v9, p7

    .line 2
    .line 3
    sget-object v0, Landroidx/compose/foundation/gestures/b;->a:Lfw0/i0;

    .line 4
    .line 5
    move-object/from16 v1, p6

    .line 6
    .line 7
    invoke-direct {p0, v0, v9, v1, p4}, Lg1/d1;-><init>(Lay0/k;ZLi1/l;Lg1/w1;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lg1/p2;->C:Le1/j;

    .line 11
    .line 12
    iput-object p3, p0, Lg1/p2;->D:Lg1/j1;

    .line 13
    .line 14
    new-instance v6, Lo3/d;

    .line 15
    .line 16
    invoke-direct {v6}, Lo3/d;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object v6, p0, Lg1/p2;->E:Lo3/d;

    .line 20
    .line 21
    new-instance v0, Lg1/f2;

    .line 22
    .line 23
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-boolean v9, v0, Lg1/f2;->r:Z

    .line 27
    .line 28
    invoke-virtual {p0, v0}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Lg1/p2;->F:Lg1/f2;

    .line 32
    .line 33
    new-instance v0, Lg1/d0;

    .line 34
    .line 35
    sget-object v1, Landroidx/compose/foundation/gestures/b;->d:Lg1/i2;

    .line 36
    .line 37
    new-instance v2, La0/j;

    .line 38
    .line 39
    invoke-direct {v2, v1}, La0/j;-><init>(Lt4/c;)V

    .line 40
    .line 41
    .line 42
    new-instance v1, Lc1/u;

    .line 43
    .line 44
    invoke-direct {v1, v2}, Lc1/u;-><init>(Lc1/c0;)V

    .line 45
    .line 46
    .line 47
    invoke-direct {v0, v1}, Lg1/d0;-><init>(Lc1/u;)V

    .line 48
    .line 49
    .line 50
    iput-object v0, p0, Lg1/p2;->G:Lg1/d0;

    .line 51
    .line 52
    iget-object v2, p0, Lg1/p2;->C:Le1/j;

    .line 53
    .line 54
    iget-object v1, p0, Lg1/p2;->D:Lg1/j1;

    .line 55
    .line 56
    if-nez v1, :cond_0

    .line 57
    .line 58
    move-object v3, v0

    .line 59
    goto :goto_0

    .line 60
    :cond_0
    move-object v3, v1

    .line 61
    :goto_0
    new-instance v0, Lg1/u2;

    .line 62
    .line 63
    new-instance v8, Ld2/g;

    .line 64
    .line 65
    const/16 v1, 0x11

    .line 66
    .line 67
    invoke-direct {v8, p0, v1}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 68
    .line 69
    .line 70
    move-object v7, p0

    .line 71
    move-object v4, p4

    .line 72
    move-object v1, p5

    .line 73
    move/from16 v5, p8

    .line 74
    .line 75
    invoke-direct/range {v0 .. v8}, Lg1/u2;-><init>(Lg1/q2;Le1/j;Lg1/j1;Lg1/w1;ZLo3/d;Lg1/p2;Ld2/g;)V

    .line 76
    .line 77
    .line 78
    iput-object v0, p0, Lg1/p2;->H:Lg1/u2;

    .line 79
    .line 80
    new-instance v1, Lg1/l2;

    .line 81
    .line 82
    invoke-direct {v1, v0, v9}, Lg1/l2;-><init>(Lg1/u2;Z)V

    .line 83
    .line 84
    .line 85
    iput-object v1, p0, Lg1/p2;->I:Lg1/l2;

    .line 86
    .line 87
    new-instance v2, Lg1/y;

    .line 88
    .line 89
    invoke-direct {v2, p4, v0, v5, p2}, Lg1/y;-><init>(Lg1/w1;Lg1/u2;ZLg1/u;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {p0, v2}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 93
    .line 94
    .line 95
    iput-object v2, p0, Lg1/p2;->J:Lg1/y;

    .line 96
    .line 97
    new-instance v0, Lo3/g;

    .line 98
    .line 99
    invoke-direct {v0, v1, v6}, Lo3/g;-><init>(Lo3/a;Lo3/d;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p0, v0}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 103
    .line 104
    .line 105
    new-instance v0, Lc3/v;

    .line 106
    .line 107
    const/4 v1, 0x4

    .line 108
    const/4 v3, 0x2

    .line 109
    const/4 v4, 0x0

    .line 110
    invoke-direct {v0, v3, v4, v1}, Lc3/v;-><init>(ILay0/n;I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p0, v0}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 114
    .line 115
    .line 116
    new-instance v0, Lq1/e;

    .line 117
    .line 118
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 119
    .line 120
    .line 121
    iput-object v2, v0, Lq1/e;->r:Lg1/y;

    .line 122
    .line 123
    invoke-virtual {p0, v0}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 124
    .line 125
    .line 126
    new-instance v0, Le1/h0;

    .line 127
    .line 128
    new-instance v1, Le81/w;

    .line 129
    .line 130
    const/16 v2, 0xd

    .line 131
    .line 132
    invoke-direct {v1, p0, v2}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 133
    .line 134
    .line 135
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 136
    .line 137
    .line 138
    iput-object v1, v0, Le1/h0;->r:Le81/w;

    .line 139
    .line 140
    invoke-virtual {p0, v0}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 141
    .line 142
    .line 143
    return-void
.end method


# virtual methods
.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final P0()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iget-object v0, v0, Lv3/h0;->A:Lt4/c;

    .line 11
    .line 12
    iget-object v1, p0, Lg1/p2;->G:Lg1/d0;

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    new-instance v2, La0/j;

    .line 18
    .line 19
    invoke-direct {v2, v0}, La0/j;-><init>(Lt4/c;)V

    .line 20
    .line 21
    .line 22
    new-instance v0, Lc1/u;

    .line 23
    .line 24
    invoke-direct {v0, v2}, Lc1/u;-><init>(Lc1/c0;)V

    .line 25
    .line 26
    .line 27
    iput-object v0, v1, Lg1/d0;->a:Lc1/u;

    .line 28
    .line 29
    :goto_0
    iget-object v0, p0, Lg1/p2;->M:Lb0/d1;

    .line 30
    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    iget-object p0, p0, Lv3/h0;->A:Lt4/c;

    .line 38
    .line 39
    iput-object p0, v0, Lb0/d1;->h:Ljava/lang/Object;

    .line 40
    .line 41
    :cond_1
    return-void
.end method

.method public final Z(Landroid/view/KeyEvent;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final a0(Ld4/l;)V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lg1/d1;->v:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_1

    .line 5
    .line 6
    iget-object v0, p0, Lg1/p2;->K:La71/a0;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lg1/p2;->L:Lg1/m2;

    .line 11
    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    :cond_0
    new-instance v0, La71/a0;

    .line 15
    .line 16
    const/16 v2, 0x18

    .line 17
    .line 18
    invoke-direct {v0, p0, v2}, La71/a0;-><init>(Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lg1/p2;->K:La71/a0;

    .line 22
    .line 23
    new-instance v0, Lg1/m2;

    .line 24
    .line 25
    invoke-direct {v0, p0, v1}, Lg1/m2;-><init>(Lg1/p2;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lg1/p2;->L:Lg1/m2;

    .line 29
    .line 30
    :cond_1
    iget-object v0, p0, Lg1/p2;->K:La71/a0;

    .line 31
    .line 32
    if-eqz v0, :cond_2

    .line 33
    .line 34
    sget-object v2, Ld4/x;->a:[Lhy0/z;

    .line 35
    .line 36
    sget-object v2, Ld4/k;->d:Ld4/z;

    .line 37
    .line 38
    new-instance v3, Ld4/a;

    .line 39
    .line 40
    invoke-direct {v3, v1, v0}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1, v2, v3}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    :cond_2
    iget-object p0, p0, Lg1/p2;->L:Lg1/m2;

    .line 47
    .line 48
    if-eqz p0, :cond_3

    .line 49
    .line 50
    sget-object v0, Ld4/x;->a:[Lhy0/z;

    .line 51
    .line 52
    sget-object v0, Ld4/k;->e:Ld4/z;

    .line 53
    .line 54
    invoke-virtual {p1, v0, p0}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    :cond_3
    return-void
.end method

.method public final d()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lg1/d1;->l0()V

    .line 2
    .line 3
    .line 4
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object v0, v0, Lv3/h0;->A:Lt4/c;

    .line 14
    .line 15
    iget-object v1, p0, Lg1/p2;->G:Lg1/d0;

    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    new-instance v2, La0/j;

    .line 21
    .line 22
    invoke-direct {v2, v0}, La0/j;-><init>(Lt4/c;)V

    .line 23
    .line 24
    .line 25
    new-instance v0, Lc1/u;

    .line 26
    .line 27
    invoke-direct {v0, v2}, Lc1/u;-><init>(Lc1/c0;)V

    .line 28
    .line 29
    .line 30
    iput-object v0, v1, Lg1/d0;->a:Lc1/u;

    .line 31
    .line 32
    :goto_0
    iget-object v0, p0, Lg1/p2;->M:Lb0/d1;

    .line 33
    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    iget-object p0, p0, Lv3/h0;->A:Lt4/c;

    .line 41
    .line 42
    iput-object p0, v0, Lb0/d1;->h:Ljava/lang/Object;

    .line 43
    .line 44
    :cond_1
    return-void
.end method

.method public final e1(Lg1/c1;Lg1/c1;)Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Le1/w0;->e:Le1/w0;

    .line 2
    .line 3
    new-instance v1, Le1/e;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/16 v3, 0x1c

    .line 7
    .line 8
    iget-object p0, p0, Lg1/p2;->H:Lg1/u2;

    .line 9
    .line 10
    invoke-direct {v1, v3, p1, p0, v2}, Le1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, v0, v1, p2}, Lg1/u2;->f(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 18
    .line 19
    if-ne p0, p1, :cond_0

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method

.method public final f1(J)V
    .locals 0

    .line 1
    return-void
.end method

.method public final g1(J)V
    .locals 7

    .line 1
    iget-object v0, p0, Lg1/p2;->E:Lo3/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Lo3/d;->c()Lvy0/b0;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lg1/m2;

    .line 8
    .line 9
    const/4 v6, 0x0

    .line 10
    const/4 v5, 0x0

    .line 11
    move-object v2, p0

    .line 12
    move-wide v3, p1

    .line 13
    invoke-direct/range {v1 .. v6}, Lg1/m2;-><init>(Lg1/p2;JLkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x3

    .line 17
    invoke-static {v0, v5, v5, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final h0(Landroid/view/KeyEvent;)Z
    .locals 11

    .line 1
    iget-boolean v0, p0, Lg1/d1;->v:Z

    .line 2
    .line 3
    if-eqz v0, :cond_4

    .line 4
    .line 5
    invoke-static {p1}, Ln3/c;->b(Landroid/view/KeyEvent;)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    sget-wide v2, Ln3/a;->p:J

    .line 10
    .line 11
    invoke-static {v0, v1, v2, v3}, Ln3/a;->a(JJ)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-static {v0}, Ljp/x1;->a(I)J

    .line 22
    .line 23
    .line 24
    move-result-wide v0

    .line 25
    sget-wide v2, Ln3/a;->o:J

    .line 26
    .line 27
    invoke-static {v0, v1, v2, v3}, Ln3/a;->a(JJ)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_4

    .line 32
    .line 33
    :cond_0
    invoke-static {p1}, Ln3/c;->c(Landroid/view/KeyEvent;)I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    const/4 v1, 0x2

    .line 38
    if-ne v0, v1, :cond_4

    .line 39
    .line 40
    invoke-virtual {p1}, Landroid/view/KeyEvent;->isCtrlPressed()Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-nez v0, :cond_4

    .line 45
    .line 46
    iget-object v0, p0, Lg1/p2;->H:Lg1/u2;

    .line 47
    .line 48
    iget-object v0, v0, Lg1/u2;->d:Lg1/w1;

    .line 49
    .line 50
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 51
    .line 52
    const/4 v2, 0x0

    .line 53
    iget-object v3, p0, Lg1/p2;->J:Lg1/y;

    .line 54
    .line 55
    const/16 v4, 0x20

    .line 56
    .line 57
    const-wide v5, 0xffffffffL

    .line 58
    .line 59
    .line 60
    .line 61
    .line 62
    if-ne v0, v1, :cond_2

    .line 63
    .line 64
    iget-wide v0, v3, Lg1/y;->z:J

    .line 65
    .line 66
    and-long/2addr v0, v5

    .line 67
    long-to-int v0, v0

    .line 68
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    invoke-static {p1}, Ljp/x1;->a(I)J

    .line 73
    .line 74
    .line 75
    move-result-wide v7

    .line 76
    sget-wide v9, Ln3/a;->o:J

    .line 77
    .line 78
    invoke-static {v7, v8, v9, v10}, Ln3/a;->a(JJ)Z

    .line 79
    .line 80
    .line 81
    move-result p1

    .line 82
    if-eqz p1, :cond_1

    .line 83
    .line 84
    int-to-float p1, v0

    .line 85
    goto :goto_0

    .line 86
    :cond_1
    int-to-float p1, v0

    .line 87
    neg-float p1, p1

    .line 88
    :goto_0
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    int-to-long v0, v0

    .line 93
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    :goto_1
    int-to-long v2, p1

    .line 98
    shl-long/2addr v0, v4

    .line 99
    and-long/2addr v2, v5

    .line 100
    or-long/2addr v0, v2

    .line 101
    move-wide v4, v0

    .line 102
    goto :goto_3

    .line 103
    :cond_2
    iget-wide v0, v3, Lg1/y;->z:J

    .line 104
    .line 105
    shr-long/2addr v0, v4

    .line 106
    long-to-int v0, v0

    .line 107
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 108
    .line 109
    .line 110
    move-result p1

    .line 111
    invoke-static {p1}, Ljp/x1;->a(I)J

    .line 112
    .line 113
    .line 114
    move-result-wide v7

    .line 115
    sget-wide v9, Ln3/a;->o:J

    .line 116
    .line 117
    invoke-static {v7, v8, v9, v10}, Ln3/a;->a(JJ)Z

    .line 118
    .line 119
    .line 120
    move-result p1

    .line 121
    if-eqz p1, :cond_3

    .line 122
    .line 123
    int-to-float p1, v0

    .line 124
    goto :goto_2

    .line 125
    :cond_3
    int-to-float p1, v0

    .line 126
    neg-float p1, p1

    .line 127
    :goto_2
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 128
    .line 129
    .line 130
    move-result p1

    .line 131
    int-to-long v0, p1

    .line 132
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 133
    .line 134
    .line 135
    move-result p1

    .line 136
    goto :goto_1

    .line 137
    :goto_3
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 138
    .line 139
    .line 140
    move-result-object p1

    .line 141
    new-instance v2, Lg1/m2;

    .line 142
    .line 143
    const/4 v7, 0x1

    .line 144
    const/4 v6, 0x0

    .line 145
    move-object v3, p0

    .line 146
    invoke-direct/range {v2 .. v7}, Lg1/m2;-><init>(Lg1/p2;JLkotlin/coroutines/Continuation;I)V

    .line 147
    .line 148
    .line 149
    const/4 p0, 0x3

    .line 150
    invoke-static {p1, v6, v6, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 151
    .line 152
    .line 153
    const/4 p0, 0x1

    .line 154
    return p0

    .line 155
    :cond_4
    const/4 p0, 0x0

    .line 156
    return p0
.end method

.method public final h1()Z
    .locals 4

    .line 1
    iget-object p0, p0, Lg1/p2;->H:Lg1/u2;

    .line 2
    .line 3
    iget-object v0, p0, Lg1/u2;->a:Lg1/q2;

    .line 4
    .line 5
    invoke-interface {v0}, Lg1/q2;->a()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_8

    .line 10
    .line 11
    iget-object p0, p0, Lg1/u2;->b:Le1/j;

    .line 12
    .line 13
    if-eqz p0, :cond_7

    .line 14
    .line 15
    iget-object p0, p0, Le1/j;->c:Le1/f0;

    .line 16
    .line 17
    iget-object v0, p0, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 18
    .line 19
    const/16 v1, 0x1f

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 25
    .line 26
    if-lt v3, v1, :cond_0

    .line 27
    .line 28
    invoke-static {v0}, Le1/m;->b(Landroid/widget/EdgeEffect;)F

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    move v0, v2

    .line 34
    :goto_0
    cmpg-float v0, v0, v2

    .line 35
    .line 36
    if-nez v0, :cond_8

    .line 37
    .line 38
    :cond_1
    iget-object v0, p0, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 39
    .line 40
    if-eqz v0, :cond_3

    .line 41
    .line 42
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 43
    .line 44
    if-lt v3, v1, :cond_2

    .line 45
    .line 46
    invoke-static {v0}, Le1/m;->b(Landroid/widget/EdgeEffect;)F

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    goto :goto_1

    .line 51
    :cond_2
    move v0, v2

    .line 52
    :goto_1
    cmpg-float v0, v0, v2

    .line 53
    .line 54
    if-nez v0, :cond_8

    .line 55
    .line 56
    :cond_3
    iget-object v0, p0, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 57
    .line 58
    if-eqz v0, :cond_5

    .line 59
    .line 60
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 61
    .line 62
    if-lt v3, v1, :cond_4

    .line 63
    .line 64
    invoke-static {v0}, Le1/m;->b(Landroid/widget/EdgeEffect;)F

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    goto :goto_2

    .line 69
    :cond_4
    move v0, v2

    .line 70
    :goto_2
    cmpg-float v0, v0, v2

    .line 71
    .line 72
    if-nez v0, :cond_8

    .line 73
    .line 74
    :cond_5
    iget-object p0, p0, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 75
    .line 76
    if-eqz p0, :cond_7

    .line 77
    .line 78
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 79
    .line 80
    if-lt v0, v1, :cond_6

    .line 81
    .line 82
    invoke-static {p0}, Le1/m;->b(Landroid/widget/EdgeEffect;)F

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    goto :goto_3

    .line 87
    :cond_6
    move p0, v2

    .line 88
    :goto_3
    cmpg-float p0, p0, v2

    .line 89
    .line 90
    if-nez p0, :cond_8

    .line 91
    .line 92
    :cond_7
    const/4 p0, 0x0

    .line 93
    return p0

    .line 94
    :cond_8
    const/4 p0, 0x1

    .line 95
    return p0
.end method

.method public final j1(Le1/j;Lg1/u;Lg1/j1;Lg1/w1;Lg1/q2;Li1/l;ZZ)V
    .locals 11

    .line 1
    move-object/from16 v2, p5

    .line 2
    .line 3
    move/from16 v3, p7

    .line 4
    .line 5
    move/from16 v4, p8

    .line 6
    .line 7
    iget-boolean v5, p0, Lg1/d1;->v:Z

    .line 8
    .line 9
    const/4 v6, 0x1

    .line 10
    const/4 v7, 0x0

    .line 11
    if-eq v5, v3, :cond_0

    .line 12
    .line 13
    iget-object v5, p0, Lg1/p2;->I:Lg1/l2;

    .line 14
    .line 15
    iput-boolean v3, v5, Lg1/l2;->e:Z

    .line 16
    .line 17
    iget-object v5, p0, Lg1/p2;->F:Lg1/f2;

    .line 18
    .line 19
    iput-boolean v3, v5, Lg1/f2;->r:Z

    .line 20
    .line 21
    move v8, v6

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v8, v7

    .line 24
    :goto_0
    if-nez p3, :cond_1

    .line 25
    .line 26
    iget-object v5, p0, Lg1/p2;->G:Lg1/d0;

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    move-object v5, p3

    .line 30
    :goto_1
    iget-object v9, p0, Lg1/p2;->H:Lg1/u2;

    .line 31
    .line 32
    iget-object v10, v9, Lg1/u2;->a:Lg1/q2;

    .line 33
    .line 34
    invoke-static {v10, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v10

    .line 38
    if-nez v10, :cond_2

    .line 39
    .line 40
    iput-object v2, v9, Lg1/u2;->a:Lg1/q2;

    .line 41
    .line 42
    move v7, v6

    .line 43
    :cond_2
    iput-object p1, v9, Lg1/u2;->b:Le1/j;

    .line 44
    .line 45
    iget-object v2, v9, Lg1/u2;->d:Lg1/w1;

    .line 46
    .line 47
    if-eq v2, p4, :cond_3

    .line 48
    .line 49
    iput-object p4, v9, Lg1/u2;->d:Lg1/w1;

    .line 50
    .line 51
    move v7, v6

    .line 52
    :cond_3
    iget-boolean v2, v9, Lg1/u2;->e:Z

    .line 53
    .line 54
    if-eq v2, v4, :cond_4

    .line 55
    .line 56
    iput-boolean v4, v9, Lg1/u2;->e:Z

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_4
    move v6, v7

    .line 60
    :goto_2
    iput-object v5, v9, Lg1/u2;->c:Lg1/j1;

    .line 61
    .line 62
    iget-object v2, p0, Lg1/p2;->E:Lo3/d;

    .line 63
    .line 64
    iput-object v2, v9, Lg1/u2;->f:Lo3/d;

    .line 65
    .line 66
    iget-object v2, p0, Lg1/p2;->J:Lg1/y;

    .line 67
    .line 68
    iput-object p4, v2, Lg1/y;->r:Lg1/w1;

    .line 69
    .line 70
    iput-boolean v4, v2, Lg1/y;->t:Z

    .line 71
    .line 72
    iput-object p2, v2, Lg1/y;->u:Lg1/u;

    .line 73
    .line 74
    iput-object p1, p0, Lg1/p2;->C:Le1/j;

    .line 75
    .line 76
    iput-object p3, p0, Lg1/p2;->D:Lg1/j1;

    .line 77
    .line 78
    sget-object v1, Landroidx/compose/foundation/gestures/b;->a:Lfw0/i0;

    .line 79
    .line 80
    iget-object p1, v9, Lg1/u2;->d:Lg1/w1;

    .line 81
    .line 82
    sget-object p2, Lg1/w1;->d:Lg1/w1;

    .line 83
    .line 84
    if-ne p1, p2, :cond_5

    .line 85
    .line 86
    :goto_3
    move-object v0, p0

    .line 87
    move-object v4, p2

    .line 88
    move v2, v3

    .line 89
    move v5, v6

    .line 90
    move-object/from16 v3, p6

    .line 91
    .line 92
    goto :goto_4

    .line 93
    :cond_5
    sget-object p2, Lg1/w1;->e:Lg1/w1;

    .line 94
    .line 95
    goto :goto_3

    .line 96
    :goto_4
    invoke-virtual/range {v0 .. v5}, Lg1/d1;->i1(Lay0/k;ZLi1/l;Lg1/w1;Z)V

    .line 97
    .line 98
    .line 99
    if-eqz v8, :cond_6

    .line 100
    .line 101
    const/4 p1, 0x0

    .line 102
    iput-object p1, p0, Lg1/p2;->K:La71/a0;

    .line 103
    .line 104
    iput-object p1, p0, Lg1/p2;->L:Lg1/m2;

    .line 105
    .line 106
    invoke-static {p0}, Lv3/f;->o(Lv3/x1;)V

    .line 107
    .line 108
    .line 109
    :cond_6
    return-void
.end method

.method public final v0(Lp3/k;Lp3/l;J)V
    .locals 17

    .line 1
    move-object/from16 v2, p0

    .line 2
    .line 3
    move-object/from16 v8, p1

    .line 4
    .line 5
    move-object/from16 v9, p2

    .line 6
    .line 7
    iget-object v0, v8, Lp3/k;->a:Ljava/lang/Object;

    .line 8
    .line 9
    move-object v1, v0

    .line 10
    check-cast v1, Ljava/util/Collection;

    .line 11
    .line 12
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/4 v10, 0x0

    .line 17
    move v3, v10

    .line 18
    :goto_0
    if-ge v3, v1, :cond_1

    .line 19
    .line 20
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    check-cast v4, Lp3/t;

    .line 25
    .line 26
    iget-object v5, v2, Lg1/d1;->u:Lay0/k;

    .line 27
    .line 28
    invoke-interface {v5, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    check-cast v4, Ljava/lang/Boolean;

    .line 33
    .line 34
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-eqz v4, :cond_0

    .line 39
    .line 40
    invoke-super/range {p0 .. p4}, Lg1/d1;->v0(Lp3/k;Lp3/l;J)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    :goto_1
    iget-boolean v0, v2, Lg1/d1;->v:Z

    .line 48
    .line 49
    if-eqz v0, :cond_a

    .line 50
    .line 51
    sget-object v0, Lp3/l;->d:Lp3/l;

    .line 52
    .line 53
    const/4 v11, 0x6

    .line 54
    if-ne v9, v0, :cond_3

    .line 55
    .line 56
    iget v0, v8, Lp3/k;->e:I

    .line 57
    .line 58
    if-ne v0, v11, :cond_3

    .line 59
    .line 60
    iget-object v0, v2, Lg1/p2;->M:Lb0/d1;

    .line 61
    .line 62
    if-nez v0, :cond_2

    .line 63
    .line 64
    new-instance v12, Lb0/d1;

    .line 65
    .line 66
    new-instance v13, La0/j;

    .line 67
    .line 68
    invoke-static {v2}, Lv3/f;->z(Lv3/m;)Landroid/view/View;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-static {v0}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    const/16 v1, 0x14

    .line 81
    .line 82
    invoke-direct {v13, v0, v1}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 83
    .line 84
    .line 85
    new-instance v0, La50/d;

    .line 86
    .line 87
    const/4 v6, 0x4

    .line 88
    const/4 v7, 0x6

    .line 89
    const/4 v1, 0x2

    .line 90
    const-class v3, Lg1/p2;

    .line 91
    .line 92
    const-string v4, "onWheelScrollStopped"

    .line 93
    .line 94
    const-string v5, "onWheelScrollStopped-TH1AsA0(J)V"

    .line 95
    .line 96
    invoke-direct/range {v0 .. v7}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 97
    .line 98
    .line 99
    invoke-static {v2}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    iget-object v1, v1, Lv3/h0;->A:Lt4/c;

    .line 104
    .line 105
    iget-object v3, v2, Lg1/p2;->H:Lg1/u2;

    .line 106
    .line 107
    invoke-direct {v12, v3, v13, v0, v1}, Lb0/d1;-><init>(Lg1/u2;La0/j;La50/d;Lt4/c;)V

    .line 108
    .line 109
    .line 110
    iput-object v12, v2, Lg1/p2;->M:Lb0/d1;

    .line 111
    .line 112
    :cond_2
    iget-object v0, v2, Lg1/p2;->M:Lb0/d1;

    .line 113
    .line 114
    if-eqz v0, :cond_3

    .line 115
    .line 116
    invoke-virtual {v2}, Lx2/r;->L0()Lvy0/b0;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    iget-object v3, v0, Lb0/d1;->j:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v3, Lvy0/x1;

    .line 123
    .line 124
    if-nez v3, :cond_3

    .line 125
    .line 126
    new-instance v3, Le60/m;

    .line 127
    .line 128
    const/16 v4, 0x11

    .line 129
    .line 130
    const/4 v5, 0x0

    .line 131
    invoke-direct {v3, v0, v5, v4}, Le60/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 132
    .line 133
    .line 134
    const/4 v4, 0x3

    .line 135
    invoke-static {v1, v5, v5, v3, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    iput-object v1, v0, Lb0/d1;->j:Ljava/lang/Object;

    .line 140
    .line 141
    :cond_3
    iget-object v0, v2, Lg1/p2;->M:Lb0/d1;

    .line 142
    .line 143
    if-eqz v0, :cond_a

    .line 144
    .line 145
    sget-object v1, Lp3/l;->e:Lp3/l;

    .line 146
    .line 147
    if-ne v9, v1, :cond_a

    .line 148
    .line 149
    iget v1, v8, Lp3/k;->e:I

    .line 150
    .line 151
    iget-object v2, v8, Lp3/k;->a:Ljava/lang/Object;

    .line 152
    .line 153
    if-ne v1, v11, :cond_a

    .line 154
    .line 155
    move-object v1, v2

    .line 156
    check-cast v1, Ljava/util/Collection;

    .line 157
    .line 158
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 159
    .line 160
    .line 161
    move-result v3

    .line 162
    move v4, v10

    .line 163
    :goto_2
    if-ge v4, v3, :cond_5

    .line 164
    .line 165
    invoke-interface {v2, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v5

    .line 169
    check-cast v5, Lp3/t;

    .line 170
    .line 171
    invoke-virtual {v5}, Lp3/t;->b()Z

    .line 172
    .line 173
    .line 174
    move-result v5

    .line 175
    if-eqz v5, :cond_4

    .line 176
    .line 177
    goto/16 :goto_7

    .line 178
    .line 179
    :cond_4
    add-int/lit8 v4, v4, 0x1

    .line 180
    .line 181
    goto :goto_2

    .line 182
    :cond_5
    iget-object v3, v0, Lb0/d1;->f:Ljava/lang/Object;

    .line 183
    .line 184
    check-cast v3, La0/j;

    .line 185
    .line 186
    iget-object v3, v3, La0/j;->e:Ljava/lang/Object;

    .line 187
    .line 188
    check-cast v3, Landroid/view/ViewConfiguration;

    .line 189
    .line 190
    invoke-virtual {v3}, Landroid/view/ViewConfiguration;->getScaledVerticalScrollFactor()F

    .line 191
    .line 192
    .line 193
    move-result v4

    .line 194
    neg-float v4, v4

    .line 195
    invoke-virtual {v3}, Landroid/view/ViewConfiguration;->getScaledHorizontalScrollFactor()F

    .line 196
    .line 197
    .line 198
    move-result v3

    .line 199
    neg-float v3, v3

    .line 200
    new-instance v5, Ld3/b;

    .line 201
    .line 202
    const-wide/16 v6, 0x0

    .line 203
    .line 204
    invoke-direct {v5, v6, v7}, Ld3/b;-><init>(J)V

    .line 205
    .line 206
    .line 207
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 208
    .line 209
    .line 210
    move-result v6

    .line 211
    move v7, v10

    .line 212
    :goto_3
    iget-wide v8, v5, Ld3/b;->a:J

    .line 213
    .line 214
    if-ge v7, v6, :cond_6

    .line 215
    .line 216
    invoke-interface {v2, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v5

    .line 220
    check-cast v5, Lp3/t;

    .line 221
    .line 222
    iget-wide v11, v5, Lp3/t;->j:J

    .line 223
    .line 224
    invoke-static {v8, v9, v11, v12}, Ld3/b;->h(JJ)J

    .line 225
    .line 226
    .line 227
    move-result-wide v8

    .line 228
    new-instance v5, Ld3/b;

    .line 229
    .line 230
    invoke-direct {v5, v8, v9}, Ld3/b;-><init>(J)V

    .line 231
    .line 232
    .line 233
    add-int/lit8 v7, v7, 0x1

    .line 234
    .line 235
    goto :goto_3

    .line 236
    :cond_6
    const/16 v5, 0x20

    .line 237
    .line 238
    shr-long v6, v8, v5

    .line 239
    .line 240
    long-to-int v6, v6

    .line 241
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 242
    .line 243
    .line 244
    move-result v6

    .line 245
    mul-float/2addr v6, v3

    .line 246
    const-wide v11, 0xffffffffL

    .line 247
    .line 248
    .line 249
    .line 250
    .line 251
    and-long v7, v8, v11

    .line 252
    .line 253
    long-to-int v3, v7

    .line 254
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 255
    .line 256
    .line 257
    move-result v3

    .line 258
    mul-float/2addr v3, v4

    .line 259
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 260
    .line 261
    .line 262
    move-result v4

    .line 263
    int-to-long v6, v4

    .line 264
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 265
    .line 266
    .line 267
    move-result v3

    .line 268
    int-to-long v3, v3

    .line 269
    shl-long v5, v6, v5

    .line 270
    .line 271
    and-long/2addr v3, v11

    .line 272
    or-long v12, v5, v3

    .line 273
    .line 274
    iget-object v3, v0, Lb0/d1;->e:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast v3, Lg1/u2;

    .line 277
    .line 278
    invoke-virtual {v3, v12, v13}, Lg1/u2;->e(J)J

    .line 279
    .line 280
    .line 281
    move-result-wide v4

    .line 282
    invoke-virtual {v3, v4, v5}, Lg1/u2;->g(J)F

    .line 283
    .line 284
    .line 285
    move-result v4

    .line 286
    const/4 v5, 0x0

    .line 287
    cmpg-float v6, v4, v5

    .line 288
    .line 289
    if-nez v6, :cond_7

    .line 290
    .line 291
    move v3, v10

    .line 292
    goto :goto_4

    .line 293
    :cond_7
    cmpl-float v4, v4, v5

    .line 294
    .line 295
    if-lez v4, :cond_8

    .line 296
    .line 297
    iget-object v3, v3, Lg1/u2;->a:Lg1/q2;

    .line 298
    .line 299
    invoke-interface {v3}, Lg1/q2;->d()Z

    .line 300
    .line 301
    .line 302
    move-result v3

    .line 303
    goto :goto_4

    .line 304
    :cond_8
    iget-object v3, v3, Lg1/u2;->a:Lg1/q2;

    .line 305
    .line 306
    invoke-interface {v3}, Lg1/q2;->b()Z

    .line 307
    .line 308
    .line 309
    move-result v3

    .line 310
    :goto_4
    if-eqz v3, :cond_9

    .line 311
    .line 312
    iget-object v0, v0, Lb0/d1;->i:Ljava/lang/Object;

    .line 313
    .line 314
    check-cast v0, Lxy0/j;

    .line 315
    .line 316
    new-instance v11, Lg1/r1;

    .line 317
    .line 318
    invoke-static {v2}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    move-result-object v3

    .line 322
    check-cast v3, Lp3/t;

    .line 323
    .line 324
    iget-wide v14, v3, Lp3/t;->b:J

    .line 325
    .line 326
    const/16 v16, 0x0

    .line 327
    .line 328
    invoke-direct/range {v11 .. v16}, Lg1/r1;-><init>(JJZ)V

    .line 329
    .line 330
    .line 331
    invoke-interface {v0, v11}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object v0

    .line 335
    instance-of v0, v0, Lxy0/p;

    .line 336
    .line 337
    xor-int/lit8 v0, v0, 0x1

    .line 338
    .line 339
    goto :goto_5

    .line 340
    :cond_9
    iget-boolean v0, v0, Lb0/d1;->d:Z

    .line 341
    .line 342
    :goto_5
    if-eqz v0, :cond_a

    .line 343
    .line 344
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 345
    .line 346
    .line 347
    move-result v0

    .line 348
    :goto_6
    if-ge v10, v0, :cond_a

    .line 349
    .line 350
    invoke-interface {v2, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v1

    .line 354
    check-cast v1, Lp3/t;

    .line 355
    .line 356
    invoke-virtual {v1}, Lp3/t;->a()V

    .line 357
    .line 358
    .line 359
    add-int/lit8 v10, v10, 0x1

    .line 360
    .line 361
    goto :goto_6

    .line 362
    :cond_a
    :goto_7
    return-void
.end method
