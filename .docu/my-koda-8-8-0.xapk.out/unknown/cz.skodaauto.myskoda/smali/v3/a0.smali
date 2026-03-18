.class public final Lv3/a0;
.super Lv3/f1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final U:Le3/g;


# instance fields
.field public S:Lv3/y;

.field public T:Lv3/z;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget v1, Le3/s;->j:I

    .line 6
    .line 7
    sget-wide v1, Le3/s;->g:J

    .line 8
    .line 9
    invoke-virtual {v0, v1, v2}, Le3/g;->e(J)V

    .line 10
    .line 11
    .line 12
    const/high16 v1, 0x3f800000    # 1.0f

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Le3/g;->l(F)V

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    invoke-virtual {v0, v1}, Le3/g;->m(I)V

    .line 19
    .line 20
    .line 21
    sput-object v0, Lv3/a0;->U:Le3/g;

    .line 22
    .line 23
    return-void
.end method

.method public constructor <init>(Lv3/h0;Lv3/y;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lv3/f1;-><init>(Lv3/h0;)V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lv3/a0;->S:Lv3/y;

    .line 5
    .line 6
    iget-object p1, p1, Lv3/h0;->j:Lv3/h0;

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    new-instance p1, Lv3/z;

    .line 11
    .line 12
    invoke-direct {p1, p0}, Lv3/z;-><init>(Lv3/a0;)V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 p1, 0x0

    .line 17
    :goto_0
    iput-object p1, p0, Lv3/a0;->T:Lv3/z;

    .line 18
    .line 19
    check-cast p2, Lx2/r;

    .line 20
    .line 21
    iget-object p0, p2, Lx2/r;->d:Lx2/r;

    .line 22
    .line 23
    iget p0, p0, Lx2/r;->f:I

    .line 24
    .line 25
    and-int/lit16 p0, p0, 0x200

    .line 26
    .line 27
    if-nez p0, :cond_1

    .line 28
    .line 29
    return-void

    .line 30
    :cond_1
    new-instance p0, Ljava/lang/ClassCastException;

    .line 31
    .line 32
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 33
    .line 34
    .line 35
    throw p0
.end method


# virtual methods
.method public final A(I)I
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/a0;->S:Lv3/y;

    .line 2
    .line 3
    iget-object v1, p0, Lv3/f1;->s:Lv3/f1;

    .line 4
    .line 5
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    invoke-interface {v0, p0, v1, p1}, Lv3/y;->D(Lv3/p0;Lt3/p0;I)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final C0(Lt3/a;)I
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/a0;->T:Lv3/z;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object p0, v0, Lv3/q0;->w:Landroidx/collection/h0;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Landroidx/collection/h0;->d(Ljava/lang/Object;)I

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    if-ltz p1, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, Landroidx/collection/h0;->c:[I

    .line 14
    .line 15
    aget p0, p0, p1

    .line 16
    .line 17
    return p0

    .line 18
    :cond_0
    const/high16 p0, -0x80000000

    .line 19
    .line 20
    return p0

    .line 21
    :cond_1
    invoke-static {p0, p1}, Lv3/f;->c(Lv3/p0;Lt3/a;)I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0
.end method

.method public final G(I)I
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/a0;->S:Lv3/y;

    .line 2
    .line 3
    iget-object v1, p0, Lv3/f1;->s:Lv3/f1;

    .line 4
    .line 5
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    invoke-interface {v0, p0, v1, p1}, Lv3/y;->X(Lv3/p0;Lt3/p0;I)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final H1()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lv3/p0;->m:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    invoke-virtual {p0}, Lv3/f1;->r1()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lv3/f1;->N0()Lt3/r0;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-interface {v0}, Lt3/r0;->c()V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lv3/f1;->s:Lv3/f1;

    .line 17
    .line 18
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final I1(Lv3/y;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/a0;->S:Lv3/y;

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    move-object v0, p1

    .line 10
    check-cast v0, Lx2/r;

    .line 11
    .line 12
    iget-object v0, v0, Lx2/r;->d:Lx2/r;

    .line 13
    .line 14
    iget v0, v0, Lx2/r;->f:I

    .line 15
    .line 16
    and-int/lit16 v0, v0, 0x200

    .line 17
    .line 18
    if-nez v0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/ClassCastException;

    .line 22
    .line 23
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    :goto_0
    iput-object p1, p0, Lv3/a0;->S:Lv3/y;

    .line 28
    .line 29
    return-void
.end method

.method public final J(I)I
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/a0;->S:Lv3/y;

    .line 2
    .line 3
    iget-object v1, p0, Lv3/f1;->s:Lv3/f1;

    .line 4
    .line 5
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    invoke-interface {v0, p0, v1, p1}, Lv3/y;->F0(Lv3/p0;Lt3/p0;I)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final L(J)Lt3/e1;
    .locals 2

    .line 1
    invoke-virtual {p0, p1, p2}, Lt3/e1;->y0(J)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lv3/a0;->S:Lv3/y;

    .line 5
    .line 6
    iget-object v1, p0, Lv3/f1;->s:Lv3/f1;

    .line 7
    .line 8
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {v0, p0, v1, p1, p2}, Lv3/y;->c(Lt3/s0;Lt3/p0;J)Lt3/r0;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p0, p1}, Lv3/f1;->y1(Lt3/r0;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0}, Lv3/f1;->q1()V

    .line 19
    .line 20
    .line 21
    return-object p0
.end method

.method public final a1()V
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/a0;->T:Lv3/z;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lv3/z;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Lv3/z;-><init>(Lv3/a0;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lv3/a0;->T:Lv3/z;

    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final c(I)I
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/a0;->S:Lv3/y;

    .line 2
    .line 3
    iget-object v1, p0, Lv3/f1;->s:Lv3/f1;

    .line 4
    .line 5
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    invoke-interface {v0, p0, v1, p1}, Lv3/y;->J(Lv3/p0;Lt3/p0;I)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final d1()Lv3/q0;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/a0;->T:Lv3/z;

    .line 2
    .line 3
    return-object p0
.end method

.method public final f1()Lx2/r;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/a0;->S:Lv3/y;

    .line 2
    .line 3
    check-cast p0, Lx2/r;

    .line 4
    .line 5
    iget-object p0, p0, Lx2/r;->d:Lx2/r;

    .line 6
    .line 7
    return-object p0
.end method

.method public final l0(JFLay0/k;)V
    .locals 6

    .line 1
    const/4 v5, 0x0

    .line 2
    move-object v0, p0

    .line 3
    move-wide v1, p1

    .line 4
    move v3, p3

    .line 5
    move-object v4, p4

    .line 6
    invoke-virtual/range {v0 .. v5}, Lv3/f1;->v1(JFLay0/k;Lh3/c;)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0}, Lv3/a0;->H1()V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final m0(JFLh3/c;)V
    .locals 6

    .line 1
    const/4 v4, 0x0

    .line 2
    move-object v0, p0

    .line 3
    move-wide v1, p1

    .line 4
    move v3, p3

    .line 5
    move-object v5, p4

    .line 6
    invoke-virtual/range {v0 .. v5}, Lv3/f1;->v1(JFLay0/k;Lh3/c;)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0}, Lv3/a0;->H1()V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final u1(Le3/r;Lh3/c;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lv3/f1;->s:Lv3/f1;

    .line 2
    .line 3
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0, p1, p2}, Lv3/f1;->Y0(Le3/r;Lh3/c;)V

    .line 7
    .line 8
    .line 9
    iget-object p2, p0, Lv3/f1;->r:Lv3/h0;

    .line 10
    .line 11
    invoke-static {p2}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    check-cast p2, Lw3/t;

    .line 16
    .line 17
    invoke-virtual {p2}, Lw3/t;->getShowLayoutBounds()Z

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    if-eqz p2, :cond_1

    .line 22
    .line 23
    iget-object p2, p0, Lv3/f1;->s:Lv3/f1;

    .line 24
    .line 25
    if-eqz p2, :cond_1

    .line 26
    .line 27
    iget-wide v0, p0, Lt3/e1;->f:J

    .line 28
    .line 29
    iget-wide v2, p2, Lt3/e1;->f:J

    .line 30
    .line 31
    invoke-static {v0, v1, v2, v3}, Lt4/l;->a(JJ)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    iget-wide v0, p2, Lv3/f1;->C:J

    .line 38
    .line 39
    const-wide/16 v2, 0x0

    .line 40
    .line 41
    invoke-static {v0, v1, v2, v3}, Lt4/j;->b(JJ)Z

    .line 42
    .line 43
    .line 44
    move-result p2

    .line 45
    if-nez p2, :cond_1

    .line 46
    .line 47
    :cond_0
    iget-wide v0, p0, Lt3/e1;->f:J

    .line 48
    .line 49
    const/16 p0, 0x20

    .line 50
    .line 51
    shr-long v2, v0, p0

    .line 52
    .line 53
    long-to-int p0, v2

    .line 54
    int-to-float p0, p0

    .line 55
    const/high16 p2, 0x3f000000    # 0.5f

    .line 56
    .line 57
    sub-float v5, p0, p2

    .line 58
    .line 59
    const-wide v2, 0xffffffffL

    .line 60
    .line 61
    .line 62
    .line 63
    .line 64
    and-long/2addr v0, v2

    .line 65
    long-to-int p0, v0

    .line 66
    int-to-float p0, p0

    .line 67
    sub-float v6, p0, p2

    .line 68
    .line 69
    const/high16 v3, 0x3f000000    # 0.5f

    .line 70
    .line 71
    const/high16 v4, 0x3f000000    # 0.5f

    .line 72
    .line 73
    sget-object v7, Lv3/a0;->U:Le3/g;

    .line 74
    .line 75
    move-object v2, p1

    .line 76
    invoke-interface/range {v2 .. v7}, Le3/r;->r(FFFFLe3/g;)V

    .line 77
    .line 78
    .line 79
    :cond_1
    return-void
.end method
