.class public abstract Lv3/f1;
.super Lv3/p0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/p0;
.implements Lt3/y;
.implements Lv3/p1;


# static fields
.field public static final N:Le3/k0;

.field public static final O:Lv3/w;

.field public static final P:[F

.field public static final Q:Lv3/d;

.field public static final R:Lv3/d;


# instance fields
.field public A:Lt3/r0;

.field public B:Landroidx/collection/h0;

.field public C:J

.field public D:F

.field public E:Ld3/a;

.field public F:Lv3/w;

.field public G:Lh3/c;

.field public H:Le3/r;

.field public I:Lkn/i0;

.field public final J:Lv3/c1;

.field public K:Z

.field public L:Lv3/n1;

.field public M:Lh3/c;

.field public final r:Lv3/h0;

.field public s:Lv3/f1;

.field public t:Lv3/f1;

.field public u:Z

.field public v:Z

.field public w:Lay0/k;

.field public x:Lt4/c;

.field public y:Lt4/m;

.field public z:F


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Le3/k0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/high16 v1, 0x3f800000    # 1.0f

    .line 7
    .line 8
    iput v1, v0, Le3/k0;->e:F

    .line 9
    .line 10
    iput v1, v0, Le3/k0;->f:F

    .line 11
    .line 12
    iput v1, v0, Le3/k0;->g:F

    .line 13
    .line 14
    sget-wide v1, Le3/y;->a:J

    .line 15
    .line 16
    iput-wide v1, v0, Le3/k0;->k:J

    .line 17
    .line 18
    iput-wide v1, v0, Le3/k0;->l:J

    .line 19
    .line 20
    const/high16 v1, 0x41000000    # 8.0f

    .line 21
    .line 22
    iput v1, v0, Le3/k0;->p:F

    .line 23
    .line 24
    sget-wide v1, Le3/q0;->b:J

    .line 25
    .line 26
    iput-wide v1, v0, Le3/k0;->q:J

    .line 27
    .line 28
    sget-object v1, Le3/j0;->a:Le3/i0;

    .line 29
    .line 30
    iput-object v1, v0, Le3/k0;->r:Le3/n0;

    .line 31
    .line 32
    const-wide v1, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 33
    .line 34
    .line 35
    .line 36
    .line 37
    iput-wide v1, v0, Le3/k0;->t:J

    .line 38
    .line 39
    invoke-static {}, Lkp/b9;->a()Lt4/d;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iput-object v1, v0, Le3/k0;->u:Lt4/c;

    .line 44
    .line 45
    sget-object v1, Lt4/m;->d:Lt4/m;

    .line 46
    .line 47
    iput-object v1, v0, Le3/k0;->v:Lt4/m;

    .line 48
    .line 49
    const/4 v1, 0x3

    .line 50
    iput v1, v0, Le3/k0;->x:I

    .line 51
    .line 52
    sput-object v0, Lv3/f1;->N:Le3/k0;

    .line 53
    .line 54
    new-instance v0, Lv3/w;

    .line 55
    .line 56
    invoke-direct {v0}, Lv3/w;-><init>()V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lv3/f1;->O:Lv3/w;

    .line 60
    .line 61
    invoke-static {}, Le3/c0;->a()[F

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Lv3/f1;->P:[F

    .line 66
    .line 67
    new-instance v0, Lv3/d;

    .line 68
    .line 69
    const/4 v1, 0x1

    .line 70
    invoke-direct {v0, v1}, Lv3/d;-><init>(I)V

    .line 71
    .line 72
    .line 73
    sput-object v0, Lv3/f1;->Q:Lv3/d;

    .line 74
    .line 75
    new-instance v0, Lv3/d;

    .line 76
    .line 77
    const/4 v1, 0x2

    .line 78
    invoke-direct {v0, v1}, Lv3/d;-><init>(I)V

    .line 79
    .line 80
    .line 81
    sput-object v0, Lv3/f1;->R:Lv3/d;

    .line 82
    .line 83
    return-void
.end method

.method public constructor <init>(Lv3/h0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Lv3/p0;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv3/f1;->r:Lv3/h0;

    .line 5
    .line 6
    iget-object v0, p1, Lv3/h0;->A:Lt4/c;

    .line 7
    .line 8
    iput-object v0, p0, Lv3/f1;->x:Lt4/c;

    .line 9
    .line 10
    iget-object p1, p1, Lv3/h0;->B:Lt4/m;

    .line 11
    .line 12
    iput-object p1, p0, Lv3/f1;->y:Lt4/m;

    .line 13
    .line 14
    const p1, 0x3f4ccccd    # 0.8f

    .line 15
    .line 16
    .line 17
    iput p1, p0, Lv3/f1;->z:F

    .line 18
    .line 19
    const-wide/16 v0, 0x0

    .line 20
    .line 21
    iput-wide v0, p0, Lv3/f1;->C:J

    .line 22
    .line 23
    new-instance p1, Lv3/c1;

    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    invoke-direct {p1, p0, v0}, Lv3/c1;-><init>(Lv3/f1;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lv3/f1;->J:Lv3/c1;

    .line 30
    .line 31
    return-void
.end method

.method public static z1(Lt3/y;)Lv3/f1;
    .locals 1

    .line 1
    instance-of v0, p0, Lt3/o0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p0

    .line 6
    check-cast v0, Lt3/o0;

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 v0, 0x0

    .line 10
    :goto_0
    if-eqz v0, :cond_2

    .line 11
    .line 12
    iget-object v0, v0, Lt3/o0;->d:Lv3/q0;

    .line 13
    .line 14
    iget-object v0, v0, Lv3/q0;->r:Lv3/f1;

    .line 15
    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_1
    return-object v0

    .line 20
    :cond_2
    :goto_1
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.node.NodeCoordinator"

    .line 21
    .line 22
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    check-cast p0, Lv3/f1;

    .line 26
    .line 27
    return-object p0
.end method


# virtual methods
.method public final A1(J)J
    .locals 5

    .line 1
    iget-object v0, p0, Lv3/f1;->L:Lv3/n1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    check-cast v0, Lw3/o1;

    .line 7
    .line 8
    invoke-virtual {v0, p1, p2, v1}, Lw3/o1;->d(JZ)J

    .line 9
    .line 10
    .line 11
    move-result-wide p1

    .line 12
    :cond_0
    iget-wide v0, p0, Lv3/f1;->C:J

    .line 13
    .line 14
    const/16 p0, 0x20

    .line 15
    .line 16
    shr-long v2, p1, p0

    .line 17
    .line 18
    long-to-int v2, v2

    .line 19
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    shr-long v3, v0, p0

    .line 24
    .line 25
    long-to-int v3, v3

    .line 26
    int-to-float v3, v3

    .line 27
    add-float/2addr v2, v3

    .line 28
    const-wide v3, 0xffffffffL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    and-long/2addr p1, v3

    .line 34
    long-to-int p1, p1

    .line 35
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    and-long/2addr v0, v3

    .line 40
    long-to-int p2, v0

    .line 41
    int-to-float p2, p2

    .line 42
    add-float/2addr p1, p2

    .line 43
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 44
    .line 45
    .line 46
    move-result p2

    .line 47
    int-to-long v0, p2

    .line 48
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    int-to-long p1, p1

    .line 53
    shl-long/2addr v0, p0

    .line 54
    and-long p0, p1, v3

    .line 55
    .line 56
    or-long/2addr p0, v0

    .line 57
    return-wide p0
.end method

.method public final B(J)J
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lv3/f1;->R(J)J

    .line 2
    .line 3
    .line 4
    move-result-wide p1

    .line 5
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 6
    .line 7
    invoke-static {p0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Lw3/t;

    .line 12
    .line 13
    invoke-virtual {p0}, Lw3/t;->z()V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lw3/t;->V:[F

    .line 17
    .line 18
    invoke-static {p1, p2, p0}, Le3/c0;->b(J[F)J

    .line 19
    .line 20
    .line 21
    move-result-wide p0

    .line 22
    return-wide p0
.end method

.method public final B1()Ld3/c;
    .locals 7

    .line 1
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_0
    invoke-static {p0}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget-object v1, p0, Lv3/f1;->E:Ld3/a;

    .line 15
    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    new-instance v1, Ld3/a;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    invoke-direct {v1, v2}, Ld3/a;-><init>(I)V

    .line 22
    .line 23
    .line 24
    iput-object v1, p0, Lv3/f1;->E:Ld3/a;

    .line 25
    .line 26
    :cond_1
    invoke-virtual {p0}, Lv3/f1;->e1()J

    .line 27
    .line 28
    .line 29
    move-result-wide v2

    .line 30
    invoke-virtual {p0, v2, v3}, Lv3/f1;->W0(J)J

    .line 31
    .line 32
    .line 33
    move-result-wide v2

    .line 34
    const/16 v4, 0x20

    .line 35
    .line 36
    shr-long v4, v2, v4

    .line 37
    .line 38
    long-to-int v4, v4

    .line 39
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    neg-float v5, v5

    .line 44
    iput v5, v1, Ld3/a;->b:F

    .line 45
    .line 46
    const-wide v5, 0xffffffffL

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    and-long/2addr v2, v5

    .line 52
    long-to-int v2, v2

    .line 53
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    neg-float v3, v3

    .line 58
    iput v3, v1, Ld3/a;->c:F

    .line 59
    .line 60
    invoke-virtual {p0}, Lt3/e1;->d0()I

    .line 61
    .line 62
    .line 63
    move-result v3

    .line 64
    int-to-float v3, v3

    .line 65
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    add-float/2addr v4, v3

    .line 70
    iput v4, v1, Ld3/a;->d:F

    .line 71
    .line 72
    invoke-virtual {p0}, Lt3/e1;->b0()I

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    int-to-float v3, v3

    .line 77
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 78
    .line 79
    .line 80
    move-result v2

    .line 81
    add-float/2addr v2, v3

    .line 82
    iput v2, v1, Ld3/a;->e:F

    .line 83
    .line 84
    :goto_0
    if-eq p0, v0, :cond_3

    .line 85
    .line 86
    const/4 v2, 0x0

    .line 87
    const/4 v3, 0x1

    .line 88
    invoke-virtual {p0, v1, v2, v3}, Lv3/f1;->w1(Ld3/a;ZZ)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v1}, Ld3/a;->g()Z

    .line 92
    .line 93
    .line 94
    move-result v2

    .line 95
    if-eqz v2, :cond_2

    .line 96
    .line 97
    :goto_1
    sget-object p0, Ld3/c;->e:Ld3/c;

    .line 98
    .line 99
    return-object p0

    .line 100
    :cond_2
    iget-object p0, p0, Lv3/f1;->t:Lv3/f1;

    .line 101
    .line 102
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    goto :goto_0

    .line 106
    :cond_3
    new-instance p0, Ld3/c;

    .line 107
    .line 108
    iget v0, v1, Ld3/a;->b:F

    .line 109
    .line 110
    iget v2, v1, Ld3/a;->c:F

    .line 111
    .line 112
    iget v3, v1, Ld3/a;->d:F

    .line 113
    .line 114
    iget v1, v1, Ld3/a;->e:F

    .line 115
    .line 116
    invoke-direct {p0, v0, v2, v3, v1}, Ld3/c;-><init>(FFFF)V

    .line 117
    .line 118
    .line 119
    return-object p0
.end method

.method public final C1(Lv3/f1;[F)V
    .locals 5

    .line 1
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Lv3/f1;->t:Lv3/f1;

    .line 8
    .line 9
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p1, p2}, Lv3/f1;->C1(Lv3/f1;[F)V

    .line 13
    .line 14
    .line 15
    iget-wide v0, p0, Lv3/f1;->C:J

    .line 16
    .line 17
    const-wide/16 v2, 0x0

    .line 18
    .line 19
    invoke-static {v0, v1, v2, v3}, Lt4/j;->b(JJ)Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-nez p1, :cond_0

    .line 24
    .line 25
    sget-object p1, Lv3/f1;->P:[F

    .line 26
    .line 27
    invoke-static {p1}, Le3/c0;->d([F)V

    .line 28
    .line 29
    .line 30
    iget-wide v0, p0, Lv3/f1;->C:J

    .line 31
    .line 32
    const/16 v2, 0x20

    .line 33
    .line 34
    shr-long v2, v0, v2

    .line 35
    .line 36
    long-to-int v2, v2

    .line 37
    int-to-float v2, v2

    .line 38
    neg-float v2, v2

    .line 39
    const-wide v3, 0xffffffffL

    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    and-long/2addr v0, v3

    .line 45
    long-to-int v0, v0

    .line 46
    int-to-float v0, v0

    .line 47
    neg-float v0, v0

    .line 48
    invoke-static {p1, v2, v0}, Le3/c0;->f([FFF)V

    .line 49
    .line 50
    .line 51
    invoke-static {p2, p1}, Le3/c0;->e([F[F)V

    .line 52
    .line 53
    .line 54
    :cond_0
    iget-object p0, p0, Lv3/f1;->L:Lv3/n1;

    .line 55
    .line 56
    if-eqz p0, :cond_1

    .line 57
    .line 58
    check-cast p0, Lw3/o1;

    .line 59
    .line 60
    invoke-virtual {p0}, Lw3/o1;->a()[F

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    if-eqz p0, :cond_1

    .line 65
    .line 66
    invoke-static {p2, p0}, Le3/c0;->e([F[F)V

    .line 67
    .line 68
    .line 69
    :cond_1
    return-void
.end method

.method public final D1(Lv3/f1;[F)V
    .locals 6

    .line 1
    :goto_0
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_2

    .line 6
    .line 7
    iget-object v0, p0, Lv3/f1;->L:Lv3/n1;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    check-cast v0, Lw3/o1;

    .line 12
    .line 13
    invoke-virtual {v0}, Lw3/o1;->b()[F

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-static {p2, v0}, Le3/c0;->e([F[F)V

    .line 18
    .line 19
    .line 20
    :cond_0
    iget-wide v0, p0, Lv3/f1;->C:J

    .line 21
    .line 22
    const-wide/16 v2, 0x0

    .line 23
    .line 24
    invoke-static {v0, v1, v2, v3}, Lt4/j;->b(JJ)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-nez v2, :cond_1

    .line 29
    .line 30
    sget-object v2, Lv3/f1;->P:[F

    .line 31
    .line 32
    invoke-static {v2}, Le3/c0;->d([F)V

    .line 33
    .line 34
    .line 35
    const/16 v3, 0x20

    .line 36
    .line 37
    shr-long v3, v0, v3

    .line 38
    .line 39
    long-to-int v3, v3

    .line 40
    int-to-float v3, v3

    .line 41
    const-wide v4, 0xffffffffL

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    and-long/2addr v0, v4

    .line 47
    long-to-int v0, v0

    .line 48
    int-to-float v0, v0

    .line 49
    invoke-static {v2, v3, v0}, Le3/c0;->f([FFF)V

    .line 50
    .line 51
    .line 52
    invoke-static {p2, v2}, Le3/c0;->e([F[F)V

    .line 53
    .line 54
    .line 55
    :cond_1
    iget-object p0, p0, Lv3/f1;->t:Lv3/f1;

    .line 56
    .line 57
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    return-void
.end method

.method public final E1(Lay0/k;Z)V
    .locals 8

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    iget-object v0, p0, Lv3/f1;->M:Lh3/c;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const-string v0, "layerBlock can\'t be provided when explicitLayer is provided"

    .line 9
    .line 10
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    :cond_1
    :goto_0
    const/4 v0, 0x0

    .line 14
    const/4 v1, 0x1

    .line 15
    iget-object v2, p0, Lv3/f1;->r:Lv3/h0;

    .line 16
    .line 17
    if-nez p2, :cond_3

    .line 18
    .line 19
    iget-object p2, p0, Lv3/f1;->w:Lay0/k;

    .line 20
    .line 21
    if-ne p2, p1, :cond_3

    .line 22
    .line 23
    iget-object p2, p0, Lv3/f1;->x:Lt4/c;

    .line 24
    .line 25
    iget-object v3, v2, Lv3/h0;->A:Lt4/c;

    .line 26
    .line 27
    invoke-static {p2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-eqz p2, :cond_3

    .line 32
    .line 33
    iget-object p2, p0, Lv3/f1;->y:Lt4/m;

    .line 34
    .line 35
    iget-object v3, v2, Lv3/h0;->B:Lt4/m;

    .line 36
    .line 37
    if-eq p2, v3, :cond_2

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_2
    move p2, v0

    .line 41
    goto :goto_2

    .line 42
    :cond_3
    :goto_1
    move p2, v1

    .line 43
    :goto_2
    iget-object v3, v2, Lv3/h0;->A:Lt4/c;

    .line 44
    .line 45
    iput-object v3, p0, Lv3/f1;->x:Lt4/c;

    .line 46
    .line 47
    iget-object v3, v2, Lv3/h0;->B:Lt4/m;

    .line 48
    .line 49
    iput-object v3, p0, Lv3/f1;->y:Lt4/m;

    .line 50
    .line 51
    invoke-virtual {v2}, Lv3/h0;->I()Z

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    iget-object v4, p0, Lv3/f1;->J:Lv3/c1;

    .line 56
    .line 57
    const/4 v5, 0x0

    .line 58
    if-eqz v3, :cond_7

    .line 59
    .line 60
    if-eqz p1, :cond_7

    .line 61
    .line 62
    iput-object p1, p0, Lv3/f1;->w:Lay0/k;

    .line 63
    .line 64
    iget-object p1, p0, Lv3/f1;->L:Lv3/n1;

    .line 65
    .line 66
    if-nez p1, :cond_5

    .line 67
    .line 68
    invoke-static {v2}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    iget-object p2, p0, Lv3/f1;->I:Lkn/i0;

    .line 73
    .line 74
    if-nez p2, :cond_4

    .line 75
    .line 76
    new-instance p2, Lv3/c1;

    .line 77
    .line 78
    const/4 v0, 0x0

    .line 79
    invoke-direct {p2, p0, v0}, Lv3/c1;-><init>(Lv3/f1;I)V

    .line 80
    .line 81
    .line 82
    new-instance v0, Lkn/i0;

    .line 83
    .line 84
    const/4 v3, 0x3

    .line 85
    invoke-direct {v0, v3, p0, p2}, Lkn/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    iput-object v0, p0, Lv3/f1;->I:Lkn/i0;

    .line 89
    .line 90
    move-object p2, v0

    .line 91
    :cond_4
    check-cast p1, Lw3/t;

    .line 92
    .line 93
    invoke-virtual {p1, p2, v4, v5}, Lw3/t;->h(Lay0/n;Lv3/c1;Lh3/c;)Lv3/n1;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    iget-wide v5, p0, Lt3/e1;->f:J

    .line 98
    .line 99
    move-object p2, p1

    .line 100
    check-cast p2, Lw3/o1;

    .line 101
    .line 102
    invoke-virtual {p2, v5, v6}, Lw3/o1;->f(J)V

    .line 103
    .line 104
    .line 105
    iget-wide v5, p0, Lv3/f1;->C:J

    .line 106
    .line 107
    invoke-virtual {p2, v5, v6}, Lw3/o1;->e(J)V

    .line 108
    .line 109
    .line 110
    iput-object p1, p0, Lv3/f1;->L:Lv3/n1;

    .line 111
    .line 112
    invoke-virtual {p0, v1}, Lv3/f1;->F1(Z)Z

    .line 113
    .line 114
    .line 115
    iput-boolean v1, v2, Lv3/h0;->L:Z

    .line 116
    .line 117
    invoke-virtual {v4}, Lv3/c1;->invoke()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    return-void

    .line 121
    :cond_5
    if-eqz p2, :cond_6

    .line 122
    .line 123
    invoke-virtual {p0, v1}, Lv3/f1;->F1(Z)Z

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    if-eqz p0, :cond_6

    .line 128
    .line 129
    invoke-virtual {v2}, Lv3/h0;->O()V

    .line 130
    .line 131
    .line 132
    invoke-static {v2}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    check-cast p0, Lw3/t;

    .line 137
    .line 138
    invoke-virtual {p0}, Lw3/t;->getRectManager()Le4/a;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-virtual {p0, v2}, Le4/a;->f(Lv3/h0;)V

    .line 143
    .line 144
    .line 145
    :cond_6
    return-void

    .line 146
    :cond_7
    iput-object v5, p0, Lv3/f1;->w:Lay0/k;

    .line 147
    .line 148
    iget-object p1, p0, Lv3/f1;->L:Lv3/n1;

    .line 149
    .line 150
    if-eqz p1, :cond_d

    .line 151
    .line 152
    check-cast p1, Lw3/o1;

    .line 153
    .line 154
    iget-object p2, p1, Lw3/o1;->f:Lw3/t;

    .line 155
    .line 156
    invoke-virtual {p1}, Lw3/o1;->b()[F

    .line 157
    .line 158
    .line 159
    move-result-object v3

    .line 160
    invoke-static {v3}, Le3/j0;->p([F)Z

    .line 161
    .line 162
    .line 163
    move-result v3

    .line 164
    if-nez v3, :cond_8

    .line 165
    .line 166
    invoke-virtual {v2}, Lv3/h0;->O()V

    .line 167
    .line 168
    .line 169
    :cond_8
    iput-object v5, p1, Lw3/o1;->g:Lay0/n;

    .line 170
    .line 171
    iput-object v5, p1, Lw3/o1;->h:Lay0/a;

    .line 172
    .line 173
    iput-boolean v1, p1, Lw3/o1;->j:Z

    .line 174
    .line 175
    iget-boolean v3, p1, Lw3/o1;->m:Z

    .line 176
    .line 177
    if-eqz v3, :cond_9

    .line 178
    .line 179
    iput-boolean v0, p1, Lw3/o1;->m:Z

    .line 180
    .line 181
    invoke-virtual {p2, p1, v0}, Lw3/t;->t(Lv3/n1;Z)V

    .line 182
    .line 183
    .line 184
    :cond_9
    iget-object v3, p1, Lw3/o1;->e:Le3/w;

    .line 185
    .line 186
    if-eqz v3, :cond_c

    .line 187
    .line 188
    iget-object v6, p1, Lw3/o1;->d:Lh3/c;

    .line 189
    .line 190
    invoke-interface {v3, v6}, Le3/w;->b(Lh3/c;)V

    .line 191
    .line 192
    .line 193
    iget-object v3, p2, Lw3/t;->G1:Lb81/b;

    .line 194
    .line 195
    :cond_a
    iget-object v6, v3, Lb81/b;->f:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast v6, Ljava/lang/ref/ReferenceQueue;

    .line 198
    .line 199
    iget-object v7, v3, Lb81/b;->e:Ljava/lang/Object;

    .line 200
    .line 201
    check-cast v7, Ln2/b;

    .line 202
    .line 203
    invoke-virtual {v6}, Ljava/lang/ref/ReferenceQueue;->poll()Ljava/lang/ref/Reference;

    .line 204
    .line 205
    .line 206
    move-result-object v6

    .line 207
    if-eqz v6, :cond_b

    .line 208
    .line 209
    invoke-virtual {v7, v6}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    :cond_b
    if-nez v6, :cond_a

    .line 213
    .line 214
    new-instance v6, Ljava/lang/ref/WeakReference;

    .line 215
    .line 216
    iget-object v3, v3, Lb81/b;->f:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast v3, Ljava/lang/ref/ReferenceQueue;

    .line 219
    .line 220
    invoke-direct {v6, p1, v3}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;Ljava/lang/ref/ReferenceQueue;)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v7, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    iget-object p2, p2, Lw3/t;->A:Ljava/util/ArrayList;

    .line 227
    .line 228
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 229
    .line 230
    .line 231
    :cond_c
    iput-boolean v1, v2, Lv3/h0;->L:Z

    .line 232
    .line 233
    invoke-virtual {v4}, Lv3/c1;->invoke()Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 237
    .line 238
    .line 239
    move-result-object p1

    .line 240
    iget-boolean p1, p1, Lx2/r;->q:Z

    .line 241
    .line 242
    if-eqz p1, :cond_d

    .line 243
    .line 244
    invoke-virtual {v2}, Lv3/h0;->J()Z

    .line 245
    .line 246
    .line 247
    move-result p1

    .line 248
    if-eqz p1, :cond_d

    .line 249
    .line 250
    iget-object p1, v2, Lv3/h0;->p:Lv3/o1;

    .line 251
    .line 252
    if-eqz p1, :cond_d

    .line 253
    .line 254
    check-cast p1, Lw3/t;

    .line 255
    .line 256
    invoke-virtual {p1, v2}, Lw3/t;->v(Lv3/h0;)V

    .line 257
    .line 258
    .line 259
    :cond_d
    iput-object v5, p0, Lv3/f1;->L:Lv3/n1;

    .line 260
    .line 261
    iput-boolean v0, p0, Lv3/f1;->K:Z

    .line 262
    .line 263
    return-void
.end method

.method public final F([F)V
    .locals 6

    .line 1
    iget-object v0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    invoke-static {v0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {p0}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-static {v1}, Lv3/f1;->z1(Lt3/y;)Lv3/f1;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {p0, v1, p1}, Lv3/f1;->D1(Lv3/f1;[F)V

    .line 16
    .line 17
    .line 18
    instance-of p0, v0, Lp3/g;

    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    check-cast v0, Lp3/g;

    .line 23
    .line 24
    check-cast v0, Lw3/t;

    .line 25
    .line 26
    invoke-virtual {v0, p1}, Lw3/t;->p([F)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    const-wide/16 v2, 0x0

    .line 31
    .line 32
    invoke-virtual {v1, v2, v3}, Lv3/f1;->K(J)J

    .line 33
    .line 34
    .line 35
    move-result-wide v0

    .line 36
    const-wide v2, 0x7fffffff7fffffffL

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    and-long/2addr v2, v0

    .line 42
    const-wide v4, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    cmp-long p0, v2, v4

    .line 48
    .line 49
    if-eqz p0, :cond_1

    .line 50
    .line 51
    const/16 p0, 0x20

    .line 52
    .line 53
    shr-long v2, v0, p0

    .line 54
    .line 55
    long-to-int p0, v2

    .line 56
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    const-wide v2, 0xffffffffL

    .line 61
    .line 62
    .line 63
    .line 64
    .line 65
    and-long/2addr v0, v2

    .line 66
    long-to-int v0, v0

    .line 67
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    invoke-static {p1, p0, v0}, Le3/c0;->f([FFF)V

    .line 72
    .line 73
    .line 74
    :cond_1
    return-void
.end method

.method public final F1(Z)Z
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lv3/f1;->M:Lh3/c;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    move/from16 v18, v2

    .line 9
    .line 10
    goto/16 :goto_14

    .line 11
    .line 12
    :cond_0
    iget-object v1, v0, Lv3/f1;->L:Lv3/n1;

    .line 13
    .line 14
    if-eqz v1, :cond_37

    .line 15
    .line 16
    iget-object v3, v0, Lv3/f1;->w:Lay0/k;

    .line 17
    .line 18
    if-eqz v3, :cond_36

    .line 19
    .line 20
    sget-object v4, Lv3/f1;->N:Le3/k0;

    .line 21
    .line 22
    const/high16 v5, 0x3f800000    # 1.0f

    .line 23
    .line 24
    invoke-virtual {v4, v5}, Le3/k0;->l(F)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v4, v5}, Le3/k0;->p(F)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v4, v5}, Le3/k0;->b(F)V

    .line 31
    .line 32
    .line 33
    const/4 v5, 0x0

    .line 34
    invoke-virtual {v4, v5}, Le3/k0;->B(F)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v4, v5}, Le3/k0;->D(F)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v4, v5}, Le3/k0;->t(F)V

    .line 41
    .line 42
    .line 43
    sget-wide v6, Le3/y;->a:J

    .line 44
    .line 45
    invoke-virtual {v4, v6, v7}, Le3/k0;->c(J)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v4, v6, v7}, Le3/k0;->z(J)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v4, v5}, Le3/k0;->g(F)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v4, v5}, Le3/k0;->h(F)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v4, v5}, Le3/k0;->i(F)V

    .line 58
    .line 59
    .line 60
    iget v6, v4, Le3/k0;->p:F

    .line 61
    .line 62
    const/high16 v7, 0x41000000    # 8.0f

    .line 63
    .line 64
    cmpg-float v6, v6, v7

    .line 65
    .line 66
    if-nez v6, :cond_1

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_1
    iget v6, v4, Le3/k0;->d:I

    .line 70
    .line 71
    or-int/lit16 v6, v6, 0x800

    .line 72
    .line 73
    iput v6, v4, Le3/k0;->d:I

    .line 74
    .line 75
    iput v7, v4, Le3/k0;->p:F

    .line 76
    .line 77
    :goto_0
    sget-wide v6, Le3/q0;->b:J

    .line 78
    .line 79
    invoke-virtual {v4, v6, v7}, Le3/k0;->A(J)V

    .line 80
    .line 81
    .line 82
    sget-object v8, Le3/j0;->a:Le3/i0;

    .line 83
    .line 84
    invoke-virtual {v4, v8}, Le3/k0;->w(Le3/n0;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v4, v2}, Le3/k0;->d(Z)V

    .line 88
    .line 89
    .line 90
    const/4 v8, 0x0

    .line 91
    invoke-virtual {v4, v8}, Le3/k0;->f(Le3/o;)V

    .line 92
    .line 93
    .line 94
    iget v9, v4, Le3/k0;->x:I

    .line 95
    .line 96
    const/high16 v10, 0x80000

    .line 97
    .line 98
    const/4 v11, 0x3

    .line 99
    if-ne v9, v11, :cond_2

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_2
    iget v9, v4, Le3/k0;->d:I

    .line 103
    .line 104
    or-int/2addr v9, v10

    .line 105
    iput v9, v4, Le3/k0;->d:I

    .line 106
    .line 107
    iput v11, v4, Le3/k0;->x:I

    .line 108
    .line 109
    :goto_1
    const-wide v11, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 110
    .line 111
    .line 112
    .line 113
    .line 114
    iput-wide v11, v4, Le3/k0;->t:J

    .line 115
    .line 116
    iput-object v8, v4, Le3/k0;->y:Le3/g0;

    .line 117
    .line 118
    iput v2, v4, Le3/k0;->d:I

    .line 119
    .line 120
    iget-object v9, v0, Lv3/f1;->r:Lv3/h0;

    .line 121
    .line 122
    iget-object v13, v9, Lv3/h0;->A:Lt4/c;

    .line 123
    .line 124
    iput-object v13, v4, Le3/k0;->u:Lt4/c;

    .line 125
    .line 126
    iget-object v13, v9, Lv3/h0;->B:Lt4/m;

    .line 127
    .line 128
    iput-object v13, v4, Le3/k0;->v:Lt4/m;

    .line 129
    .line 130
    iget-wide v13, v0, Lt3/e1;->f:J

    .line 131
    .line 132
    invoke-static {v13, v14}, Lkp/f9;->c(J)J

    .line 133
    .line 134
    .line 135
    move-result-wide v13

    .line 136
    iput-wide v13, v4, Le3/k0;->t:J

    .line 137
    .line 138
    invoke-static {v9}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 139
    .line 140
    .line 141
    move-result-object v13

    .line 142
    check-cast v13, Lw3/t;

    .line 143
    .line 144
    invoke-virtual {v13}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 145
    .line 146
    .line 147
    move-result-object v13

    .line 148
    sget-object v14, Lv3/e;->j:Lv3/e;

    .line 149
    .line 150
    new-instance v15, La7/j;

    .line 151
    .line 152
    move/from16 v16, v10

    .line 153
    .line 154
    const/16 v10, 0x18

    .line 155
    .line 156
    invoke-direct {v15, v3, v10}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v13, v0, v14, v15}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 160
    .line 161
    .line 162
    iget-object v3, v0, Lv3/f1;->F:Lv3/w;

    .line 163
    .line 164
    if-nez v3, :cond_3

    .line 165
    .line 166
    new-instance v3, Lv3/w;

    .line 167
    .line 168
    invoke-direct {v3}, Lv3/w;-><init>()V

    .line 169
    .line 170
    .line 171
    iput-object v3, v0, Lv3/f1;->F:Lv3/w;

    .line 172
    .line 173
    :cond_3
    sget-object v10, Lv3/f1;->O:Lv3/w;

    .line 174
    .line 175
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 176
    .line 177
    .line 178
    iget v13, v3, Lv3/w;->a:F

    .line 179
    .line 180
    iput v13, v10, Lv3/w;->a:F

    .line 181
    .line 182
    iget v13, v3, Lv3/w;->b:F

    .line 183
    .line 184
    iput v13, v10, Lv3/w;->b:F

    .line 185
    .line 186
    iget v13, v3, Lv3/w;->c:F

    .line 187
    .line 188
    iput v13, v10, Lv3/w;->c:F

    .line 189
    .line 190
    iget v13, v3, Lv3/w;->d:F

    .line 191
    .line 192
    iput v13, v10, Lv3/w;->d:F

    .line 193
    .line 194
    iget v13, v3, Lv3/w;->e:F

    .line 195
    .line 196
    iput v13, v10, Lv3/w;->e:F

    .line 197
    .line 198
    iget v13, v3, Lv3/w;->f:F

    .line 199
    .line 200
    iput v13, v10, Lv3/w;->f:F

    .line 201
    .line 202
    iget v13, v3, Lv3/w;->g:F

    .line 203
    .line 204
    iput v13, v10, Lv3/w;->g:F

    .line 205
    .line 206
    iget v13, v3, Lv3/w;->h:F

    .line 207
    .line 208
    iput v13, v10, Lv3/w;->h:F

    .line 209
    .line 210
    iget-wide v13, v3, Lv3/w;->i:J

    .line 211
    .line 212
    iput-wide v13, v10, Lv3/w;->i:J

    .line 213
    .line 214
    iget v13, v4, Le3/k0;->e:F

    .line 215
    .line 216
    iput v13, v3, Lv3/w;->a:F

    .line 217
    .line 218
    iget v14, v4, Le3/k0;->f:F

    .line 219
    .line 220
    iput v14, v3, Lv3/w;->b:F

    .line 221
    .line 222
    iget v14, v4, Le3/k0;->h:F

    .line 223
    .line 224
    iput v14, v3, Lv3/w;->c:F

    .line 225
    .line 226
    iget v14, v4, Le3/k0;->i:F

    .line 227
    .line 228
    iput v14, v3, Lv3/w;->d:F

    .line 229
    .line 230
    iget v14, v4, Le3/k0;->m:F

    .line 231
    .line 232
    iput v14, v3, Lv3/w;->e:F

    .line 233
    .line 234
    iget v14, v4, Le3/k0;->n:F

    .line 235
    .line 236
    iput v14, v3, Lv3/w;->f:F

    .line 237
    .line 238
    iget v14, v4, Le3/k0;->o:F

    .line 239
    .line 240
    iput v14, v3, Lv3/w;->g:F

    .line 241
    .line 242
    iget v14, v4, Le3/k0;->p:F

    .line 243
    .line 244
    iput v14, v3, Lv3/w;->h:F

    .line 245
    .line 246
    iget-wide v14, v4, Le3/k0;->q:J

    .line 247
    .line 248
    iput-wide v14, v3, Lv3/w;->i:J

    .line 249
    .line 250
    check-cast v1, Lw3/o1;

    .line 251
    .line 252
    move/from16 v17, v5

    .line 253
    .line 254
    iget-object v5, v1, Lw3/o1;->f:Lw3/t;

    .line 255
    .line 256
    iget v8, v4, Le3/k0;->d:I

    .line 257
    .line 258
    iget v2, v1, Lw3/o1;->q:I

    .line 259
    .line 260
    or-int/2addr v2, v8

    .line 261
    iget-object v8, v4, Le3/k0;->v:Lt4/m;

    .line 262
    .line 263
    iput-object v8, v1, Lw3/o1;->o:Lt4/m;

    .line 264
    .line 265
    iget-object v8, v4, Le3/k0;->u:Lt4/c;

    .line 266
    .line 267
    iput-object v8, v1, Lw3/o1;->n:Lt4/c;

    .line 268
    .line 269
    and-int/lit16 v8, v2, 0x1000

    .line 270
    .line 271
    if-eqz v8, :cond_4

    .line 272
    .line 273
    iput-wide v14, v1, Lw3/o1;->r:J

    .line 274
    .line 275
    :cond_4
    and-int/lit8 v14, v2, 0x1

    .line 276
    .line 277
    if-eqz v14, :cond_6

    .line 278
    .line 279
    iget-object v14, v1, Lw3/o1;->d:Lh3/c;

    .line 280
    .line 281
    iget-object v14, v14, Lh3/c;->a:Lh3/d;

    .line 282
    .line 283
    iget v15, v14, Lh3/d;->j:F

    .line 284
    .line 285
    cmpg-float v15, v15, v13

    .line 286
    .line 287
    if-nez v15, :cond_5

    .line 288
    .line 289
    goto :goto_2

    .line 290
    :cond_5
    iput v13, v14, Lh3/d;->j:F

    .line 291
    .line 292
    iget-object v14, v14, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 293
    .line 294
    invoke-virtual {v14, v13}, Landroid/graphics/RenderNode;->setScaleX(F)Z

    .line 295
    .line 296
    .line 297
    :cond_6
    :goto_2
    and-int/lit8 v13, v2, 0x2

    .line 298
    .line 299
    if-eqz v13, :cond_8

    .line 300
    .line 301
    iget-object v13, v1, Lw3/o1;->d:Lh3/c;

    .line 302
    .line 303
    iget v14, v4, Le3/k0;->f:F

    .line 304
    .line 305
    iget-object v13, v13, Lh3/c;->a:Lh3/d;

    .line 306
    .line 307
    iget v15, v13, Lh3/d;->k:F

    .line 308
    .line 309
    cmpg-float v15, v15, v14

    .line 310
    .line 311
    if-nez v15, :cond_7

    .line 312
    .line 313
    goto :goto_3

    .line 314
    :cond_7
    iput v14, v13, Lh3/d;->k:F

    .line 315
    .line 316
    iget-object v13, v13, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 317
    .line 318
    invoke-virtual {v13, v14}, Landroid/graphics/RenderNode;->setScaleY(F)Z

    .line 319
    .line 320
    .line 321
    :cond_8
    :goto_3
    and-int/lit8 v13, v2, 0x4

    .line 322
    .line 323
    if-eqz v13, :cond_9

    .line 324
    .line 325
    iget-object v13, v1, Lw3/o1;->d:Lh3/c;

    .line 326
    .line 327
    iget v14, v4, Le3/k0;->g:F

    .line 328
    .line 329
    invoke-virtual {v13, v14}, Lh3/c;->h(F)V

    .line 330
    .line 331
    .line 332
    :cond_9
    and-int/lit8 v13, v2, 0x8

    .line 333
    .line 334
    if-eqz v13, :cond_b

    .line 335
    .line 336
    iget-object v13, v1, Lw3/o1;->d:Lh3/c;

    .line 337
    .line 338
    iget v14, v4, Le3/k0;->h:F

    .line 339
    .line 340
    iget-object v13, v13, Lh3/c;->a:Lh3/d;

    .line 341
    .line 342
    iget v15, v13, Lh3/d;->l:F

    .line 343
    .line 344
    cmpg-float v15, v15, v14

    .line 345
    .line 346
    if-nez v15, :cond_a

    .line 347
    .line 348
    goto :goto_4

    .line 349
    :cond_a
    iput v14, v13, Lh3/d;->l:F

    .line 350
    .line 351
    iget-object v13, v13, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 352
    .line 353
    invoke-virtual {v13, v14}, Landroid/graphics/RenderNode;->setTranslationX(F)Z

    .line 354
    .line 355
    .line 356
    :cond_b
    :goto_4
    and-int/lit8 v13, v2, 0x10

    .line 357
    .line 358
    if-eqz v13, :cond_d

    .line 359
    .line 360
    iget-object v13, v1, Lw3/o1;->d:Lh3/c;

    .line 361
    .line 362
    iget v14, v4, Le3/k0;->i:F

    .line 363
    .line 364
    iget-object v13, v13, Lh3/c;->a:Lh3/d;

    .line 365
    .line 366
    iget v15, v13, Lh3/d;->m:F

    .line 367
    .line 368
    cmpg-float v15, v15, v14

    .line 369
    .line 370
    if-nez v15, :cond_c

    .line 371
    .line 372
    goto :goto_5

    .line 373
    :cond_c
    iput v14, v13, Lh3/d;->m:F

    .line 374
    .line 375
    iget-object v13, v13, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 376
    .line 377
    invoke-virtual {v13, v14}, Landroid/graphics/RenderNode;->setTranslationY(F)Z

    .line 378
    .line 379
    .line 380
    :cond_d
    :goto_5
    and-int/lit8 v13, v2, 0x20

    .line 381
    .line 382
    const/4 v14, 0x1

    .line 383
    if-eqz v13, :cond_f

    .line 384
    .line 385
    iget-object v13, v1, Lw3/o1;->d:Lh3/c;

    .line 386
    .line 387
    iget v15, v4, Le3/k0;->j:F

    .line 388
    .line 389
    iget-object v11, v13, Lh3/c;->a:Lh3/d;

    .line 390
    .line 391
    iget v12, v11, Lh3/d;->n:F

    .line 392
    .line 393
    cmpg-float v12, v12, v15

    .line 394
    .line 395
    if-nez v12, :cond_e

    .line 396
    .line 397
    goto :goto_6

    .line 398
    :cond_e
    iput v15, v11, Lh3/d;->n:F

    .line 399
    .line 400
    iget-object v11, v11, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 401
    .line 402
    invoke-virtual {v11, v15}, Landroid/graphics/RenderNode;->setElevation(F)Z

    .line 403
    .line 404
    .line 405
    iput-boolean v14, v13, Lh3/c;->g:Z

    .line 406
    .line 407
    invoke-virtual {v13}, Lh3/c;->a()V

    .line 408
    .line 409
    .line 410
    :goto_6
    iget v11, v4, Le3/k0;->j:F

    .line 411
    .line 412
    cmpl-float v11, v11, v17

    .line 413
    .line 414
    if-lez v11, :cond_f

    .line 415
    .line 416
    iget-boolean v11, v1, Lw3/o1;->w:Z

    .line 417
    .line 418
    if-nez v11, :cond_f

    .line 419
    .line 420
    iget-object v11, v1, Lw3/o1;->h:Lay0/a;

    .line 421
    .line 422
    if-eqz v11, :cond_f

    .line 423
    .line 424
    invoke-interface {v11}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 425
    .line 426
    .line 427
    :cond_f
    and-int/lit8 v11, v2, 0x40

    .line 428
    .line 429
    if-eqz v11, :cond_10

    .line 430
    .line 431
    iget-object v11, v1, Lw3/o1;->d:Lh3/c;

    .line 432
    .line 433
    iget-wide v12, v4, Le3/k0;->k:J

    .line 434
    .line 435
    iget-object v11, v11, Lh3/c;->a:Lh3/d;

    .line 436
    .line 437
    iget-wide v14, v11, Lh3/d;->o:J

    .line 438
    .line 439
    invoke-static {v12, v13, v14, v15}, Le3/s;->c(JJ)Z

    .line 440
    .line 441
    .line 442
    move-result v14

    .line 443
    if-nez v14, :cond_10

    .line 444
    .line 445
    iput-wide v12, v11, Lh3/d;->o:J

    .line 446
    .line 447
    iget-object v11, v11, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 448
    .line 449
    invoke-static {v12, v13}, Le3/j0;->z(J)I

    .line 450
    .line 451
    .line 452
    move-result v12

    .line 453
    invoke-virtual {v11, v12}, Landroid/graphics/RenderNode;->setAmbientShadowColor(I)Z

    .line 454
    .line 455
    .line 456
    :cond_10
    and-int/lit16 v11, v2, 0x80

    .line 457
    .line 458
    if-eqz v11, :cond_11

    .line 459
    .line 460
    iget-object v11, v1, Lw3/o1;->d:Lh3/c;

    .line 461
    .line 462
    iget-wide v12, v4, Le3/k0;->l:J

    .line 463
    .line 464
    iget-object v11, v11, Lh3/c;->a:Lh3/d;

    .line 465
    .line 466
    iget-wide v14, v11, Lh3/d;->p:J

    .line 467
    .line 468
    invoke-static {v12, v13, v14, v15}, Le3/s;->c(JJ)Z

    .line 469
    .line 470
    .line 471
    move-result v14

    .line 472
    if-nez v14, :cond_11

    .line 473
    .line 474
    iput-wide v12, v11, Lh3/d;->p:J

    .line 475
    .line 476
    iget-object v11, v11, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 477
    .line 478
    invoke-static {v12, v13}, Le3/j0;->z(J)I

    .line 479
    .line 480
    .line 481
    move-result v12

    .line 482
    invoke-virtual {v11, v12}, Landroid/graphics/RenderNode;->setSpotShadowColor(I)Z

    .line 483
    .line 484
    .line 485
    :cond_11
    and-int/lit16 v11, v2, 0x400

    .line 486
    .line 487
    if-eqz v11, :cond_13

    .line 488
    .line 489
    iget-object v11, v1, Lw3/o1;->d:Lh3/c;

    .line 490
    .line 491
    iget v12, v4, Le3/k0;->o:F

    .line 492
    .line 493
    iget-object v11, v11, Lh3/c;->a:Lh3/d;

    .line 494
    .line 495
    iget v13, v11, Lh3/d;->s:F

    .line 496
    .line 497
    cmpg-float v13, v13, v12

    .line 498
    .line 499
    if-nez v13, :cond_12

    .line 500
    .line 501
    goto :goto_7

    .line 502
    :cond_12
    iput v12, v11, Lh3/d;->s:F

    .line 503
    .line 504
    iget-object v11, v11, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 505
    .line 506
    invoke-virtual {v11, v12}, Landroid/graphics/RenderNode;->setRotationZ(F)Z

    .line 507
    .line 508
    .line 509
    :cond_13
    :goto_7
    and-int/lit16 v11, v2, 0x100

    .line 510
    .line 511
    if-eqz v11, :cond_15

    .line 512
    .line 513
    iget-object v11, v1, Lw3/o1;->d:Lh3/c;

    .line 514
    .line 515
    iget v12, v4, Le3/k0;->m:F

    .line 516
    .line 517
    iget-object v11, v11, Lh3/c;->a:Lh3/d;

    .line 518
    .line 519
    iget v13, v11, Lh3/d;->q:F

    .line 520
    .line 521
    cmpg-float v13, v13, v12

    .line 522
    .line 523
    if-nez v13, :cond_14

    .line 524
    .line 525
    goto :goto_8

    .line 526
    :cond_14
    iput v12, v11, Lh3/d;->q:F

    .line 527
    .line 528
    iget-object v11, v11, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 529
    .line 530
    invoke-virtual {v11, v12}, Landroid/graphics/RenderNode;->setRotationX(F)Z

    .line 531
    .line 532
    .line 533
    :cond_15
    :goto_8
    and-int/lit16 v11, v2, 0x200

    .line 534
    .line 535
    if-eqz v11, :cond_17

    .line 536
    .line 537
    iget-object v11, v1, Lw3/o1;->d:Lh3/c;

    .line 538
    .line 539
    iget v12, v4, Le3/k0;->n:F

    .line 540
    .line 541
    iget-object v11, v11, Lh3/c;->a:Lh3/d;

    .line 542
    .line 543
    iget v13, v11, Lh3/d;->r:F

    .line 544
    .line 545
    cmpg-float v13, v13, v12

    .line 546
    .line 547
    if-nez v13, :cond_16

    .line 548
    .line 549
    goto :goto_9

    .line 550
    :cond_16
    iput v12, v11, Lh3/d;->r:F

    .line 551
    .line 552
    iget-object v11, v11, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 553
    .line 554
    invoke-virtual {v11, v12}, Landroid/graphics/RenderNode;->setRotationY(F)Z

    .line 555
    .line 556
    .line 557
    :cond_17
    :goto_9
    and-int/lit16 v11, v2, 0x800

    .line 558
    .line 559
    if-eqz v11, :cond_19

    .line 560
    .line 561
    iget-object v11, v1, Lw3/o1;->d:Lh3/c;

    .line 562
    .line 563
    iget v12, v4, Le3/k0;->p:F

    .line 564
    .line 565
    iget-object v11, v11, Lh3/c;->a:Lh3/d;

    .line 566
    .line 567
    iget v13, v11, Lh3/d;->t:F

    .line 568
    .line 569
    cmpg-float v13, v13, v12

    .line 570
    .line 571
    if-nez v13, :cond_18

    .line 572
    .line 573
    goto :goto_a

    .line 574
    :cond_18
    iput v12, v11, Lh3/d;->t:F

    .line 575
    .line 576
    iget-object v11, v11, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 577
    .line 578
    invoke-virtual {v11, v12}, Landroid/graphics/RenderNode;->setCameraDistance(F)Z

    .line 579
    .line 580
    .line 581
    :cond_19
    :goto_a
    const/16 v11, 0x20

    .line 582
    .line 583
    const-wide v12, 0xffffffffL

    .line 584
    .line 585
    .line 586
    .line 587
    .line 588
    if-eqz v8, :cond_1c

    .line 589
    .line 590
    iget-wide v14, v1, Lw3/o1;->r:J

    .line 591
    .line 592
    invoke-static {v14, v15, v6, v7}, Le3/q0;->a(JJ)Z

    .line 593
    .line 594
    .line 595
    move-result v6

    .line 596
    if-eqz v6, :cond_1a

    .line 597
    .line 598
    iget-object v6, v1, Lw3/o1;->d:Lh3/c;

    .line 599
    .line 600
    iget-wide v7, v6, Lh3/c;->v:J

    .line 601
    .line 602
    const-wide v14, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 603
    .line 604
    .line 605
    .line 606
    .line 607
    invoke-static {v7, v8, v14, v15}, Ld3/b;->c(JJ)Z

    .line 608
    .line 609
    .line 610
    move-result v7

    .line 611
    if-nez v7, :cond_1c

    .line 612
    .line 613
    iput-wide v14, v6, Lh3/c;->v:J

    .line 614
    .line 615
    iget-object v6, v6, Lh3/c;->a:Lh3/d;

    .line 616
    .line 617
    iget-object v6, v6, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 618
    .line 619
    invoke-virtual {v6}, Landroid/graphics/RenderNode;->resetPivot()Z

    .line 620
    .line 621
    .line 622
    goto :goto_b

    .line 623
    :cond_1a
    iget-object v6, v1, Lw3/o1;->d:Lh3/c;

    .line 624
    .line 625
    iget-wide v7, v1, Lw3/o1;->r:J

    .line 626
    .line 627
    invoke-static {v7, v8}, Le3/q0;->b(J)F

    .line 628
    .line 629
    .line 630
    move-result v7

    .line 631
    iget-wide v14, v1, Lw3/o1;->i:J

    .line 632
    .line 633
    shr-long/2addr v14, v11

    .line 634
    long-to-int v8, v14

    .line 635
    int-to-float v8, v8

    .line 636
    mul-float/2addr v7, v8

    .line 637
    iget-wide v14, v1, Lw3/o1;->r:J

    .line 638
    .line 639
    invoke-static {v14, v15}, Le3/q0;->c(J)F

    .line 640
    .line 641
    .line 642
    move-result v8

    .line 643
    iget-wide v14, v1, Lw3/o1;->i:J

    .line 644
    .line 645
    and-long/2addr v14, v12

    .line 646
    long-to-int v14, v14

    .line 647
    int-to-float v14, v14

    .line 648
    mul-float/2addr v8, v14

    .line 649
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 650
    .line 651
    .line 652
    move-result v7

    .line 653
    int-to-long v14, v7

    .line 654
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 655
    .line 656
    .line 657
    move-result v7

    .line 658
    int-to-long v7, v7

    .line 659
    shl-long/2addr v14, v11

    .line 660
    and-long/2addr v7, v12

    .line 661
    or-long/2addr v7, v14

    .line 662
    iget-wide v14, v6, Lh3/c;->v:J

    .line 663
    .line 664
    invoke-static {v14, v15, v7, v8}, Ld3/b;->c(JJ)Z

    .line 665
    .line 666
    .line 667
    move-result v14

    .line 668
    if-nez v14, :cond_1c

    .line 669
    .line 670
    iput-wide v7, v6, Lh3/c;->v:J

    .line 671
    .line 672
    iget-object v6, v6, Lh3/c;->a:Lh3/d;

    .line 673
    .line 674
    iget-object v6, v6, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 675
    .line 676
    const-wide v14, 0x7fffffff7fffffffL

    .line 677
    .line 678
    .line 679
    .line 680
    .line 681
    and-long/2addr v14, v7

    .line 682
    const-wide v19, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 683
    .line 684
    .line 685
    .line 686
    .line 687
    cmp-long v14, v14, v19

    .line 688
    .line 689
    if-nez v14, :cond_1b

    .line 690
    .line 691
    invoke-virtual {v6}, Landroid/graphics/RenderNode;->resetPivot()Z

    .line 692
    .line 693
    .line 694
    goto :goto_b

    .line 695
    :cond_1b
    shr-long v14, v7, v11

    .line 696
    .line 697
    long-to-int v14, v14

    .line 698
    invoke-static {v14}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 699
    .line 700
    .line 701
    move-result v14

    .line 702
    invoke-virtual {v6, v14}, Landroid/graphics/RenderNode;->setPivotX(F)Z

    .line 703
    .line 704
    .line 705
    and-long/2addr v7, v12

    .line 706
    long-to-int v7, v7

    .line 707
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 708
    .line 709
    .line 710
    move-result v7

    .line 711
    invoke-virtual {v6, v7}, Landroid/graphics/RenderNode;->setPivotY(F)Z

    .line 712
    .line 713
    .line 714
    :cond_1c
    :goto_b
    and-int/lit16 v6, v2, 0x4000

    .line 715
    .line 716
    if-eqz v6, :cond_1d

    .line 717
    .line 718
    iget-object v6, v1, Lw3/o1;->d:Lh3/c;

    .line 719
    .line 720
    iget-boolean v7, v4, Le3/k0;->s:Z

    .line 721
    .line 722
    iget-boolean v8, v6, Lh3/c;->w:Z

    .line 723
    .line 724
    if-eq v8, v7, :cond_1d

    .line 725
    .line 726
    iput-boolean v7, v6, Lh3/c;->w:Z

    .line 727
    .line 728
    const/4 v7, 0x1

    .line 729
    iput-boolean v7, v6, Lh3/c;->g:Z

    .line 730
    .line 731
    invoke-virtual {v6}, Lh3/c;->a()V

    .line 732
    .line 733
    .line 734
    :cond_1d
    const/high16 v6, 0x20000

    .line 735
    .line 736
    and-int/2addr v6, v2

    .line 737
    if-eqz v6, :cond_21

    .line 738
    .line 739
    iget-object v6, v1, Lw3/o1;->d:Lh3/c;

    .line 740
    .line 741
    iget-object v7, v4, Le3/k0;->w:Le3/o;

    .line 742
    .line 743
    iget-object v6, v6, Lh3/c;->a:Lh3/d;

    .line 744
    .line 745
    iget-object v8, v6, Lh3/d;->x:Le3/o;

    .line 746
    .line 747
    invoke-static {v8, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 748
    .line 749
    .line 750
    move-result v8

    .line 751
    if-nez v8, :cond_21

    .line 752
    .line 753
    iput-object v7, v6, Lh3/d;->x:Le3/o;

    .line 754
    .line 755
    sget v8, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 756
    .line 757
    const/16 v14, 0x1f

    .line 758
    .line 759
    if-lt v8, v14, :cond_21

    .line 760
    .line 761
    iget-object v6, v6, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 762
    .line 763
    if-eqz v7, :cond_1f

    .line 764
    .line 765
    iget-object v8, v7, Le3/o;->a:Landroid/graphics/RenderEffect;

    .line 766
    .line 767
    if-nez v8, :cond_20

    .line 768
    .line 769
    iget v8, v7, Le3/o;->b:F

    .line 770
    .line 771
    iget v14, v7, Le3/o;->c:F

    .line 772
    .line 773
    iget v15, v7, Le3/o;->d:I

    .line 774
    .line 775
    cmpg-float v21, v8, v17

    .line 776
    .line 777
    if-nez v21, :cond_1e

    .line 778
    .line 779
    cmpg-float v21, v14, v17

    .line 780
    .line 781
    if-nez v21, :cond_1e

    .line 782
    .line 783
    invoke-static {}, Lc4/a;->f()Landroid/graphics/RenderEffect;

    .line 784
    .line 785
    .line 786
    move-result-object v8

    .line 787
    goto :goto_c

    .line 788
    :cond_1e
    invoke-static {v15}, Le3/j0;->y(I)Landroid/graphics/Shader$TileMode;

    .line 789
    .line 790
    .line 791
    move-result-object v15

    .line 792
    invoke-static {v8, v14, v15}, Lc4/a;->h(FFLandroid/graphics/Shader$TileMode;)Landroid/graphics/RenderEffect;

    .line 793
    .line 794
    .line 795
    move-result-object v8

    .line 796
    :goto_c
    iput-object v8, v7, Le3/o;->a:Landroid/graphics/RenderEffect;

    .line 797
    .line 798
    goto :goto_d

    .line 799
    :cond_1f
    const/4 v8, 0x0

    .line 800
    :cond_20
    :goto_d
    invoke-static {v6, v8}, Lc4/a;->t(Landroid/graphics/RenderNode;Landroid/graphics/RenderEffect;)V

    .line 801
    .line 802
    .line 803
    :cond_21
    const/high16 v6, 0x40000

    .line 804
    .line 805
    and-int/2addr v6, v2

    .line 806
    if-eqz v6, :cond_22

    .line 807
    .line 808
    iget-object v6, v1, Lw3/o1;->d:Lh3/c;

    .line 809
    .line 810
    iget-object v6, v6, Lh3/c;->a:Lh3/d;

    .line 811
    .line 812
    :cond_22
    and-int v6, v2, v16

    .line 813
    .line 814
    if-eqz v6, :cond_25

    .line 815
    .line 816
    iget-object v6, v1, Lw3/o1;->d:Lh3/c;

    .line 817
    .line 818
    iget v7, v4, Le3/k0;->x:I

    .line 819
    .line 820
    iget-object v6, v6, Lh3/c;->a:Lh3/d;

    .line 821
    .line 822
    iget v8, v6, Lh3/d;->i:I

    .line 823
    .line 824
    if-ne v8, v7, :cond_23

    .line 825
    .line 826
    goto :goto_e

    .line 827
    :cond_23
    iput v7, v6, Lh3/d;->i:I

    .line 828
    .line 829
    iget-object v8, v6, Lh3/d;->e:Landroid/graphics/Paint;

    .line 830
    .line 831
    if-nez v8, :cond_24

    .line 832
    .line 833
    new-instance v8, Landroid/graphics/Paint;

    .line 834
    .line 835
    invoke-direct {v8}, Landroid/graphics/Paint;-><init>()V

    .line 836
    .line 837
    .line 838
    iput-object v8, v6, Lh3/d;->e:Landroid/graphics/Paint;

    .line 839
    .line 840
    :cond_24
    invoke-static {v7}, Le3/j0;->u(I)Landroid/graphics/BlendMode;

    .line 841
    .line 842
    .line 843
    move-result-object v7

    .line 844
    invoke-virtual {v8, v7}, Landroid/graphics/Paint;->setBlendMode(Landroid/graphics/BlendMode;)V

    .line 845
    .line 846
    .line 847
    invoke-virtual {v6}, Lh3/d;->d()V

    .line 848
    .line 849
    .line 850
    :cond_25
    :goto_e
    const v6, 0x8000

    .line 851
    .line 852
    .line 853
    and-int/2addr v6, v2

    .line 854
    if-eqz v6, :cond_27

    .line 855
    .line 856
    iget-object v6, v1, Lw3/o1;->d:Lh3/c;

    .line 857
    .line 858
    iget-object v6, v6, Lh3/c;->a:Lh3/d;

    .line 859
    .line 860
    iget v7, v6, Lh3/d;->y:I

    .line 861
    .line 862
    if-nez v7, :cond_26

    .line 863
    .line 864
    goto :goto_f

    .line 865
    :cond_26
    const/4 v7, 0x0

    .line 866
    iput v7, v6, Lh3/d;->y:I

    .line 867
    .line 868
    invoke-virtual {v6}, Lh3/d;->d()V

    .line 869
    .line 870
    .line 871
    :cond_27
    :goto_f
    and-int/lit16 v6, v2, 0x1f1b

    .line 872
    .line 873
    if-eqz v6, :cond_28

    .line 874
    .line 875
    const/4 v7, 0x1

    .line 876
    iput-boolean v7, v1, Lw3/o1;->t:Z

    .line 877
    .line 878
    iput-boolean v7, v1, Lw3/o1;->u:Z

    .line 879
    .line 880
    :cond_28
    iget-object v6, v1, Lw3/o1;->s:Le3/g0;

    .line 881
    .line 882
    iget-object v7, v4, Le3/k0;->y:Le3/g0;

    .line 883
    .line 884
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 885
    .line 886
    .line 887
    move-result v6

    .line 888
    if-nez v6, :cond_2f

    .line 889
    .line 890
    iget-object v6, v4, Le3/k0;->y:Le3/g0;

    .line 891
    .line 892
    iput-object v6, v1, Lw3/o1;->s:Le3/g0;

    .line 893
    .line 894
    if-nez v6, :cond_29

    .line 895
    .line 896
    goto/16 :goto_11

    .line 897
    .line 898
    :cond_29
    iget-object v7, v1, Lw3/o1;->d:Lh3/c;

    .line 899
    .line 900
    instance-of v8, v6, Le3/e0;

    .line 901
    .line 902
    if-eqz v8, :cond_2a

    .line 903
    .line 904
    move-object v8, v6

    .line 905
    check-cast v8, Le3/e0;

    .line 906
    .line 907
    iget-object v8, v8, Le3/e0;->a:Ld3/c;

    .line 908
    .line 909
    iget v14, v8, Ld3/c;->a:F

    .line 910
    .line 911
    iget v15, v8, Ld3/c;->b:F

    .line 912
    .line 913
    move/from16 v16, v11

    .line 914
    .line 915
    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 916
    .line 917
    .line 918
    move-result v11

    .line 919
    move-wide/from16 v21, v12

    .line 920
    .line 921
    int-to-long v12, v11

    .line 922
    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 923
    .line 924
    .line 925
    move-result v11

    .line 926
    move-wide/from16 v19, v12

    .line 927
    .line 928
    int-to-long v11, v11

    .line 929
    shl-long v19, v19, v16

    .line 930
    .line 931
    and-long v11, v11, v21

    .line 932
    .line 933
    or-long v11, v19, v11

    .line 934
    .line 935
    iget v13, v8, Ld3/c;->c:F

    .line 936
    .line 937
    sub-float/2addr v13, v14

    .line 938
    iget v8, v8, Ld3/c;->d:F

    .line 939
    .line 940
    sub-float/2addr v8, v15

    .line 941
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 942
    .line 943
    .line 944
    move-result v13

    .line 945
    int-to-long v13, v13

    .line 946
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 947
    .line 948
    .line 949
    move-result v8

    .line 950
    move-object v15, v7

    .line 951
    int-to-long v7, v8

    .line 952
    shl-long v13, v13, v16

    .line 953
    .line 954
    and-long v7, v7, v21

    .line 955
    .line 956
    or-long v24, v13, v7

    .line 957
    .line 958
    const/16 v26, 0x0

    .line 959
    .line 960
    move-wide/from16 v22, v11

    .line 961
    .line 962
    move-object/from16 v21, v15

    .line 963
    .line 964
    invoke-virtual/range {v21 .. v26}, Lh3/c;->i(JJF)V

    .line 965
    .line 966
    .line 967
    goto/16 :goto_10

    .line 968
    .line 969
    :cond_2a
    move-object v15, v7

    .line 970
    move/from16 v16, v11

    .line 971
    .line 972
    move-wide/from16 v21, v12

    .line 973
    .line 974
    instance-of v7, v6, Le3/d0;

    .line 975
    .line 976
    const-wide/16 v11, 0x0

    .line 977
    .line 978
    if-eqz v7, :cond_2b

    .line 979
    .line 980
    move-object v7, v6

    .line 981
    check-cast v7, Le3/d0;

    .line 982
    .line 983
    iget-object v7, v7, Le3/d0;->a:Le3/i;

    .line 984
    .line 985
    const/4 v8, 0x0

    .line 986
    iput-object v8, v15, Lh3/c;->k:Le3/g0;

    .line 987
    .line 988
    const-wide v13, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 989
    .line 990
    .line 991
    .line 992
    .line 993
    iput-wide v13, v15, Lh3/c;->i:J

    .line 994
    .line 995
    iput-wide v11, v15, Lh3/c;->h:J

    .line 996
    .line 997
    move/from16 v8, v17

    .line 998
    .line 999
    iput v8, v15, Lh3/c;->j:F

    .line 1000
    .line 1001
    const/4 v8, 0x1

    .line 1002
    iput-boolean v8, v15, Lh3/c;->g:Z

    .line 1003
    .line 1004
    const/4 v8, 0x0

    .line 1005
    iput-boolean v8, v15, Lh3/c;->n:Z

    .line 1006
    .line 1007
    iput-object v7, v15, Lh3/c;->l:Le3/i;

    .line 1008
    .line 1009
    invoke-virtual {v15}, Lh3/c;->a()V

    .line 1010
    .line 1011
    .line 1012
    goto :goto_10

    .line 1013
    :cond_2b
    instance-of v7, v6, Le3/f0;

    .line 1014
    .line 1015
    if-eqz v7, :cond_2e

    .line 1016
    .line 1017
    move-object v7, v6

    .line 1018
    check-cast v7, Le3/f0;

    .line 1019
    .line 1020
    iget-object v8, v7, Le3/f0;->b:Le3/i;

    .line 1021
    .line 1022
    if-eqz v8, :cond_2c

    .line 1023
    .line 1024
    const/4 v13, 0x0

    .line 1025
    iput-object v13, v15, Lh3/c;->k:Le3/g0;

    .line 1026
    .line 1027
    const-wide v13, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 1028
    .line 1029
    .line 1030
    .line 1031
    .line 1032
    iput-wide v13, v15, Lh3/c;->i:J

    .line 1033
    .line 1034
    iput-wide v11, v15, Lh3/c;->h:J

    .line 1035
    .line 1036
    const/4 v7, 0x0

    .line 1037
    iput v7, v15, Lh3/c;->j:F

    .line 1038
    .line 1039
    const/4 v11, 0x1

    .line 1040
    iput-boolean v11, v15, Lh3/c;->g:Z

    .line 1041
    .line 1042
    const/4 v7, 0x0

    .line 1043
    iput-boolean v7, v15, Lh3/c;->n:Z

    .line 1044
    .line 1045
    iput-object v8, v15, Lh3/c;->l:Le3/i;

    .line 1046
    .line 1047
    invoke-virtual {v15}, Lh3/c;->a()V

    .line 1048
    .line 1049
    .line 1050
    goto :goto_10

    .line 1051
    :cond_2c
    const/4 v11, 0x1

    .line 1052
    iget-object v7, v7, Le3/f0;->a:Ld3/d;

    .line 1053
    .line 1054
    iget v8, v7, Ld3/d;->a:F

    .line 1055
    .line 1056
    iget v12, v7, Ld3/d;->b:F

    .line 1057
    .line 1058
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1059
    .line 1060
    .line 1061
    move-result v8

    .line 1062
    int-to-long v13, v8

    .line 1063
    invoke-static {v12}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1064
    .line 1065
    .line 1066
    move-result v8

    .line 1067
    int-to-long v11, v8

    .line 1068
    shl-long v13, v13, v16

    .line 1069
    .line 1070
    and-long v11, v11, v21

    .line 1071
    .line 1072
    or-long/2addr v11, v13

    .line 1073
    invoke-virtual {v7}, Ld3/d;->b()F

    .line 1074
    .line 1075
    .line 1076
    move-result v8

    .line 1077
    invoke-virtual {v7}, Ld3/d;->a()F

    .line 1078
    .line 1079
    .line 1080
    move-result v13

    .line 1081
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1082
    .line 1083
    .line 1084
    move-result v8

    .line 1085
    move-wide/from16 v19, v11

    .line 1086
    .line 1087
    int-to-long v11, v8

    .line 1088
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1089
    .line 1090
    .line 1091
    move-result v8

    .line 1092
    int-to-long v13, v8

    .line 1093
    shl-long v11, v11, v16

    .line 1094
    .line 1095
    and-long v13, v13, v21

    .line 1096
    .line 1097
    or-long v24, v11, v13

    .line 1098
    .line 1099
    iget-wide v7, v7, Ld3/d;->h:J

    .line 1100
    .line 1101
    shr-long v7, v7, v16

    .line 1102
    .line 1103
    long-to-int v7, v7

    .line 1104
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1105
    .line 1106
    .line 1107
    move-result v26

    .line 1108
    move-object/from16 v21, v15

    .line 1109
    .line 1110
    move-wide/from16 v22, v19

    .line 1111
    .line 1112
    invoke-virtual/range {v21 .. v26}, Lh3/c;->i(JJF)V

    .line 1113
    .line 1114
    .line 1115
    :goto_10
    instance-of v6, v6, Le3/d0;

    .line 1116
    .line 1117
    if-eqz v6, :cond_2d

    .line 1118
    .line 1119
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 1120
    .line 1121
    const/16 v7, 0x21

    .line 1122
    .line 1123
    if-ge v6, v7, :cond_2d

    .line 1124
    .line 1125
    iget-object v6, v1, Lw3/o1;->h:Lay0/a;

    .line 1126
    .line 1127
    if-eqz v6, :cond_2d

    .line 1128
    .line 1129
    invoke-interface {v6}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 1130
    .line 1131
    .line 1132
    :cond_2d
    :goto_11
    const/4 v7, 0x1

    .line 1133
    goto :goto_12

    .line 1134
    :cond_2e
    new-instance v0, La8/r0;

    .line 1135
    .line 1136
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1137
    .line 1138
    .line 1139
    throw v0

    .line 1140
    :cond_2f
    const/4 v7, 0x0

    .line 1141
    :goto_12
    iget v6, v4, Le3/k0;->d:I

    .line 1142
    .line 1143
    iput v6, v1, Lw3/o1;->q:I

    .line 1144
    .line 1145
    if-nez v2, :cond_30

    .line 1146
    .line 1147
    if-eqz v7, :cond_32

    .line 1148
    .line 1149
    :cond_30
    invoke-virtual {v5}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 1150
    .line 1151
    .line 1152
    move-result-object v1

    .line 1153
    if-eqz v1, :cond_31

    .line 1154
    .line 1155
    invoke-interface {v1, v5, v5}, Landroid/view/ViewParent;->onDescendantInvalidated(Landroid/view/View;Landroid/view/View;)V

    .line 1156
    .line 1157
    .line 1158
    :cond_31
    iget-boolean v1, v5, Lw3/t;->i:Z

    .line 1159
    .line 1160
    if-eqz v1, :cond_32

    .line 1161
    .line 1162
    const/4 v7, 0x0

    .line 1163
    invoke-virtual {v5, v7}, Lw3/t;->I(F)V

    .line 1164
    .line 1165
    .line 1166
    :cond_32
    iget-boolean v1, v0, Lv3/f1;->v:Z

    .line 1167
    .line 1168
    iget-boolean v2, v4, Le3/k0;->s:Z

    .line 1169
    .line 1170
    iput-boolean v2, v0, Lv3/f1;->v:Z

    .line 1171
    .line 1172
    iget v2, v4, Le3/k0;->g:F

    .line 1173
    .line 1174
    iput v2, v0, Lv3/f1;->z:F

    .line 1175
    .line 1176
    iget v2, v10, Lv3/w;->a:F

    .line 1177
    .line 1178
    iget v4, v3, Lv3/w;->a:F

    .line 1179
    .line 1180
    cmpg-float v2, v2, v4

    .line 1181
    .line 1182
    if-nez v2, :cond_33

    .line 1183
    .line 1184
    iget v2, v10, Lv3/w;->b:F

    .line 1185
    .line 1186
    iget v4, v3, Lv3/w;->b:F

    .line 1187
    .line 1188
    cmpg-float v2, v2, v4

    .line 1189
    .line 1190
    if-nez v2, :cond_33

    .line 1191
    .line 1192
    iget v2, v10, Lv3/w;->c:F

    .line 1193
    .line 1194
    iget v4, v3, Lv3/w;->c:F

    .line 1195
    .line 1196
    cmpg-float v2, v2, v4

    .line 1197
    .line 1198
    if-nez v2, :cond_33

    .line 1199
    .line 1200
    iget v2, v10, Lv3/w;->d:F

    .line 1201
    .line 1202
    iget v4, v3, Lv3/w;->d:F

    .line 1203
    .line 1204
    cmpg-float v2, v2, v4

    .line 1205
    .line 1206
    if-nez v2, :cond_33

    .line 1207
    .line 1208
    iget v2, v10, Lv3/w;->e:F

    .line 1209
    .line 1210
    iget v4, v3, Lv3/w;->e:F

    .line 1211
    .line 1212
    cmpg-float v2, v2, v4

    .line 1213
    .line 1214
    if-nez v2, :cond_33

    .line 1215
    .line 1216
    iget v2, v10, Lv3/w;->f:F

    .line 1217
    .line 1218
    iget v4, v3, Lv3/w;->f:F

    .line 1219
    .line 1220
    cmpg-float v2, v2, v4

    .line 1221
    .line 1222
    if-nez v2, :cond_33

    .line 1223
    .line 1224
    iget v2, v10, Lv3/w;->g:F

    .line 1225
    .line 1226
    iget v4, v3, Lv3/w;->g:F

    .line 1227
    .line 1228
    cmpg-float v2, v2, v4

    .line 1229
    .line 1230
    if-nez v2, :cond_33

    .line 1231
    .line 1232
    iget v2, v10, Lv3/w;->h:F

    .line 1233
    .line 1234
    iget v4, v3, Lv3/w;->h:F

    .line 1235
    .line 1236
    cmpg-float v2, v2, v4

    .line 1237
    .line 1238
    if-nez v2, :cond_33

    .line 1239
    .line 1240
    iget-wide v4, v10, Lv3/w;->i:J

    .line 1241
    .line 1242
    iget-wide v2, v3, Lv3/w;->i:J

    .line 1243
    .line 1244
    invoke-static {v4, v5, v2, v3}, Le3/q0;->a(JJ)Z

    .line 1245
    .line 1246
    .line 1247
    move-result v2

    .line 1248
    if-eqz v2, :cond_33

    .line 1249
    .line 1250
    const/4 v2, 0x1

    .line 1251
    goto :goto_13

    .line 1252
    :cond_33
    const/4 v2, 0x0

    .line 1253
    :goto_13
    xor-int/lit8 v3, v2, 0x1

    .line 1254
    .line 1255
    if-eqz p1, :cond_35

    .line 1256
    .line 1257
    if-eqz v2, :cond_34

    .line 1258
    .line 1259
    iget-boolean v0, v0, Lv3/f1;->v:Z

    .line 1260
    .line 1261
    if-eq v1, v0, :cond_35

    .line 1262
    .line 1263
    :cond_34
    iget-object v0, v9, Lv3/h0;->p:Lv3/o1;

    .line 1264
    .line 1265
    if-eqz v0, :cond_35

    .line 1266
    .line 1267
    check-cast v0, Lw3/t;

    .line 1268
    .line 1269
    invoke-virtual {v0, v9}, Lw3/t;->v(Lv3/h0;)V

    .line 1270
    .line 1271
    .line 1272
    :cond_35
    return v3

    .line 1273
    :cond_36
    const-string v0, "updateLayerParameters requires a non-null layerBlock"

    .line 1274
    .line 1275
    invoke-static {v0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 1276
    .line 1277
    .line 1278
    move-result-object v0

    .line 1279
    throw v0

    .line 1280
    :cond_37
    iget-object v0, v0, Lv3/f1;->w:Lay0/k;

    .line 1281
    .line 1282
    const/16 v18, 0x0

    .line 1283
    .line 1284
    if-nez v0, :cond_38

    .line 1285
    .line 1286
    :goto_14
    return v18

    .line 1287
    :cond_38
    const-string v0, "null layer with a non-null layerBlock"

    .line 1288
    .line 1289
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 1290
    .line 1291
    .line 1292
    return v18
.end method

.method public final G1(J)Z
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-wide v1, 0x7f8000007f800000L    # 1.404448428688076E306

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    and-long v3, p1, v1

    .line 9
    .line 10
    xor-long/2addr v1, v3

    .line 11
    const-wide v3, 0x100000001L

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    sub-long/2addr v1, v3

    .line 17
    const-wide v3, -0x7fffffff80000000L    # -1.0609978955E-314

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    and-long/2addr v1, v3

    .line 23
    const-wide/16 v3, 0x0

    .line 24
    .line 25
    cmp-long v1, v1, v3

    .line 26
    .line 27
    if-nez v1, :cond_d

    .line 28
    .line 29
    iget-object v1, v0, Lv3/f1;->L:Lv3/n1;

    .line 30
    .line 31
    if-eqz v1, :cond_c

    .line 32
    .line 33
    iget-boolean v0, v0, Lv3/f1;->v:Z

    .line 34
    .line 35
    if-eqz v0, :cond_c

    .line 36
    .line 37
    check-cast v1, Lw3/o1;

    .line 38
    .line 39
    const/16 v0, 0x20

    .line 40
    .line 41
    shr-long v4, p1, v0

    .line 42
    .line 43
    long-to-int v4, v4

    .line 44
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 45
    .line 46
    .line 47
    move-result v7

    .line 48
    const-wide v4, 0xffffffffL

    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    and-long v8, p1, v4

    .line 54
    .line 55
    long-to-int v6, v8

    .line 56
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 57
    .line 58
    .line 59
    move-result v8

    .line 60
    iget-object v1, v1, Lw3/o1;->d:Lh3/c;

    .line 61
    .line 62
    iget-boolean v6, v1, Lh3/c;->w:Z

    .line 63
    .line 64
    if-eqz v6, :cond_a

    .line 65
    .line 66
    invoke-virtual {v1}, Lh3/c;->e()Le3/g0;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    instance-of v6, v1, Le3/e0;

    .line 71
    .line 72
    if-eqz v6, :cond_1

    .line 73
    .line 74
    check-cast v1, Le3/e0;

    .line 75
    .line 76
    iget-object v0, v1, Le3/e0;->a:Ld3/c;

    .line 77
    .line 78
    iget v1, v0, Ld3/c;->a:F

    .line 79
    .line 80
    cmpg-float v1, v1, v7

    .line 81
    .line 82
    if-gtz v1, :cond_0

    .line 83
    .line 84
    iget v1, v0, Ld3/c;->c:F

    .line 85
    .line 86
    cmpg-float v1, v7, v1

    .line 87
    .line 88
    if-gez v1, :cond_0

    .line 89
    .line 90
    iget v1, v0, Ld3/c;->b:F

    .line 91
    .line 92
    cmpg-float v1, v1, v8

    .line 93
    .line 94
    if-gtz v1, :cond_0

    .line 95
    .line 96
    iget v0, v0, Ld3/c;->d:F

    .line 97
    .line 98
    cmpg-float v0, v8, v0

    .line 99
    .line 100
    if-gez v0, :cond_0

    .line 101
    .line 102
    goto/16 :goto_1

    .line 103
    .line 104
    :cond_0
    const/16 v16, 0x0

    .line 105
    .line 106
    const/16 v17, 0x1

    .line 107
    .line 108
    goto/16 :goto_0

    .line 109
    .line 110
    :cond_1
    instance-of v6, v1, Le3/f0;

    .line 111
    .line 112
    if-eqz v6, :cond_8

    .line 113
    .line 114
    check-cast v1, Le3/f0;

    .line 115
    .line 116
    iget-object v1, v1, Le3/f0;->a:Ld3/d;

    .line 117
    .line 118
    iget v6, v1, Ld3/d;->a:F

    .line 119
    .line 120
    iget-wide v9, v1, Ld3/d;->f:J

    .line 121
    .line 122
    iget-wide v11, v1, Ld3/d;->h:J

    .line 123
    .line 124
    iget-wide v13, v1, Ld3/d;->g:J

    .line 125
    .line 126
    iget v15, v1, Ld3/d;->d:F

    .line 127
    .line 128
    move/from16 p0, v0

    .line 129
    .line 130
    iget v0, v1, Ld3/d;->b:F

    .line 131
    .line 132
    const/16 v16, 0x0

    .line 133
    .line 134
    iget v2, v1, Ld3/d;->c:F

    .line 135
    .line 136
    move-wide/from16 v18, v4

    .line 137
    .line 138
    const/16 v17, 0x1

    .line 139
    .line 140
    iget-wide v3, v1, Ld3/d;->e:J

    .line 141
    .line 142
    cmpg-float v5, v7, v6

    .line 143
    .line 144
    if-ltz v5, :cond_7

    .line 145
    .line 146
    cmpl-float v5, v7, v2

    .line 147
    .line 148
    if-gez v5, :cond_7

    .line 149
    .line 150
    cmpg-float v5, v8, v0

    .line 151
    .line 152
    if-ltz v5, :cond_7

    .line 153
    .line 154
    cmpl-float v5, v8, v15

    .line 155
    .line 156
    if-ltz v5, :cond_2

    .line 157
    .line 158
    goto/16 :goto_0

    .line 159
    .line 160
    :cond_2
    move v5, v2

    .line 161
    move-wide/from16 p1, v3

    .line 162
    .line 163
    shr-long v2, p1, p0

    .line 164
    .line 165
    long-to-int v2, v2

    .line 166
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 167
    .line 168
    .line 169
    move-result v3

    .line 170
    move v4, v2

    .line 171
    move/from16 v20, v3

    .line 172
    .line 173
    shr-long v2, v9, p0

    .line 174
    .line 175
    long-to-int v2, v2

    .line 176
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 177
    .line 178
    .line 179
    move-result v3

    .line 180
    add-float v3, v3, v20

    .line 181
    .line 182
    invoke-virtual {v1}, Ld3/d;->b()F

    .line 183
    .line 184
    .line 185
    move-result v20

    .line 186
    cmpg-float v3, v3, v20

    .line 187
    .line 188
    if-gtz v3, :cond_6

    .line 189
    .line 190
    move/from16 v20, v2

    .line 191
    .line 192
    shr-long v2, v11, p0

    .line 193
    .line 194
    long-to-int v2, v2

    .line 195
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 196
    .line 197
    .line 198
    move-result v3

    .line 199
    move/from16 v21, v2

    .line 200
    .line 201
    move/from16 v22, v3

    .line 202
    .line 203
    shr-long v2, v13, p0

    .line 204
    .line 205
    long-to-int v2, v2

    .line 206
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 207
    .line 208
    .line 209
    move-result v3

    .line 210
    add-float v3, v3, v22

    .line 211
    .line 212
    invoke-virtual {v1}, Ld3/d;->b()F

    .line 213
    .line 214
    .line 215
    move-result v22

    .line 216
    cmpg-float v3, v3, v22

    .line 217
    .line 218
    if-gtz v3, :cond_6

    .line 219
    .line 220
    move/from16 v22, v2

    .line 221
    .line 222
    and-long v2, p1, v18

    .line 223
    .line 224
    long-to-int v2, v2

    .line 225
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 226
    .line 227
    .line 228
    move-result v3

    .line 229
    and-long v11, v11, v18

    .line 230
    .line 231
    long-to-int v11, v11

    .line 232
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 233
    .line 234
    .line 235
    move-result v12

    .line 236
    add-float/2addr v12, v3

    .line 237
    invoke-virtual {v1}, Ld3/d;->a()F

    .line 238
    .line 239
    .line 240
    move-result v3

    .line 241
    cmpg-float v3, v12, v3

    .line 242
    .line 243
    if-gtz v3, :cond_6

    .line 244
    .line 245
    and-long v9, v9, v18

    .line 246
    .line 247
    long-to-int v3, v9

    .line 248
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 249
    .line 250
    .line 251
    move-result v9

    .line 252
    and-long v12, v13, v18

    .line 253
    .line 254
    long-to-int v10, v12

    .line 255
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 256
    .line 257
    .line 258
    move-result v12

    .line 259
    add-float/2addr v12, v9

    .line 260
    invoke-virtual {v1}, Ld3/d;->a()F

    .line 261
    .line 262
    .line 263
    move-result v9

    .line 264
    cmpg-float v9, v12, v9

    .line 265
    .line 266
    if-gtz v9, :cond_6

    .line 267
    .line 268
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 269
    .line 270
    .line 271
    move-result v4

    .line 272
    add-float v9, v4, v6

    .line 273
    .line 274
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 275
    .line 276
    .line 277
    move-result v2

    .line 278
    add-float/2addr v2, v0

    .line 279
    invoke-static/range {v20 .. v20}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 280
    .line 281
    .line 282
    move-result v4

    .line 283
    sub-float v4, v5, v4

    .line 284
    .line 285
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 286
    .line 287
    .line 288
    move-result v3

    .line 289
    add-float/2addr v3, v0

    .line 290
    invoke-static/range {v22 .. v22}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 291
    .line 292
    .line 293
    move-result v0

    .line 294
    sub-float v0, v5, v0

    .line 295
    .line 296
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 297
    .line 298
    .line 299
    move-result v5

    .line 300
    sub-float v10, v15, v5

    .line 301
    .line 302
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 303
    .line 304
    .line 305
    move-result v5

    .line 306
    sub-float/2addr v15, v5

    .line 307
    invoke-static/range {v21 .. v21}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 308
    .line 309
    .line 310
    move-result v5

    .line 311
    add-float/2addr v5, v6

    .line 312
    cmpg-float v6, v7, v9

    .line 313
    .line 314
    if-gez v6, :cond_3

    .line 315
    .line 316
    cmpg-float v6, v8, v2

    .line 317
    .line 318
    if-gez v6, :cond_3

    .line 319
    .line 320
    iget-wide v5, v1, Ld3/d;->e:J

    .line 321
    .line 322
    move v10, v2

    .line 323
    invoke-static/range {v5 .. v10}, Lw3/h0;->y(JFFFF)Z

    .line 324
    .line 325
    .line 326
    move-result v0

    .line 327
    goto/16 :goto_2

    .line 328
    .line 329
    :cond_3
    cmpg-float v2, v7, v5

    .line 330
    .line 331
    if-gez v2, :cond_4

    .line 332
    .line 333
    cmpl-float v2, v8, v15

    .line 334
    .line 335
    if-lez v2, :cond_4

    .line 336
    .line 337
    move v9, v5

    .line 338
    iget-wide v5, v1, Ld3/d;->h:J

    .line 339
    .line 340
    move v10, v15

    .line 341
    invoke-static/range {v5 .. v10}, Lw3/h0;->y(JFFFF)Z

    .line 342
    .line 343
    .line 344
    move-result v0

    .line 345
    goto :goto_2

    .line 346
    :cond_4
    cmpl-float v2, v7, v4

    .line 347
    .line 348
    if-lez v2, :cond_5

    .line 349
    .line 350
    cmpg-float v2, v8, v3

    .line 351
    .line 352
    if-gez v2, :cond_5

    .line 353
    .line 354
    iget-wide v5, v1, Ld3/d;->f:J

    .line 355
    .line 356
    move v10, v3

    .line 357
    move v9, v4

    .line 358
    invoke-static/range {v5 .. v10}, Lw3/h0;->y(JFFFF)Z

    .line 359
    .line 360
    .line 361
    move-result v0

    .line 362
    goto :goto_2

    .line 363
    :cond_5
    cmpl-float v2, v7, v0

    .line 364
    .line 365
    if-lez v2, :cond_b

    .line 366
    .line 367
    cmpl-float v2, v8, v10

    .line 368
    .line 369
    if-lez v2, :cond_b

    .line 370
    .line 371
    iget-wide v5, v1, Ld3/d;->g:J

    .line 372
    .line 373
    move v9, v0

    .line 374
    invoke-static/range {v5 .. v10}, Lw3/h0;->y(JFFFF)Z

    .line 375
    .line 376
    .line 377
    move-result v0

    .line 378
    goto :goto_2

    .line 379
    :cond_6
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 380
    .line 381
    .line 382
    move-result-object v0

    .line 383
    invoke-static {v0, v1}, Le3/i;->c(Le3/i;Ld3/d;)V

    .line 384
    .line 385
    .line 386
    invoke-static {v7, v8, v0}, Lw3/h0;->x(FFLe3/i;)Z

    .line 387
    .line 388
    .line 389
    move-result v0

    .line 390
    goto :goto_2

    .line 391
    :cond_7
    :goto_0
    move/from16 v0, v16

    .line 392
    .line 393
    goto :goto_2

    .line 394
    :cond_8
    const/16 v16, 0x0

    .line 395
    .line 396
    const/16 v17, 0x1

    .line 397
    .line 398
    instance-of v0, v1, Le3/d0;

    .line 399
    .line 400
    if-eqz v0, :cond_9

    .line 401
    .line 402
    check-cast v1, Le3/d0;

    .line 403
    .line 404
    iget-object v0, v1, Le3/d0;->a:Le3/i;

    .line 405
    .line 406
    invoke-static {v7, v8, v0}, Lw3/h0;->x(FFLe3/i;)Z

    .line 407
    .line 408
    .line 409
    move-result v0

    .line 410
    goto :goto_2

    .line 411
    :cond_9
    new-instance v0, La8/r0;

    .line 412
    .line 413
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 414
    .line 415
    .line 416
    throw v0

    .line 417
    :cond_a
    :goto_1
    const/16 v16, 0x0

    .line 418
    .line 419
    const/16 v17, 0x1

    .line 420
    .line 421
    :cond_b
    move/from16 v0, v17

    .line 422
    .line 423
    :goto_2
    if-eqz v0, :cond_e

    .line 424
    .line 425
    goto :goto_3

    .line 426
    :cond_c
    const/16 v17, 0x1

    .line 427
    .line 428
    :goto_3
    return v17

    .line 429
    :cond_d
    const/16 v16, 0x0

    .line 430
    .line 431
    :cond_e
    return v16
.end method

.method public final H0()Lv3/p0;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/f1;->s:Lv3/f1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final J0()Lt3/y;
    .locals 0

    .line 1
    return-object p0
.end method

.method public final K(J)J
    .locals 1

    .line 1
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const-string v0, "LayoutCoordinate operations are only valid when isAttached is true"

    .line 10
    .line 11
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    invoke-virtual {p0, p1, p2}, Lv3/f1;->R(J)J

    .line 15
    .line 16
    .line 17
    move-result-wide p1

    .line 18
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 19
    .line 20
    invoke-static {p0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    check-cast p0, Lw3/t;

    .line 25
    .line 26
    invoke-virtual {p0, p1, p2}, Lw3/t;->q(J)J

    .line 27
    .line 28
    .line 29
    move-result-wide p0

    .line 30
    return-wide p0
.end method

.method public final L0()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/f1;->A:Lt3/r0;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final M0()Lv3/h0;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final N0()Lt3/r0;
    .locals 1

    .line 1
    iget-object p0, p0, Lv3/f1;->A:Lt3/r0;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    const-string v0, "Asking for measurement result of unmeasured layout modifier"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public final O()Lt3/y;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const-string v0, "LayoutCoordinate operations are only valid when isAttached is true"

    .line 10
    .line 11
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    invoke-virtual {p0}, Lv3/f1;->p1()V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 18
    .line 19
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 20
    .line 21
    iget-object p0, p0, Lg1/q;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lv3/f1;

    .line 24
    .line 25
    iget-object p0, p0, Lv3/f1;->t:Lv3/f1;

    .line 26
    .line 27
    return-object p0
.end method

.method public final O0()Lv3/p0;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/f1;->t:Lv3/f1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final P(Lt3/y;Z)Ld3/c;
    .locals 7

    .line 1
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const-string v0, "LayoutCoordinate operations are only valid when isAttached is true"

    .line 10
    .line 11
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    invoke-interface {p1}, Lt3/y;->g()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    new-instance v0, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string v1, "LayoutCoordinates "

    .line 23
    .line 24
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, " is not attached!"

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    :cond_1
    invoke-static {p1}, Lv3/f1;->z1(Lt3/y;)Lv3/f1;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-virtual {v0}, Lv3/f1;->p1()V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0, v0}, Lv3/f1;->b1(Lv3/f1;)Lv3/f1;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    iget-object v2, p0, Lv3/f1;->E:Ld3/a;

    .line 54
    .line 55
    if-nez v2, :cond_2

    .line 56
    .line 57
    new-instance v2, Ld3/a;

    .line 58
    .line 59
    const/4 v3, 0x0

    .line 60
    invoke-direct {v2, v3}, Ld3/a;-><init>(I)V

    .line 61
    .line 62
    .line 63
    iput-object v2, p0, Lv3/f1;->E:Ld3/a;

    .line 64
    .line 65
    :cond_2
    const/4 v3, 0x0

    .line 66
    iput v3, v2, Ld3/a;->b:F

    .line 67
    .line 68
    iput v3, v2, Ld3/a;->c:F

    .line 69
    .line 70
    invoke-interface {p1}, Lt3/y;->h()J

    .line 71
    .line 72
    .line 73
    move-result-wide v3

    .line 74
    const/16 v5, 0x20

    .line 75
    .line 76
    shr-long/2addr v3, v5

    .line 77
    long-to-int v3, v3

    .line 78
    int-to-float v3, v3

    .line 79
    iput v3, v2, Ld3/a;->d:F

    .line 80
    .line 81
    invoke-interface {p1}, Lt3/y;->h()J

    .line 82
    .line 83
    .line 84
    move-result-wide v3

    .line 85
    const-wide v5, 0xffffffffL

    .line 86
    .line 87
    .line 88
    .line 89
    .line 90
    and-long/2addr v3, v5

    .line 91
    long-to-int p1, v3

    .line 92
    int-to-float p1, p1

    .line 93
    iput p1, v2, Ld3/a;->e:F

    .line 94
    .line 95
    :goto_0
    if-eq v0, v1, :cond_4

    .line 96
    .line 97
    const/4 p1, 0x0

    .line 98
    invoke-virtual {v0, v2, p2, p1}, Lv3/f1;->w1(Ld3/a;ZZ)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v2}, Ld3/a;->g()Z

    .line 102
    .line 103
    .line 104
    move-result p1

    .line 105
    if-eqz p1, :cond_3

    .line 106
    .line 107
    sget-object p0, Ld3/c;->e:Ld3/c;

    .line 108
    .line 109
    return-object p0

    .line 110
    :cond_3
    iget-object v0, v0, Lv3/f1;->t:Lv3/f1;

    .line 111
    .line 112
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_4
    invoke-virtual {p0, v1, v2, p2}, Lv3/f1;->U0(Lv3/f1;Ld3/a;Z)V

    .line 117
    .line 118
    .line 119
    new-instance p0, Ld3/c;

    .line 120
    .line 121
    iget p1, v2, Ld3/a;->b:F

    .line 122
    .line 123
    iget p2, v2, Ld3/a;->c:F

    .line 124
    .line 125
    iget v0, v2, Ld3/a;->d:F

    .line 126
    .line 127
    iget v1, v2, Ld3/a;->e:F

    .line 128
    .line 129
    invoke-direct {p0, p1, p2, v0, v1}, Ld3/c;-><init>(FFFF)V

    .line 130
    .line 131
    .line 132
    return-object p0
.end method

.method public final P0()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lv3/f1;->C:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final R(J)J
    .locals 1

    .line 1
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const-string v0, "LayoutCoordinate operations are only valid when isAttached is true"

    .line 10
    .line 11
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    invoke-virtual {p0}, Lv3/f1;->p1()V

    .line 15
    .line 16
    .line 17
    :goto_0
    if-eqz p0, :cond_1

    .line 18
    .line 19
    invoke-virtual {p0, p1, p2}, Lv3/f1;->A1(J)J

    .line 20
    .line 21
    .line 22
    move-result-wide p1

    .line 23
    iget-object p0, p0, Lv3/f1;->t:Lv3/f1;

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    return-wide p1
.end method

.method public final T0()V
    .locals 4

    .line 1
    iget-object v0, p0, Lv3/f1;->M:Lh3/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-wide v1, p0, Lv3/f1;->C:J

    .line 6
    .line 7
    iget v3, p0, Lv3/f1;->D:F

    .line 8
    .line 9
    invoke-virtual {p0, v1, v2, v3, v0}, Lv3/f1;->m0(JFLh3/c;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    iget-wide v0, p0, Lv3/f1;->C:J

    .line 14
    .line 15
    iget v2, p0, Lv3/f1;->D:F

    .line 16
    .line 17
    iget-object v3, p0, Lv3/f1;->w:Lay0/k;

    .line 18
    .line 19
    invoke-virtual {p0, v0, v1, v2, v3}, Lt3/e1;->l0(JFLay0/k;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final U0(Lv3/f1;Ld3/a;Z)V
    .locals 4

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    iget-object v0, p0, Lv3/f1;->t:Lv3/f1;

    .line 5
    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    invoke-virtual {v0, p1, p2, p3}, Lv3/f1;->U0(Lv3/f1;Ld3/a;Z)V

    .line 9
    .line 10
    .line 11
    :cond_1
    iget-wide v0, p0, Lv3/f1;->C:J

    .line 12
    .line 13
    const/16 p1, 0x20

    .line 14
    .line 15
    shr-long v2, v0, p1

    .line 16
    .line 17
    long-to-int v2, v2

    .line 18
    iget v3, p2, Ld3/a;->b:F

    .line 19
    .line 20
    int-to-float v2, v2

    .line 21
    sub-float/2addr v3, v2

    .line 22
    iput v3, p2, Ld3/a;->b:F

    .line 23
    .line 24
    iget v3, p2, Ld3/a;->d:F

    .line 25
    .line 26
    sub-float/2addr v3, v2

    .line 27
    iput v3, p2, Ld3/a;->d:F

    .line 28
    .line 29
    const-wide v2, 0xffffffffL

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    and-long/2addr v0, v2

    .line 35
    long-to-int v0, v0

    .line 36
    iget v1, p2, Ld3/a;->c:F

    .line 37
    .line 38
    int-to-float v0, v0

    .line 39
    sub-float/2addr v1, v0

    .line 40
    iput v1, p2, Ld3/a;->c:F

    .line 41
    .line 42
    iget v1, p2, Ld3/a;->e:F

    .line 43
    .line 44
    sub-float/2addr v1, v0

    .line 45
    iput v1, p2, Ld3/a;->e:F

    .line 46
    .line 47
    iget-object v0, p0, Lv3/f1;->L:Lv3/n1;

    .line 48
    .line 49
    if-eqz v0, :cond_2

    .line 50
    .line 51
    const/4 v1, 0x1

    .line 52
    check-cast v0, Lw3/o1;

    .line 53
    .line 54
    invoke-virtual {v0, p2, v1}, Lw3/o1;->c(Ld3/a;Z)V

    .line 55
    .line 56
    .line 57
    iget-boolean v0, p0, Lv3/f1;->v:Z

    .line 58
    .line 59
    if-eqz v0, :cond_2

    .line 60
    .line 61
    if-eqz p3, :cond_2

    .line 62
    .line 63
    iget-wide v0, p0, Lt3/e1;->f:J

    .line 64
    .line 65
    shr-long p0, v0, p1

    .line 66
    .line 67
    long-to-int p0, p0

    .line 68
    int-to-float p0, p0

    .line 69
    and-long/2addr v0, v2

    .line 70
    long-to-int p1, v0

    .line 71
    int-to-float p1, p1

    .line 72
    const/4 p3, 0x0

    .line 73
    invoke-virtual {p2, p3, p3, p0, p1}, Ld3/a;->f(FFFF)V

    .line 74
    .line 75
    .line 76
    :cond_2
    :goto_0
    return-void
.end method

.method public final V0(Lv3/f1;J)J
    .locals 2

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    return-wide p2

    .line 4
    :cond_0
    iget-object v0, p0, Lv3/f1;->t:Lv3/f1;

    .line 5
    .line 6
    if-eqz v0, :cond_2

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    invoke-virtual {v0, p1, p2, p3}, Lv3/f1;->V0(Lv3/f1;J)J

    .line 16
    .line 17
    .line 18
    move-result-wide p1

    .line 19
    invoke-virtual {p0, p1, p2}, Lv3/f1;->c1(J)J

    .line 20
    .line 21
    .line 22
    move-result-wide p0

    .line 23
    return-wide p0

    .line 24
    :cond_2
    :goto_0
    invoke-virtual {p0, p2, p3}, Lv3/f1;->c1(J)J

    .line 25
    .line 26
    .line 27
    move-result-wide p0

    .line 28
    return-wide p0
.end method

.method public final W0(J)J
    .locals 6

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    shr-long v1, p1, v0

    .line 4
    .line 5
    long-to-int v1, v1

    .line 6
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    invoke-virtual {p0}, Lt3/e1;->d0()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    int-to-float v2, v2

    .line 15
    sub-float/2addr v1, v2

    .line 16
    const-wide v2, 0xffffffffL

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    and-long/2addr p1, v2

    .line 22
    long-to-int p1, p1

    .line 23
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    invoke-virtual {p0}, Lt3/e1;->b0()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    int-to-float p0, p0

    .line 32
    sub-float/2addr p1, p0

    .line 33
    const/high16 p0, 0x40000000    # 2.0f

    .line 34
    .line 35
    div-float/2addr v1, p0

    .line 36
    const/4 p2, 0x0

    .line 37
    invoke-static {p2, v1}, Ljava/lang/Math;->max(FF)F

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    div-float/2addr p1, p0

    .line 42
    invoke-static {p2, p1}, Ljava/lang/Math;->max(FF)F

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    int-to-long p1, p1

    .line 51
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    int-to-long v4, p0

    .line 56
    shl-long p0, p1, v0

    .line 57
    .line 58
    and-long v0, v4, v2

    .line 59
    .line 60
    or-long/2addr p0, v0

    .line 61
    return-wide p0
.end method

.method public final X0(JJ)F
    .locals 8

    .line 1
    invoke-virtual {p0}, Lt3/e1;->d0()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    int-to-float v0, v0

    .line 6
    const/16 v1, 0x20

    .line 7
    .line 8
    shr-long v2, p3, v1

    .line 9
    .line 10
    long-to-int v2, v2

    .line 11
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    cmpl-float v0, v0, v2

    .line 16
    .line 17
    const/high16 v2, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 18
    .line 19
    const-wide v3, 0xffffffffL

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    if-ltz v0, :cond_0

    .line 25
    .line 26
    invoke-virtual {p0}, Lt3/e1;->b0()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    int-to-float v0, v0

    .line 31
    and-long v5, p3, v3

    .line 32
    .line 33
    long-to-int v5, v5

    .line 34
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    cmpl-float v0, v0, v5

    .line 39
    .line 40
    if-ltz v0, :cond_0

    .line 41
    .line 42
    return v2

    .line 43
    :cond_0
    invoke-virtual {p0, p3, p4}, Lv3/f1;->W0(J)J

    .line 44
    .line 45
    .line 46
    move-result-wide p3

    .line 47
    shr-long v5, p3, v1

    .line 48
    .line 49
    long-to-int v0, v5

    .line 50
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    and-long/2addr p3, v3

    .line 55
    long-to-int p3, p3

    .line 56
    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 57
    .line 58
    .line 59
    move-result p3

    .line 60
    shr-long v5, p1, v1

    .line 61
    .line 62
    long-to-int p4, v5

    .line 63
    invoke-static {p4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 64
    .line 65
    .line 66
    move-result p4

    .line 67
    const/4 v5, 0x0

    .line 68
    cmpg-float v6, p4, v5

    .line 69
    .line 70
    if-gez v6, :cond_1

    .line 71
    .line 72
    neg-float p4, p4

    .line 73
    goto :goto_0

    .line 74
    :cond_1
    invoke-virtual {p0}, Lt3/e1;->d0()I

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    int-to-float v6, v6

    .line 79
    sub-float/2addr p4, v6

    .line 80
    :goto_0
    invoke-static {v5, p4}, Ljava/lang/Math;->max(FF)F

    .line 81
    .line 82
    .line 83
    move-result p4

    .line 84
    and-long/2addr p1, v3

    .line 85
    long-to-int p1, p1

    .line 86
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 87
    .line 88
    .line 89
    move-result p1

    .line 90
    cmpg-float p2, p1, v5

    .line 91
    .line 92
    if-gez p2, :cond_2

    .line 93
    .line 94
    neg-float p0, p1

    .line 95
    goto :goto_1

    .line 96
    :cond_2
    invoke-virtual {p0}, Lt3/e1;->b0()I

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    int-to-float p0, p0

    .line 101
    sub-float p0, p1, p0

    .line 102
    .line 103
    :goto_1
    invoke-static {v5, p0}, Ljava/lang/Math;->max(FF)F

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    invoke-static {p4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 108
    .line 109
    .line 110
    move-result p1

    .line 111
    int-to-long p1, p1

    .line 112
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    int-to-long v6, p0

    .line 117
    shl-long p0, p1, v1

    .line 118
    .line 119
    and-long/2addr v6, v3

    .line 120
    or-long/2addr p0, v6

    .line 121
    cmpl-float p2, v0, v5

    .line 122
    .line 123
    if-gtz p2, :cond_3

    .line 124
    .line 125
    cmpl-float p2, p3, v5

    .line 126
    .line 127
    if-lez p2, :cond_4

    .line 128
    .line 129
    :cond_3
    shr-long v5, p0, v1

    .line 130
    .line 131
    long-to-int p2, v5

    .line 132
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 133
    .line 134
    .line 135
    move-result p4

    .line 136
    cmpg-float p4, p4, v0

    .line 137
    .line 138
    if-gtz p4, :cond_4

    .line 139
    .line 140
    and-long/2addr p0, v3

    .line 141
    long-to-int p0, p0

    .line 142
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 143
    .line 144
    .line 145
    move-result p1

    .line 146
    cmpg-float p1, p1, p3

    .line 147
    .line 148
    if-gtz p1, :cond_4

    .line 149
    .line 150
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 151
    .line 152
    .line 153
    move-result p1

    .line 154
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 155
    .line 156
    .line 157
    move-result p0

    .line 158
    mul-float/2addr p1, p1

    .line 159
    mul-float/2addr p0, p0

    .line 160
    add-float/2addr p0, p1

    .line 161
    return p0

    .line 162
    :cond_4
    return v2
.end method

.method public final Y0(Le3/r;Lh3/c;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lv3/f1;->L:Lv3/n1;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    check-cast v0, Lw3/o1;

    .line 6
    .line 7
    iget-object p0, v0, Lw3/o1;->p:Lg3/b;

    .line 8
    .line 9
    invoke-virtual {v0}, Lw3/o1;->g()V

    .line 10
    .line 11
    .line 12
    iget-object v1, v0, Lw3/o1;->d:Lh3/c;

    .line 13
    .line 14
    iget-object v1, v1, Lh3/c;->a:Lh3/d;

    .line 15
    .line 16
    iget v1, v1, Lh3/d;->n:F

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    cmpl-float v1, v1, v2

    .line 20
    .line 21
    if-lez v1, :cond_0

    .line 22
    .line 23
    const/4 v1, 0x1

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v1, 0x0

    .line 26
    :goto_0
    iput-boolean v1, v0, Lw3/o1;->w:Z

    .line 27
    .line 28
    iget-object v1, p0, Lg3/b;->e:Lgw0/c;

    .line 29
    .line 30
    invoke-virtual {v1, p1}, Lgw0/c;->x(Le3/r;)V

    .line 31
    .line 32
    .line 33
    iput-object p2, v1, Lgw0/c;->f:Ljava/lang/Object;

    .line 34
    .line 35
    iget-object p1, v0, Lw3/o1;->d:Lh3/c;

    .line 36
    .line 37
    invoke-virtual {p0}, Lg3/b;->x0()Lgw0/c;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    invoke-virtual {p2}, Lgw0/c;->h()Le3/r;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    invoke-virtual {p0}, Lg3/b;->x0()Lgw0/c;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p0, Lh3/c;

    .line 52
    .line 53
    invoke-virtual {p1, p2, p0}, Lh3/c;->c(Le3/r;Lh3/c;)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_1
    iget-wide v0, p0, Lv3/f1;->C:J

    .line 58
    .line 59
    const/16 v2, 0x20

    .line 60
    .line 61
    shr-long v2, v0, v2

    .line 62
    .line 63
    long-to-int v2, v2

    .line 64
    int-to-float v2, v2

    .line 65
    const-wide v3, 0xffffffffL

    .line 66
    .line 67
    .line 68
    .line 69
    .line 70
    and-long/2addr v0, v3

    .line 71
    long-to-int v0, v0

    .line 72
    int-to-float v0, v0

    .line 73
    invoke-interface {p1, v2, v0}, Le3/r;->h(FF)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0, p1, p2}, Lv3/f1;->Z0(Le3/r;Lh3/c;)V

    .line 77
    .line 78
    .line 79
    neg-float p0, v2

    .line 80
    neg-float p2, v0

    .line 81
    invoke-interface {p1, p0, p2}, Le3/r;->h(FF)V

    .line 82
    .line 83
    .line 84
    return-void
.end method

.method public final Z(Lt3/y;J)J
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2, p3}, Lv3/f1;->o1(Lt3/y;J)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public final Z0(Le3/r;Lh3/c;)V
    .locals 11

    .line 1
    const/4 v0, 0x4

    .line 2
    invoke-virtual {p0, v0}, Lv3/f1;->g1(I)Lx2/r;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2}, Lv3/f1;->u1(Le3/r;Lh3/c;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    iget-object v2, p0, Lv3/f1;->r:Lv3/h0;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    invoke-static {v2}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Lw3/t;

    .line 22
    .line 23
    invoke-virtual {v2}, Lw3/t;->getSharedDrawScope()Lv3/j0;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    iget-wide v4, p0, Lt3/e1;->f:J

    .line 28
    .line 29
    invoke-static {v4, v5}, Lkp/f9;->c(J)J

    .line 30
    .line 31
    .line 32
    move-result-wide v5

    .line 33
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    const/4 v2, 0x0

    .line 37
    move-object v10, v2

    .line 38
    :goto_0
    if-eqz v1, :cond_8

    .line 39
    .line 40
    instance-of v4, v1, Lv3/p;

    .line 41
    .line 42
    if-eqz v4, :cond_1

    .line 43
    .line 44
    move-object v8, v1

    .line 45
    check-cast v8, Lv3/p;

    .line 46
    .line 47
    move-object v7, p0

    .line 48
    move-object v4, p1

    .line 49
    move-object v9, p2

    .line 50
    invoke-virtual/range {v3 .. v9}, Lv3/j0;->c(Le3/r;JLv3/f1;Lv3/p;Lh3/c;)V

    .line 51
    .line 52
    .line 53
    goto :goto_4

    .line 54
    :cond_1
    move-object v7, p0

    .line 55
    move-object v4, p1

    .line 56
    move-object v9, p2

    .line 57
    iget p0, v1, Lx2/r;->f:I

    .line 58
    .line 59
    and-int/2addr p0, v0

    .line 60
    if-eqz p0, :cond_7

    .line 61
    .line 62
    instance-of p0, v1, Lv3/n;

    .line 63
    .line 64
    if-eqz p0, :cond_7

    .line 65
    .line 66
    move-object p0, v1

    .line 67
    check-cast p0, Lv3/n;

    .line 68
    .line 69
    iget-object p0, p0, Lv3/n;->s:Lx2/r;

    .line 70
    .line 71
    const/4 p1, 0x0

    .line 72
    :goto_1
    const/4 p2, 0x1

    .line 73
    if-eqz p0, :cond_6

    .line 74
    .line 75
    iget v8, p0, Lx2/r;->f:I

    .line 76
    .line 77
    and-int/2addr v8, v0

    .line 78
    if-eqz v8, :cond_5

    .line 79
    .line 80
    add-int/lit8 p1, p1, 0x1

    .line 81
    .line 82
    if-ne p1, p2, :cond_2

    .line 83
    .line 84
    move-object v1, p0

    .line 85
    goto :goto_2

    .line 86
    :cond_2
    if-nez v10, :cond_3

    .line 87
    .line 88
    new-instance v10, Ln2/b;

    .line 89
    .line 90
    const/16 p2, 0x10

    .line 91
    .line 92
    new-array p2, p2, [Lx2/r;

    .line 93
    .line 94
    invoke-direct {v10, p2}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    :cond_3
    if-eqz v1, :cond_4

    .line 98
    .line 99
    invoke-virtual {v10, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    move-object v1, v2

    .line 103
    :cond_4
    invoke-virtual {v10, p0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    :cond_5
    :goto_2
    iget-object p0, p0, Lx2/r;->i:Lx2/r;

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_6
    if-ne p1, p2, :cond_7

    .line 110
    .line 111
    :goto_3
    move-object p1, v4

    .line 112
    move-object p0, v7

    .line 113
    move-object p2, v9

    .line 114
    goto :goto_0

    .line 115
    :cond_7
    :goto_4
    invoke-static {v10}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 116
    .line 117
    .line 118
    move-result-object v1

    .line 119
    goto :goto_3

    .line 120
    :cond_8
    return-void
.end method

.method public final a()F
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/h0;->A:Lt4/c;

    .line 4
    .line 5
    invoke-interface {p0}, Lt4/c;->a()F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public abstract a1()V
.end method

.method public final b1(Lv3/f1;)Lv3/f1;
    .locals 5

    .line 1
    iget-object v0, p1, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    iget-object v1, p0, Lv3/f1;->r:Lv3/h0;

    .line 4
    .line 5
    if-ne v0, v1, :cond_2

    .line 6
    .line 7
    invoke-virtual {p1}, Lv3/f1;->f1()Lx2/r;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    iget-object v2, v1, Lx2/r;->d:Lx2/r;

    .line 16
    .line 17
    iget-boolean v2, v2, Lx2/r;->q:Z

    .line 18
    .line 19
    if-nez v2, :cond_0

    .line 20
    .line 21
    const-string v2, "visitLocalAncestors called on an unattached node"

    .line 22
    .line 23
    invoke-static {v2}, Ls3/a;->b(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    iget-object v1, v1, Lx2/r;->d:Lx2/r;

    .line 27
    .line 28
    iget-object v1, v1, Lx2/r;->h:Lx2/r;

    .line 29
    .line 30
    :goto_0
    if-eqz v1, :cond_7

    .line 31
    .line 32
    iget v2, v1, Lx2/r;->f:I

    .line 33
    .line 34
    and-int/lit8 v2, v2, 0x2

    .line 35
    .line 36
    if-eqz v2, :cond_1

    .line 37
    .line 38
    if-ne v1, v0, :cond_1

    .line 39
    .line 40
    goto :goto_4

    .line 41
    :cond_1
    iget-object v1, v1, Lx2/r;->h:Lx2/r;

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    :goto_1
    iget v2, v0, Lv3/h0;->r:I

    .line 45
    .line 46
    iget v3, v1, Lv3/h0;->r:I

    .line 47
    .line 48
    if-le v2, v3, :cond_3

    .line 49
    .line 50
    invoke-virtual {v0}, Lv3/h0;->v()Lv3/h0;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    move-object v2, v1

    .line 59
    :goto_2
    iget v3, v2, Lv3/h0;->r:I

    .line 60
    .line 61
    iget v4, v0, Lv3/h0;->r:I

    .line 62
    .line 63
    if-le v3, v4, :cond_4

    .line 64
    .line 65
    invoke-virtual {v2}, Lv3/h0;->v()Lv3/h0;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    :goto_3
    if-eq v0, v2, :cond_6

    .line 74
    .line 75
    invoke-virtual {v0}, Lv3/h0;->v()Lv3/h0;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-virtual {v2}, Lv3/h0;->v()Lv3/h0;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    if-eqz v0, :cond_5

    .line 84
    .line 85
    if-eqz v2, :cond_5

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 89
    .line 90
    const-string p1, "layouts are not part of the same hierarchy"

    .line 91
    .line 92
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw p0

    .line 96
    :cond_6
    if-ne v2, v1, :cond_8

    .line 97
    .line 98
    :cond_7
    return-object p0

    .line 99
    :cond_8
    iget-object p0, p1, Lv3/f1;->r:Lv3/h0;

    .line 100
    .line 101
    if-ne v0, p0, :cond_9

    .line 102
    .line 103
    :goto_4
    return-object p1

    .line 104
    :cond_9
    iget-object p0, v0, Lv3/h0;->H:Lg1/q;

    .line 105
    .line 106
    iget-object p0, p0, Lg1/q;->d:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast p0, Lv3/u;

    .line 109
    .line 110
    return-object p0
.end method

.method public final c1(J)J
    .locals 6

    .line 1
    iget-wide v0, p0, Lv3/f1;->C:J

    .line 2
    .line 3
    const/16 v2, 0x20

    .line 4
    .line 5
    shr-long v3, p1, v2

    .line 6
    .line 7
    long-to-int v3, v3

    .line 8
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    shr-long v4, v0, v2

    .line 13
    .line 14
    long-to-int v4, v4

    .line 15
    int-to-float v4, v4

    .line 16
    sub-float/2addr v3, v4

    .line 17
    const-wide v4, 0xffffffffL

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    and-long/2addr p1, v4

    .line 23
    long-to-int p1, p1

    .line 24
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    and-long/2addr v0, v4

    .line 29
    long-to-int p2, v0

    .line 30
    int-to-float p2, p2

    .line 31
    sub-float/2addr p1, p2

    .line 32
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 33
    .line 34
    .line 35
    move-result p2

    .line 36
    int-to-long v0, p2

    .line 37
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    int-to-long p1, p1

    .line 42
    shl-long/2addr v0, v2

    .line 43
    and-long/2addr p1, v4

    .line 44
    or-long/2addr p1, v0

    .line 45
    iget-object p0, p0, Lv3/f1;->L:Lv3/n1;

    .line 46
    .line 47
    if-eqz p0, :cond_0

    .line 48
    .line 49
    const/4 v0, 0x1

    .line 50
    check-cast p0, Lw3/o1;

    .line 51
    .line 52
    invoke-virtual {p0, p1, p2, v0}, Lw3/o1;->d(JZ)J

    .line 53
    .line 54
    .line 55
    move-result-wide p0

    .line 56
    return-wide p0

    .line 57
    :cond_0
    return-wide p1
.end method

.method public final d(Lt3/y;[F)V
    .locals 1

    .line 1
    invoke-static {p1}, Lv3/f1;->z1(Lt3/y;)Lv3/f1;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p1}, Lv3/f1;->p1()V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lv3/f1;->b1(Lv3/f1;)Lv3/f1;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-static {p2}, Le3/c0;->d([F)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1, v0, p2}, Lv3/f1;->D1(Lv3/f1;[F)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v0, p2}, Lv3/f1;->C1(Lv3/f1;[F)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public abstract d1()Lv3/q0;
.end method

.method public final e0()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/f1;->L:Lv3/n1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean v0, p0, Lv3/f1;->u:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 10
    .line 11
    invoke-virtual {p0}, Lv3/h0;->I()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final e1()J
    .locals 3

    .line 1
    iget-object v0, p0, Lv3/f1;->x:Lt4/c;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 4
    .line 5
    iget-object p0, p0, Lv3/h0;->C:Lw3/h2;

    .line 6
    .line 7
    invoke-interface {p0}, Lw3/h2;->d()J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    invoke-interface {v0, v1, v2}, Lt4/c;->G0(J)J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    return-wide v0
.end method

.method public abstract f1()Lx2/r;
.end method

.method public final g()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-boolean p0, p0, Lx2/r;->q:Z

    .line 6
    .line 7
    return p0
.end method

.method public final g1(I)Lx2/r;
    .locals 2

    .line 1
    invoke-static {p1}, Lv3/g1;->g(I)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object v1, v1, Lx2/r;->h:Lx2/r;

    .line 13
    .line 14
    if-nez v1, :cond_1

    .line 15
    .line 16
    goto :goto_2

    .line 17
    :cond_1
    :goto_0
    invoke-virtual {p0, v0}, Lv3/f1;->h1(Z)Lx2/r;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    :goto_1
    if-eqz p0, :cond_3

    .line 22
    .line 23
    iget v0, p0, Lx2/r;->g:I

    .line 24
    .line 25
    and-int/2addr v0, p1

    .line 26
    if-eqz v0, :cond_3

    .line 27
    .line 28
    iget v0, p0, Lx2/r;->f:I

    .line 29
    .line 30
    and-int/2addr v0, p1

    .line 31
    if-eqz v0, :cond_2

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_2
    if-eq p0, v1, :cond_3

    .line 35
    .line 36
    iget-object p0, p0, Lx2/r;->i:Lx2/r;

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_3
    :goto_2
    const/4 p0, 0x0

    .line 40
    return-object p0
.end method

.method public final getLayoutDirection()Lt4/m;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/h0;->B:Lt4/m;

    .line 4
    .line 5
    return-object p0
.end method

.method public final h()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lt3/e1;->f:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final h1(Z)Lx2/r;
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    iget-object v0, v0, Lv3/h0;->H:Lg1/q;

    .line 4
    .line 5
    iget-object v1, v0, Lg1/q;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lv3/f1;

    .line 8
    .line 9
    if-ne v1, p0, :cond_0

    .line 10
    .line 11
    iget-object p0, v0, Lg1/q;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lx2/r;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    const/4 v0, 0x0

    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    iget-object p0, p0, Lv3/f1;->t:Lv3/f1;

    .line 20
    .line 21
    if-eqz p0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    if-eqz p0, :cond_1

    .line 28
    .line 29
    iget-object p0, p0, Lx2/r;->i:Lx2/r;

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_1
    return-object v0

    .line 33
    :cond_2
    iget-object p0, p0, Lv3/f1;->t:Lv3/f1;

    .line 34
    .line 35
    if-eqz p0, :cond_3

    .line 36
    .line 37
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    :cond_3
    return-object v0
.end method

.method public final i(J)J
    .locals 3

    .line 1
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const-string v0, "LayoutCoordinate operations are only valid when isAttached is true"

    .line 10
    .line 11
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    invoke-static {p0}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-object v1, p0, Lv3/f1;->r:Lv3/h0;

    .line 19
    .line 20
    invoke-static {v1}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    check-cast v1, Lw3/t;

    .line 25
    .line 26
    invoke-virtual {v1}, Lw3/t;->z()V

    .line 27
    .line 28
    .line 29
    iget-object v1, v1, Lw3/t;->W:[F

    .line 30
    .line 31
    invoke-static {p1, p2, v1}, Le3/c0;->b(J[F)J

    .line 32
    .line 33
    .line 34
    move-result-wide p1

    .line 35
    const-wide/16 v1, 0x0

    .line 36
    .line 37
    invoke-interface {v0, v1, v2}, Lt3/y;->R(J)J

    .line 38
    .line 39
    .line 40
    move-result-wide v1

    .line 41
    invoke-static {p1, p2, v1, v2}, Ld3/b;->g(JJ)J

    .line 42
    .line 43
    .line 44
    move-result-wide p1

    .line 45
    invoke-virtual {p0, v0, p1, p2}, Lv3/f1;->o1(Lt3/y;J)J

    .line 46
    .line 47
    .line 48
    move-result-wide p0

    .line 49
    return-wide p0
.end method

.method public final i1(Lx2/r;Lv3/d;JLv3/s;IZ)V
    .locals 7

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    move-object v1, p2

    .line 5
    move-wide v2, p3

    .line 6
    move-object v4, p5

    .line 7
    move v5, p6

    .line 8
    move v6, p7

    .line 9
    invoke-virtual/range {v0 .. v6}, Lv3/f1;->l1(Lv3/d;JLv3/s;IZ)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    iget v0, p5, Lv3/s;->f:I

    .line 14
    .line 15
    iget-object v1, p5, Lv3/s;->d:Landroidx/collection/l0;

    .line 16
    .line 17
    add-int/lit8 v2, v0, 0x1

    .line 18
    .line 19
    iget v3, v1, Landroidx/collection/l0;->b:I

    .line 20
    .line 21
    invoke-virtual {p5, v2, v3}, Lv3/s;->e(II)V

    .line 22
    .line 23
    .line 24
    iget v2, p5, Lv3/s;->f:I

    .line 25
    .line 26
    add-int/lit8 v2, v2, 0x1

    .line 27
    .line 28
    iput v2, p5, Lv3/s;->f:I

    .line 29
    .line 30
    invoke-virtual {v1, p1}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iget-object v1, p5, Lv3/s;->e:Landroidx/collection/d0;

    .line 34
    .line 35
    const/high16 v2, -0x40800000    # -1.0f

    .line 36
    .line 37
    const/4 v3, 0x0

    .line 38
    invoke-static {v2, p7, v3}, Lv3/f;->a(FZZ)J

    .line 39
    .line 40
    .line 41
    move-result-wide v2

    .line 42
    invoke-virtual {v1, v2, v3}, Landroidx/collection/d0;->a(J)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p2}, Lv3/d;->c()I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    invoke-static {p1, v1}, Lv3/f;->e(Lv3/m;I)Lx2/r;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-virtual/range {p0 .. p7}, Lv3/f1;->i1(Lx2/r;Lv3/d;JLv3/s;IZ)V

    .line 54
    .line 55
    .line 56
    iput v0, p5, Lv3/s;->f:I

    .line 57
    .line 58
    return-void
.end method

.method public final j1(Lx2/r;Lv3/d;JLv3/s;IZF)V
    .locals 11

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    move-object v1, p2

    .line 5
    move-wide v2, p3

    .line 6
    move-object/from16 v4, p5

    .line 7
    .line 8
    move/from16 v5, p6

    .line 9
    .line 10
    move/from16 v6, p7

    .line 11
    .line 12
    invoke-virtual/range {v0 .. v6}, Lv3/f1;->l1(Lv3/d;JLv3/s;IZ)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    move-object/from16 v4, p5

    .line 17
    .line 18
    iget v10, v4, Lv3/s;->f:I

    .line 19
    .line 20
    iget-object v0, v4, Lv3/s;->d:Landroidx/collection/l0;

    .line 21
    .line 22
    add-int/lit8 v1, v10, 0x1

    .line 23
    .line 24
    iget v2, v0, Landroidx/collection/l0;->b:I

    .line 25
    .line 26
    invoke-virtual {v4, v1, v2}, Lv3/s;->e(II)V

    .line 27
    .line 28
    .line 29
    iget v1, v4, Lv3/s;->f:I

    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    iput v1, v4, Lv3/s;->f:I

    .line 34
    .line 35
    invoke-virtual {v0, p1}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object v0, v4, Lv3/s;->e:Landroidx/collection/d0;

    .line 39
    .line 40
    const/4 v1, 0x0

    .line 41
    move/from16 v7, p7

    .line 42
    .line 43
    move/from16 v8, p8

    .line 44
    .line 45
    invoke-static {v8, v7, v1}, Lv3/f;->a(FZZ)J

    .line 46
    .line 47
    .line 48
    move-result-wide v1

    .line 49
    invoke-virtual {v0, v1, v2}, Landroidx/collection/d0;->a(J)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p2}, Lv3/d;->c()I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    invoke-static {p1, v0}, Lv3/f;->e(Lv3/m;I)Lx2/r;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    const/4 v9, 0x1

    .line 61
    move-object v0, p0

    .line 62
    move-object v2, p2

    .line 63
    move/from16 v6, p6

    .line 64
    .line 65
    move-object v5, v4

    .line 66
    move-wide v3, p3

    .line 67
    invoke-virtual/range {v0 .. v9}, Lv3/f1;->t1(Lx2/r;Lv3/d;JLv3/s;IZFZ)V

    .line 68
    .line 69
    .line 70
    move-object v4, v5

    .line 71
    iput v10, v4, Lv3/s;->f:I

    .line 72
    .line 73
    return-void
.end method

.method public final k1(Lv3/d;JLv3/s;IZ)V
    .locals 14

    .line 1
    move-wide/from16 v3, p2

    .line 2
    .line 3
    move-object/from16 v5, p4

    .line 4
    .line 5
    move/from16 v6, p5

    .line 6
    .line 7
    invoke-virtual {p1}, Lv3/d;->c()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-virtual {p0, v0}, Lv3/f1;->g1(I)Lx2/r;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {p0, v3, v4}, Lv3/f1;->G1(J)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const/4 v8, 0x0

    .line 20
    const/high16 v9, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 21
    .line 22
    const v10, 0x7fffffff

    .line 23
    .line 24
    .line 25
    const/4 v11, 0x1

    .line 26
    if-nez v0, :cond_2

    .line 27
    .line 28
    if-ne v6, v11, :cond_1

    .line 29
    .line 30
    invoke-virtual {p0}, Lv3/f1;->e1()J

    .line 31
    .line 32
    .line 33
    move-result-wide v11

    .line 34
    invoke-virtual {p0, v3, v4, v11, v12}, Lv3/f1;->X0(JJ)F

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    and-int/2addr v2, v10

    .line 43
    if-ge v2, v9, :cond_1

    .line 44
    .line 45
    iget v2, v5, Lv3/s;->f:I

    .line 46
    .line 47
    invoke-static {v5}, Ljp/k1;->h(Ljava/util/List;)I

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    if-ne v2, v7, :cond_0

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    invoke-static {v0, v8, v8}, Lv3/f;->a(FZZ)J

    .line 55
    .line 56
    .line 57
    move-result-wide v7

    .line 58
    invoke-virtual {v5}, Lv3/s;->c()J

    .line 59
    .line 60
    .line 61
    move-result-wide v9

    .line 62
    invoke-static {v9, v10, v7, v8}, Lv3/f;->h(JJ)I

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-lez v2, :cond_1

    .line 67
    .line 68
    :goto_0
    const/4 v7, 0x0

    .line 69
    move-object v2, p1

    .line 70
    move v8, v0

    .line 71
    move-object v0, p0

    .line 72
    invoke-virtual/range {v0 .. v8}, Lv3/f1;->j1(Lx2/r;Lv3/d;JLv3/s;IZF)V

    .line 73
    .line 74
    .line 75
    :cond_1
    return-void

    .line 76
    :cond_2
    if-nez v1, :cond_3

    .line 77
    .line 78
    invoke-virtual/range {p0 .. p6}, Lv3/f1;->l1(Lv3/d;JLv3/s;IZ)V

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :cond_3
    const/16 v0, 0x20

    .line 83
    .line 84
    shr-long v2, p2, v0

    .line 85
    .line 86
    long-to-int v0, v2

    .line 87
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    const-wide v2, 0xffffffffL

    .line 92
    .line 93
    .line 94
    .line 95
    .line 96
    and-long v2, p2, v2

    .line 97
    .line 98
    long-to-int v2, v2

    .line 99
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 100
    .line 101
    .line 102
    move-result v2

    .line 103
    const/4 v3, 0x0

    .line 104
    cmpl-float v4, v0, v3

    .line 105
    .line 106
    if-ltz v4, :cond_4

    .line 107
    .line 108
    cmpl-float v3, v2, v3

    .line 109
    .line 110
    if-ltz v3, :cond_4

    .line 111
    .line 112
    invoke-virtual {p0}, Lt3/e1;->d0()I

    .line 113
    .line 114
    .line 115
    move-result v3

    .line 116
    int-to-float v3, v3

    .line 117
    cmpg-float v0, v0, v3

    .line 118
    .line 119
    if-gez v0, :cond_4

    .line 120
    .line 121
    invoke-virtual {p0}, Lt3/e1;->b0()I

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    int-to-float v0, v0

    .line 126
    cmpg-float v0, v2, v0

    .line 127
    .line 128
    if-gez v0, :cond_4

    .line 129
    .line 130
    move-object v0, p0

    .line 131
    move-object v2, p1

    .line 132
    move-wide/from16 v3, p2

    .line 133
    .line 134
    move-object/from16 v5, p4

    .line 135
    .line 136
    move/from16 v6, p5

    .line 137
    .line 138
    move/from16 v7, p6

    .line 139
    .line 140
    invoke-virtual/range {v0 .. v7}, Lv3/f1;->i1(Lx2/r;Lv3/d;JLv3/s;IZ)V

    .line 141
    .line 142
    .line 143
    return-void

    .line 144
    :cond_4
    move-wide/from16 v3, p2

    .line 145
    .line 146
    move-object/from16 v5, p4

    .line 147
    .line 148
    move/from16 v6, p5

    .line 149
    .line 150
    if-ne v6, v11, :cond_5

    .line 151
    .line 152
    invoke-virtual {p0}, Lv3/f1;->e1()J

    .line 153
    .line 154
    .line 155
    move-result-wide v12

    .line 156
    invoke-virtual {p0, v3, v4, v12, v13}, Lv3/f1;->X0(JJ)F

    .line 157
    .line 158
    .line 159
    move-result v2

    .line 160
    goto :goto_1

    .line 161
    :cond_5
    const/high16 v2, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 162
    .line 163
    :goto_1
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 164
    .line 165
    .line 166
    move-result v7

    .line 167
    and-int/2addr v7, v10

    .line 168
    if-ge v7, v9, :cond_7

    .line 169
    .line 170
    iget v7, v5, Lv3/s;->f:I

    .line 171
    .line 172
    invoke-static {v5}, Ljp/k1;->h(Ljava/util/List;)I

    .line 173
    .line 174
    .line 175
    move-result v9

    .line 176
    if-ne v7, v9, :cond_6

    .line 177
    .line 178
    move/from16 v7, p6

    .line 179
    .line 180
    goto :goto_2

    .line 181
    :cond_6
    move/from16 v7, p6

    .line 182
    .line 183
    invoke-static {v2, v7, v8}, Lv3/f;->a(FZZ)J

    .line 184
    .line 185
    .line 186
    move-result-wide v9

    .line 187
    invoke-virtual {v5}, Lv3/s;->c()J

    .line 188
    .line 189
    .line 190
    move-result-wide v12

    .line 191
    invoke-static {v12, v13, v9, v10}, Lv3/f;->h(JJ)I

    .line 192
    .line 193
    .line 194
    move-result v9

    .line 195
    if-lez v9, :cond_8

    .line 196
    .line 197
    :goto_2
    move v9, v11

    .line 198
    :goto_3
    move-object v0, p0

    .line 199
    move v8, v2

    .line 200
    move-object v2, p1

    .line 201
    goto :goto_4

    .line 202
    :cond_7
    move/from16 v7, p6

    .line 203
    .line 204
    :cond_8
    move v9, v8

    .line 205
    goto :goto_3

    .line 206
    :goto_4
    invoke-virtual/range {v0 .. v9}, Lv3/f1;->t1(Lx2/r;Lv3/d;JLv3/s;IZFZ)V

    .line 207
    .line 208
    .line 209
    return-void
.end method

.method public final l()Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/h0;->H:Lg1/q;

    .line 4
    .line 5
    const/16 v2, 0x40

    .line 6
    .line 7
    invoke-virtual {v1, v2}, Lg1/q;->i(I)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/4 v3, 0x0

    .line 12
    if-eqz v1, :cond_9

    .line 13
    .line 14
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 15
    .line 16
    .line 17
    iget-object p0, v0, Lv3/h0;->H:Lg1/q;

    .line 18
    .line 19
    iget-object p0, p0, Lg1/q;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Lv3/z1;

    .line 22
    .line 23
    move-object v1, v3

    .line 24
    :goto_0
    if-eqz p0, :cond_8

    .line 25
    .line 26
    iget v4, p0, Lx2/r;->f:I

    .line 27
    .line 28
    and-int/2addr v4, v2

    .line 29
    if-eqz v4, :cond_7

    .line 30
    .line 31
    move-object v4, p0

    .line 32
    move-object v5, v3

    .line 33
    :goto_1
    if-eqz v4, :cond_7

    .line 34
    .line 35
    instance-of v6, v4, Lv3/r1;

    .line 36
    .line 37
    if-eqz v6, :cond_0

    .line 38
    .line 39
    check-cast v4, Lv3/r1;

    .line 40
    .line 41
    iget-object v6, v0, Lv3/h0;->A:Lt4/c;

    .line 42
    .line 43
    invoke-interface {v4, v6, v1}, Lv3/r1;->l(Lt4/c;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    goto :goto_4

    .line 48
    :cond_0
    iget v6, v4, Lx2/r;->f:I

    .line 49
    .line 50
    and-int/2addr v6, v2

    .line 51
    if-eqz v6, :cond_6

    .line 52
    .line 53
    instance-of v6, v4, Lv3/n;

    .line 54
    .line 55
    if-eqz v6, :cond_6

    .line 56
    .line 57
    move-object v6, v4

    .line 58
    check-cast v6, Lv3/n;

    .line 59
    .line 60
    iget-object v6, v6, Lv3/n;->s:Lx2/r;

    .line 61
    .line 62
    const/4 v7, 0x0

    .line 63
    :goto_2
    const/4 v8, 0x1

    .line 64
    if-eqz v6, :cond_5

    .line 65
    .line 66
    iget v9, v6, Lx2/r;->f:I

    .line 67
    .line 68
    and-int/2addr v9, v2

    .line 69
    if-eqz v9, :cond_4

    .line 70
    .line 71
    add-int/lit8 v7, v7, 0x1

    .line 72
    .line 73
    if-ne v7, v8, :cond_1

    .line 74
    .line 75
    move-object v4, v6

    .line 76
    goto :goto_3

    .line 77
    :cond_1
    if-nez v5, :cond_2

    .line 78
    .line 79
    new-instance v5, Ln2/b;

    .line 80
    .line 81
    const/16 v8, 0x10

    .line 82
    .line 83
    new-array v8, v8, [Lx2/r;

    .line 84
    .line 85
    invoke-direct {v5, v8}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :cond_2
    if-eqz v4, :cond_3

    .line 89
    .line 90
    invoke-virtual {v5, v4}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    move-object v4, v3

    .line 94
    :cond_3
    invoke-virtual {v5, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    :cond_4
    :goto_3
    iget-object v6, v6, Lx2/r;->i:Lx2/r;

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_5
    if-ne v7, v8, :cond_6

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_6
    :goto_4
    invoke-static {v5}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    goto :goto_1

    .line 108
    :cond_7
    iget-object p0, p0, Lx2/r;->h:Lx2/r;

    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_8
    return-object v1

    .line 112
    :cond_9
    return-object v3
.end method

.method public l1(Lv3/d;JLv3/s;IZ)V
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/f1;->s:Lv3/f1;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p2, p3}, Lv3/f1;->c1(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide p2

    .line 9
    invoke-virtual/range {p0 .. p6}, Lv3/f1;->k1(Lv3/d;JLv3/s;IZ)V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public abstract m0(JFLh3/c;)V
.end method

.method public final m1()V
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/f1;->L:Lv3/n1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Lv3/n1;->invalidate()V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iget-object p0, p0, Lv3/f1;->t:Lv3/f1;

    .line 10
    .line 11
    if-eqz p0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0}, Lv3/f1;->m1()V

    .line 14
    .line 15
    .line 16
    :cond_1
    return-void
.end method

.method public final n1()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/f1;->L:Lv3/n1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget v0, p0, Lv3/f1;->z:F

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    cmpg-float v0, v0, v1

    .line 9
    .line 10
    if-gtz v0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    return p0

    .line 14
    :cond_0
    iget-object p0, p0, Lv3/f1;->t:Lv3/f1;

    .line 15
    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0}, Lv3/f1;->n1()Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0

    .line 23
    :cond_1
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method public final o1(Lt3/y;J)J
    .locals 2

    .line 1
    instance-of v0, p1, Lt3/o0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lt3/o0;

    .line 6
    .line 7
    iget-object v0, p1, Lt3/o0;->d:Lv3/q0;

    .line 8
    .line 9
    iget-object v0, v0, Lv3/q0;->r:Lv3/f1;

    .line 10
    .line 11
    invoke-virtual {v0}, Lv3/f1;->p1()V

    .line 12
    .line 13
    .line 14
    const-wide v0, -0x7fffffff80000000L    # -1.0609978955E-314

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    xor-long/2addr p2, v0

    .line 20
    invoke-virtual {p1, p0, p2, p3}, Lt3/o0;->b(Lt3/y;J)J

    .line 21
    .line 22
    .line 23
    move-result-wide p0

    .line 24
    xor-long/2addr p0, v0

    .line 25
    return-wide p0

    .line 26
    :cond_0
    invoke-static {p1}, Lv3/f1;->z1(Lt3/y;)Lv3/f1;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-virtual {p1}, Lv3/f1;->p1()V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0, p1}, Lv3/f1;->b1(Lv3/f1;)Lv3/f1;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    :goto_0
    if-eq p1, v0, :cond_1

    .line 38
    .line 39
    invoke-virtual {p1, p2, p3}, Lv3/f1;->A1(J)J

    .line 40
    .line 41
    .line 42
    move-result-wide p2

    .line 43
    iget-object p1, p1, Lv3/f1;->t:Lv3/f1;

    .line 44
    .line 45
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    invoke-virtual {p0, v0, p2, p3}, Lv3/f1;->V0(Lv3/f1;J)J

    .line 50
    .line 51
    .line 52
    move-result-wide p0

    .line 53
    return-wide p0
.end method

.method public final p1()V
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 4
    .line 5
    invoke-virtual {p0}, Lv3/l0;->b()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final q1()V
    .locals 13

    .line 1
    const/16 v0, 0x80

    .line 2
    .line 3
    invoke-static {v0}, Lv3/g1;->g(I)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-virtual {p0, v1}, Lv3/f1;->h1(Z)Lx2/r;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    if-eqz v2, :cond_c

    .line 12
    .line 13
    iget-object v2, v2, Lx2/r;->d:Lx2/r;

    .line 14
    .line 15
    iget v2, v2, Lx2/r;->g:I

    .line 16
    .line 17
    and-int/2addr v2, v0

    .line 18
    if-eqz v2, :cond_c

    .line 19
    .line 20
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    const/4 v3, 0x0

    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    invoke-virtual {v2}, Lv2/f;->e()Lay0/k;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    move-object v4, v3

    .line 33
    :goto_0
    invoke-static {v2}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    :try_start_0
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    goto :goto_1

    .line 44
    :catchall_0
    move-exception p0

    .line 45
    goto/16 :goto_8

    .line 46
    .line 47
    :cond_1
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 48
    .line 49
    .line 50
    move-result-object v6

    .line 51
    iget-object v6, v6, Lx2/r;->h:Lx2/r;

    .line 52
    .line 53
    if-nez v6, :cond_2

    .line 54
    .line 55
    goto/16 :goto_7

    .line 56
    .line 57
    :cond_2
    :goto_1
    invoke-virtual {p0, v1}, Lv3/f1;->h1(Z)Lx2/r;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    :goto_2
    if-eqz v1, :cond_b

    .line 62
    .line 63
    iget v7, v1, Lx2/r;->g:I

    .line 64
    .line 65
    and-int/2addr v7, v0

    .line 66
    if-eqz v7, :cond_b

    .line 67
    .line 68
    iget v7, v1, Lx2/r;->f:I

    .line 69
    .line 70
    and-int/2addr v7, v0

    .line 71
    if-eqz v7, :cond_a

    .line 72
    .line 73
    move-object v7, v1

    .line 74
    move-object v8, v3

    .line 75
    :goto_3
    if-eqz v7, :cond_a

    .line 76
    .line 77
    instance-of v9, v7, Lv3/x;

    .line 78
    .line 79
    if-eqz v9, :cond_3

    .line 80
    .line 81
    check-cast v7, Lv3/x;

    .line 82
    .line 83
    iget-wide v9, p0, Lt3/e1;->f:J

    .line 84
    .line 85
    invoke-interface {v7, v9, v10}, Lv3/x;->h(J)V

    .line 86
    .line 87
    .line 88
    goto :goto_6

    .line 89
    :cond_3
    iget v9, v7, Lx2/r;->f:I

    .line 90
    .line 91
    and-int/2addr v9, v0

    .line 92
    if-eqz v9, :cond_9

    .line 93
    .line 94
    instance-of v9, v7, Lv3/n;

    .line 95
    .line 96
    if-eqz v9, :cond_9

    .line 97
    .line 98
    move-object v9, v7

    .line 99
    check-cast v9, Lv3/n;

    .line 100
    .line 101
    iget-object v9, v9, Lv3/n;->s:Lx2/r;

    .line 102
    .line 103
    const/4 v10, 0x0

    .line 104
    :goto_4
    const/4 v11, 0x1

    .line 105
    if-eqz v9, :cond_8

    .line 106
    .line 107
    iget v12, v9, Lx2/r;->f:I

    .line 108
    .line 109
    and-int/2addr v12, v0

    .line 110
    if-eqz v12, :cond_7

    .line 111
    .line 112
    add-int/lit8 v10, v10, 0x1

    .line 113
    .line 114
    if-ne v10, v11, :cond_4

    .line 115
    .line 116
    move-object v7, v9

    .line 117
    goto :goto_5

    .line 118
    :cond_4
    if-nez v8, :cond_5

    .line 119
    .line 120
    new-instance v8, Ln2/b;

    .line 121
    .line 122
    const/16 v11, 0x10

    .line 123
    .line 124
    new-array v11, v11, [Lx2/r;

    .line 125
    .line 126
    invoke-direct {v8, v11}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    :cond_5
    if-eqz v7, :cond_6

    .line 130
    .line 131
    invoke-virtual {v8, v7}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    move-object v7, v3

    .line 135
    :cond_6
    invoke-virtual {v8, v9}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    :cond_7
    :goto_5
    iget-object v9, v9, Lx2/r;->i:Lx2/r;

    .line 139
    .line 140
    goto :goto_4

    .line 141
    :cond_8
    if-ne v10, v11, :cond_9

    .line 142
    .line 143
    goto :goto_3

    .line 144
    :cond_9
    :goto_6
    invoke-static {v8}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 145
    .line 146
    .line 147
    move-result-object v7

    .line 148
    goto :goto_3

    .line 149
    :cond_a
    if-eq v1, v6, :cond_b

    .line 150
    .line 151
    iget-object v1, v1, Lx2/r;->i:Lx2/r;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 152
    .line 153
    goto :goto_2

    .line 154
    :cond_b
    :goto_7
    invoke-static {v2, v5, v4}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 155
    .line 156
    .line 157
    return-void

    .line 158
    :goto_8
    invoke-static {v2, v5, v4}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 159
    .line 160
    .line 161
    throw p0

    .line 162
    :cond_c
    return-void
.end method

.method public final r1()V
    .locals 10

    .line 1
    const/16 v0, 0x80

    .line 2
    .line 3
    invoke-static {v0}, Lv3/g1;->g(I)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-object v2, v2, Lx2/r;->h:Lx2/r;

    .line 15
    .line 16
    if-nez v2, :cond_1

    .line 17
    .line 18
    goto/16 :goto_6

    .line 19
    .line 20
    :cond_1
    :goto_0
    invoke-virtual {p0, v1}, Lv3/f1;->h1(Z)Lx2/r;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    :goto_1
    if-eqz v1, :cond_a

    .line 25
    .line 26
    iget v3, v1, Lx2/r;->g:I

    .line 27
    .line 28
    and-int/2addr v3, v0

    .line 29
    if-eqz v3, :cond_a

    .line 30
    .line 31
    iget v3, v1, Lx2/r;->f:I

    .line 32
    .line 33
    and-int/2addr v3, v0

    .line 34
    if-eqz v3, :cond_9

    .line 35
    .line 36
    const/4 v3, 0x0

    .line 37
    move-object v4, v1

    .line 38
    move-object v5, v3

    .line 39
    :goto_2
    if-eqz v4, :cond_9

    .line 40
    .line 41
    instance-of v6, v4, Lv3/x;

    .line 42
    .line 43
    if-eqz v6, :cond_2

    .line 44
    .line 45
    check-cast v4, Lv3/x;

    .line 46
    .line 47
    invoke-interface {v4, p0}, Lv3/x;->R(Lt3/y;)V

    .line 48
    .line 49
    .line 50
    goto :goto_5

    .line 51
    :cond_2
    iget v6, v4, Lx2/r;->f:I

    .line 52
    .line 53
    and-int/2addr v6, v0

    .line 54
    if-eqz v6, :cond_8

    .line 55
    .line 56
    instance-of v6, v4, Lv3/n;

    .line 57
    .line 58
    if-eqz v6, :cond_8

    .line 59
    .line 60
    move-object v6, v4

    .line 61
    check-cast v6, Lv3/n;

    .line 62
    .line 63
    iget-object v6, v6, Lv3/n;->s:Lx2/r;

    .line 64
    .line 65
    const/4 v7, 0x0

    .line 66
    :goto_3
    const/4 v8, 0x1

    .line 67
    if-eqz v6, :cond_7

    .line 68
    .line 69
    iget v9, v6, Lx2/r;->f:I

    .line 70
    .line 71
    and-int/2addr v9, v0

    .line 72
    if-eqz v9, :cond_6

    .line 73
    .line 74
    add-int/lit8 v7, v7, 0x1

    .line 75
    .line 76
    if-ne v7, v8, :cond_3

    .line 77
    .line 78
    move-object v4, v6

    .line 79
    goto :goto_4

    .line 80
    :cond_3
    if-nez v5, :cond_4

    .line 81
    .line 82
    new-instance v5, Ln2/b;

    .line 83
    .line 84
    const/16 v8, 0x10

    .line 85
    .line 86
    new-array v8, v8, [Lx2/r;

    .line 87
    .line 88
    invoke-direct {v5, v8}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    :cond_4
    if-eqz v4, :cond_5

    .line 92
    .line 93
    invoke-virtual {v5, v4}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    move-object v4, v3

    .line 97
    :cond_5
    invoke-virtual {v5, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    :cond_6
    :goto_4
    iget-object v6, v6, Lx2/r;->i:Lx2/r;

    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_7
    if-ne v7, v8, :cond_8

    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_8
    :goto_5
    invoke-static {v5}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 107
    .line 108
    .line 109
    move-result-object v4

    .line 110
    goto :goto_2

    .line 111
    :cond_9
    if-eq v1, v2, :cond_a

    .line 112
    .line 113
    iget-object v1, v1, Lx2/r;->i:Lx2/r;

    .line 114
    .line 115
    goto :goto_1

    .line 116
    :cond_a
    :goto_6
    return-void
.end method

.method public final s1()V
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lv3/f1;->u:Z

    .line 3
    .line 4
    iget-object v0, p0, Lv3/f1;->J:Lv3/c1;

    .line 5
    .line 6
    invoke-virtual {v0}, Lv3/c1;->invoke()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lv3/f1;->x1()V

    .line 10
    .line 11
    .line 12
    iget-wide v0, p0, Lv3/f1;->C:J

    .line 13
    .line 14
    const-wide/16 v2, 0x0

    .line 15
    .line 16
    invoke-static {v0, v1, v2, v3}, Lt4/j;->b(JJ)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 23
    .line 24
    invoke-virtual {p0}, Lv3/h0;->O()V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method public final t0()F
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/h0;->A:Lt4/c;

    .line 4
    .line 5
    invoke-interface {p0}, Lt4/c;->t0()F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final t1(Lx2/r;Lv3/d;JLv3/s;IZFZ)V
    .locals 17

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    move-object/from16 v0, p0

    .line 4
    .line 5
    move-object/from16 v1, p2

    .line 6
    .line 7
    move-wide/from16 v2, p3

    .line 8
    .line 9
    move-object/from16 v4, p5

    .line 10
    .line 11
    move/from16 v5, p6

    .line 12
    .line 13
    move/from16 v6, p7

    .line 14
    .line 15
    invoke-virtual/range {v0 .. v6}, Lv3/f1;->l1(Lv3/d;JLv3/s;IZ)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    move/from16 v6, p6

    .line 20
    .line 21
    const/16 v0, 0x10

    .line 22
    .line 23
    const/4 v1, 0x0

    .line 24
    const/4 v2, 0x0

    .line 25
    const/4 v11, 0x1

    .line 26
    const/4 v3, 0x3

    .line 27
    if-ne v6, v3, :cond_1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    const/4 v4, 0x4

    .line 31
    if-ne v6, v4, :cond_11

    .line 32
    .line 33
    :goto_0
    move-object/from16 v4, p1

    .line 34
    .line 35
    move-object v5, v2

    .line 36
    :goto_1
    if-eqz v4, :cond_11

    .line 37
    .line 38
    instance-of v7, v4, Lv3/t1;

    .line 39
    .line 40
    if-eqz v7, :cond_a

    .line 41
    .line 42
    check-cast v4, Lv3/t1;

    .line 43
    .line 44
    invoke-interface {v4}, Lv3/t1;->b0()J

    .line 45
    .line 46
    .line 47
    move-result-wide v4

    .line 48
    const/16 v7, 0x20

    .line 49
    .line 50
    shr-long v7, p3, v7

    .line 51
    .line 52
    long-to-int v7, v7

    .line 53
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 54
    .line 55
    .line 56
    move-result v8

    .line 57
    move-object/from16 v9, p0

    .line 58
    .line 59
    iget-object v10, v9, Lv3/f1;->r:Lv3/h0;

    .line 60
    .line 61
    iget-object v12, v10, Lv3/h0;->B:Lt4/m;

    .line 62
    .line 63
    sget v13, Lv3/a2;->b:I

    .line 64
    .line 65
    const-wide/high16 v13, -0x8000000000000000L

    .line 66
    .line 67
    and-long/2addr v13, v4

    .line 68
    const-wide/16 v15, 0x0

    .line 69
    .line 70
    cmp-long v13, v13, v15

    .line 71
    .line 72
    const/4 v14, 0x2

    .line 73
    if-eqz v13, :cond_3

    .line 74
    .line 75
    sget-object v15, Lt4/m;->d:Lt4/m;

    .line 76
    .line 77
    if-ne v12, v15, :cond_2

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_2
    invoke-static {v14, v4, v5}, Lv3/d;->a(IJ)I

    .line 81
    .line 82
    .line 83
    move-result v12

    .line 84
    goto :goto_3

    .line 85
    :cond_3
    :goto_2
    invoke-static {v1, v4, v5}, Lv3/d;->a(IJ)I

    .line 86
    .line 87
    .line 88
    move-result v12

    .line 89
    :goto_3
    neg-int v12, v12

    .line 90
    int-to-float v12, v12

    .line 91
    cmpl-float v8, v8, v12

    .line 92
    .line 93
    if-ltz v8, :cond_11

    .line 94
    .line 95
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 96
    .line 97
    .line 98
    move-result v7

    .line 99
    invoke-virtual {v9}, Lt3/e1;->d0()I

    .line 100
    .line 101
    .line 102
    move-result v8

    .line 103
    iget-object v10, v10, Lv3/h0;->B:Lt4/m;

    .line 104
    .line 105
    if-eqz v13, :cond_5

    .line 106
    .line 107
    sget-object v12, Lt4/m;->d:Lt4/m;

    .line 108
    .line 109
    if-ne v10, v12, :cond_4

    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_4
    invoke-static {v1, v4, v5}, Lv3/d;->a(IJ)I

    .line 113
    .line 114
    .line 115
    move-result v10

    .line 116
    goto :goto_5

    .line 117
    :cond_5
    :goto_4
    invoke-static {v14, v4, v5}, Lv3/d;->a(IJ)I

    .line 118
    .line 119
    .line 120
    move-result v10

    .line 121
    :goto_5
    add-int/2addr v8, v10

    .line 122
    int-to-float v8, v8

    .line 123
    cmpg-float v7, v7, v8

    .line 124
    .line 125
    if-gez v7, :cond_11

    .line 126
    .line 127
    const-wide v7, 0xffffffffL

    .line 128
    .line 129
    .line 130
    .line 131
    .line 132
    and-long v7, p3, v7

    .line 133
    .line 134
    long-to-int v7, v7

    .line 135
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 136
    .line 137
    .line 138
    move-result v8

    .line 139
    invoke-static {v11, v4, v5}, Lv3/d;->a(IJ)I

    .line 140
    .line 141
    .line 142
    move-result v10

    .line 143
    neg-int v10, v10

    .line 144
    int-to-float v10, v10

    .line 145
    cmpl-float v8, v8, v10

    .line 146
    .line 147
    if-ltz v8, :cond_11

    .line 148
    .line 149
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 150
    .line 151
    .line 152
    move-result v7

    .line 153
    invoke-virtual {v9}, Lt3/e1;->b0()I

    .line 154
    .line 155
    .line 156
    move-result v8

    .line 157
    invoke-static {v3, v4, v5}, Lv3/d;->a(IJ)I

    .line 158
    .line 159
    .line 160
    move-result v3

    .line 161
    add-int/2addr v3, v8

    .line 162
    int-to-float v3, v3

    .line 163
    cmpg-float v3, v7, v3

    .line 164
    .line 165
    if-gez v3, :cond_11

    .line 166
    .line 167
    new-instance v0, Lv3/d1;

    .line 168
    .line 169
    move-object/from16 v2, p1

    .line 170
    .line 171
    move-object/from16 v3, p2

    .line 172
    .line 173
    move-wide/from16 v4, p3

    .line 174
    .line 175
    move/from16 v8, p7

    .line 176
    .line 177
    move/from16 v10, p9

    .line 178
    .line 179
    move v7, v6

    .line 180
    move-object v1, v9

    .line 181
    move-object/from16 v6, p5

    .line 182
    .line 183
    move/from16 v9, p8

    .line 184
    .line 185
    invoke-direct/range {v0 .. v10}, Lv3/d1;-><init>(Lv3/f1;Lx2/r;Lv3/d;JLv3/s;IZFZ)V

    .line 186
    .line 187
    .line 188
    move-object v7, v6

    .line 189
    move-object v6, v2

    .line 190
    iget-object v1, v7, Lv3/s;->e:Landroidx/collection/d0;

    .line 191
    .line 192
    iget-object v2, v7, Lv3/s;->d:Landroidx/collection/l0;

    .line 193
    .line 194
    iget v3, v7, Lv3/s;->f:I

    .line 195
    .line 196
    invoke-static {v7}, Ljp/k1;->h(Ljava/util/List;)I

    .line 197
    .line 198
    .line 199
    move-result v4

    .line 200
    const/4 v5, 0x0

    .line 201
    if-ne v3, v4, :cond_6

    .line 202
    .line 203
    iget v3, v7, Lv3/s;->f:I

    .line 204
    .line 205
    add-int/lit8 v4, v3, 0x1

    .line 206
    .line 207
    iget v9, v2, Landroidx/collection/l0;->b:I

    .line 208
    .line 209
    invoke-virtual {v7, v4, v9}, Lv3/s;->e(II)V

    .line 210
    .line 211
    .line 212
    iget v4, v7, Lv3/s;->f:I

    .line 213
    .line 214
    add-int/2addr v4, v11

    .line 215
    iput v4, v7, Lv3/s;->f:I

    .line 216
    .line 217
    invoke-virtual {v2, v6}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 218
    .line 219
    .line 220
    invoke-static {v5, v8, v11}, Lv3/f;->a(FZZ)J

    .line 221
    .line 222
    .line 223
    move-result-wide v4

    .line 224
    invoke-virtual {v1, v4, v5}, Landroidx/collection/d0;->a(J)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {v0}, Lv3/d1;->invoke()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    iput v3, v7, Lv3/s;->f:I

    .line 231
    .line 232
    return-void

    .line 233
    :cond_6
    invoke-virtual {v7}, Lv3/s;->c()J

    .line 234
    .line 235
    .line 236
    move-result-wide v3

    .line 237
    iget v9, v7, Lv3/s;->f:I

    .line 238
    .line 239
    invoke-static {v3, v4}, Lv3/f;->p(J)Z

    .line 240
    .line 241
    .line 242
    move-result v10

    .line 243
    if-eqz v10, :cond_8

    .line 244
    .line 245
    invoke-static {v7}, Ljp/k1;->h(Ljava/util/List;)I

    .line 246
    .line 247
    .line 248
    move-result v3

    .line 249
    iput v3, v7, Lv3/s;->f:I

    .line 250
    .line 251
    add-int/lit8 v4, v3, 0x1

    .line 252
    .line 253
    iget v10, v2, Landroidx/collection/l0;->b:I

    .line 254
    .line 255
    invoke-virtual {v7, v4, v10}, Lv3/s;->e(II)V

    .line 256
    .line 257
    .line 258
    iget v4, v7, Lv3/s;->f:I

    .line 259
    .line 260
    add-int/2addr v4, v11

    .line 261
    iput v4, v7, Lv3/s;->f:I

    .line 262
    .line 263
    invoke-virtual {v2, v6}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    invoke-static {v5, v8, v11}, Lv3/f;->a(FZZ)J

    .line 267
    .line 268
    .line 269
    move-result-wide v12

    .line 270
    invoke-virtual {v1, v12, v13}, Landroidx/collection/d0;->a(J)V

    .line 271
    .line 272
    .line 273
    invoke-virtual {v0}, Lv3/d1;->invoke()Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    iput v3, v7, Lv3/s;->f:I

    .line 277
    .line 278
    invoke-virtual {v7}, Lv3/s;->c()J

    .line 279
    .line 280
    .line 281
    move-result-wide v0

    .line 282
    invoke-static {v0, v1}, Lv3/f;->l(J)F

    .line 283
    .line 284
    .line 285
    move-result v0

    .line 286
    cmpg-float v0, v0, v5

    .line 287
    .line 288
    if-gez v0, :cond_7

    .line 289
    .line 290
    add-int/lit8 v0, v9, 0x1

    .line 291
    .line 292
    iget v1, v7, Lv3/s;->f:I

    .line 293
    .line 294
    add-int/2addr v1, v11

    .line 295
    invoke-virtual {v7, v0, v1}, Lv3/s;->e(II)V

    .line 296
    .line 297
    .line 298
    :cond_7
    iput v9, v7, Lv3/s;->f:I

    .line 299
    .line 300
    return-void

    .line 301
    :cond_8
    invoke-static {v3, v4}, Lv3/f;->l(J)F

    .line 302
    .line 303
    .line 304
    move-result v3

    .line 305
    cmpl-float v3, v3, v5

    .line 306
    .line 307
    if-lez v3, :cond_9

    .line 308
    .line 309
    iget v3, v7, Lv3/s;->f:I

    .line 310
    .line 311
    add-int/lit8 v4, v3, 0x1

    .line 312
    .line 313
    iget v9, v2, Landroidx/collection/l0;->b:I

    .line 314
    .line 315
    invoke-virtual {v7, v4, v9}, Lv3/s;->e(II)V

    .line 316
    .line 317
    .line 318
    iget v4, v7, Lv3/s;->f:I

    .line 319
    .line 320
    add-int/2addr v4, v11

    .line 321
    iput v4, v7, Lv3/s;->f:I

    .line 322
    .line 323
    invoke-virtual {v2, v6}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 324
    .line 325
    .line 326
    invoke-static {v5, v8, v11}, Lv3/f;->a(FZZ)J

    .line 327
    .line 328
    .line 329
    move-result-wide v4

    .line 330
    invoke-virtual {v1, v4, v5}, Landroidx/collection/d0;->a(J)V

    .line 331
    .line 332
    .line 333
    invoke-virtual {v0}, Lv3/d1;->invoke()Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    iput v3, v7, Lv3/s;->f:I

    .line 337
    .line 338
    :cond_9
    return-void

    .line 339
    :cond_a
    move-object/from16 v6, p1

    .line 340
    .line 341
    move-object/from16 v7, p5

    .line 342
    .line 343
    move/from16 v8, p7

    .line 344
    .line 345
    iget v9, v4, Lx2/r;->f:I

    .line 346
    .line 347
    and-int/2addr v9, v0

    .line 348
    if-eqz v9, :cond_10

    .line 349
    .line 350
    instance-of v9, v4, Lv3/n;

    .line 351
    .line 352
    if-eqz v9, :cond_10

    .line 353
    .line 354
    move-object v9, v4

    .line 355
    check-cast v9, Lv3/n;

    .line 356
    .line 357
    iget-object v9, v9, Lv3/n;->s:Lx2/r;

    .line 358
    .line 359
    move v10, v1

    .line 360
    :goto_6
    if-eqz v9, :cond_f

    .line 361
    .line 362
    iget v12, v9, Lx2/r;->f:I

    .line 363
    .line 364
    and-int/2addr v12, v0

    .line 365
    if-eqz v12, :cond_e

    .line 366
    .line 367
    add-int/lit8 v10, v10, 0x1

    .line 368
    .line 369
    if-ne v10, v11, :cond_b

    .line 370
    .line 371
    move-object v4, v9

    .line 372
    goto :goto_7

    .line 373
    :cond_b
    if-nez v5, :cond_c

    .line 374
    .line 375
    new-instance v5, Ln2/b;

    .line 376
    .line 377
    new-array v12, v0, [Lx2/r;

    .line 378
    .line 379
    invoke-direct {v5, v12}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 380
    .line 381
    .line 382
    :cond_c
    if-eqz v4, :cond_d

    .line 383
    .line 384
    invoke-virtual {v5, v4}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 385
    .line 386
    .line 387
    move-object v4, v2

    .line 388
    :cond_d
    invoke-virtual {v5, v9}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 389
    .line 390
    .line 391
    :cond_e
    :goto_7
    iget-object v9, v9, Lx2/r;->i:Lx2/r;

    .line 392
    .line 393
    goto :goto_6

    .line 394
    :cond_f
    if-ne v10, v11, :cond_10

    .line 395
    .line 396
    :goto_8
    move/from16 v6, p6

    .line 397
    .line 398
    goto/16 :goto_1

    .line 399
    .line 400
    :cond_10
    invoke-static {v5}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 401
    .line 402
    .line 403
    move-result-object v4

    .line 404
    goto :goto_8

    .line 405
    :cond_11
    move-object/from16 v6, p1

    .line 406
    .line 407
    move-object/from16 v7, p5

    .line 408
    .line 409
    move/from16 v8, p7

    .line 410
    .line 411
    if-eqz p9, :cond_12

    .line 412
    .line 413
    invoke-virtual/range {p0 .. p8}, Lv3/f1;->j1(Lx2/r;Lv3/d;JLv3/s;IZF)V

    .line 414
    .line 415
    .line 416
    return-void

    .line 417
    :cond_12
    move-object/from16 v3, p2

    .line 418
    .line 419
    iget v4, v3, Lv3/d;->d:I

    .line 420
    .line 421
    packed-switch v4, :pswitch_data_0

    .line 422
    .line 423
    .line 424
    goto :goto_d

    .line 425
    :pswitch_0
    move-object v5, v2

    .line 426
    move-object v4, v6

    .line 427
    :goto_9
    if-eqz v4, :cond_1a

    .line 428
    .line 429
    instance-of v9, v4, Lv3/t1;

    .line 430
    .line 431
    if-eqz v9, :cond_13

    .line 432
    .line 433
    check-cast v4, Lv3/t1;

    .line 434
    .line 435
    invoke-interface {v4}, Lv3/t1;->A()V

    .line 436
    .line 437
    .line 438
    goto :goto_c

    .line 439
    :cond_13
    iget v9, v4, Lx2/r;->f:I

    .line 440
    .line 441
    and-int/2addr v9, v0

    .line 442
    if-eqz v9, :cond_19

    .line 443
    .line 444
    instance-of v9, v4, Lv3/n;

    .line 445
    .line 446
    if-eqz v9, :cond_19

    .line 447
    .line 448
    move-object v9, v4

    .line 449
    check-cast v9, Lv3/n;

    .line 450
    .line 451
    iget-object v9, v9, Lv3/n;->s:Lx2/r;

    .line 452
    .line 453
    move v10, v1

    .line 454
    :goto_a
    if-eqz v9, :cond_18

    .line 455
    .line 456
    iget v12, v9, Lx2/r;->f:I

    .line 457
    .line 458
    and-int/2addr v12, v0

    .line 459
    if-eqz v12, :cond_17

    .line 460
    .line 461
    add-int/lit8 v10, v10, 0x1

    .line 462
    .line 463
    if-ne v10, v11, :cond_14

    .line 464
    .line 465
    move-object v4, v9

    .line 466
    goto :goto_b

    .line 467
    :cond_14
    if-nez v5, :cond_15

    .line 468
    .line 469
    new-instance v5, Ln2/b;

    .line 470
    .line 471
    new-array v12, v0, [Lx2/r;

    .line 472
    .line 473
    invoke-direct {v5, v12}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 474
    .line 475
    .line 476
    :cond_15
    if-eqz v4, :cond_16

    .line 477
    .line 478
    invoke-virtual {v5, v4}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 479
    .line 480
    .line 481
    move-object v4, v2

    .line 482
    :cond_16
    invoke-virtual {v5, v9}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 483
    .line 484
    .line 485
    :cond_17
    :goto_b
    iget-object v9, v9, Lx2/r;->i:Lx2/r;

    .line 486
    .line 487
    goto :goto_a

    .line 488
    :cond_18
    if-ne v10, v11, :cond_19

    .line 489
    .line 490
    goto :goto_9

    .line 491
    :cond_19
    :goto_c
    invoke-static {v5}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 492
    .line 493
    .line 494
    move-result-object v4

    .line 495
    goto :goto_9

    .line 496
    :cond_1a
    :goto_d
    invoke-virtual {v3}, Lv3/d;->c()I

    .line 497
    .line 498
    .line 499
    move-result v0

    .line 500
    invoke-static {v6, v0}, Lv3/f;->e(Lv3/m;I)Lx2/r;

    .line 501
    .line 502
    .line 503
    move-result-object v1

    .line 504
    const/4 v9, 0x0

    .line 505
    move-object/from16 v0, p0

    .line 506
    .line 507
    move/from16 v6, p6

    .line 508
    .line 509
    move-object v2, v3

    .line 510
    move-object v5, v7

    .line 511
    move v7, v8

    .line 512
    move-wide/from16 v3, p3

    .line 513
    .line 514
    move/from16 v8, p8

    .line 515
    .line 516
    invoke-virtual/range {v0 .. v9}, Lv3/f1;->t1(Lx2/r;Lv3/d;JLv3/s;IZFZ)V

    .line 517
    .line 518
    .line 519
    return-void

    .line 520
    nop

    .line 521
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public abstract u1(Le3/r;Lh3/c;)V
.end method

.method public final v1(JFLay0/k;Lh3/c;)V
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    const/4 v2, 0x0

    .line 4
    iget-object v3, p0, Lv3/f1;->r:Lv3/h0;

    .line 5
    .line 6
    if-eqz p5, :cond_3

    .line 7
    .line 8
    if-nez p4, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const-string p4, "both ways to create layers shouldn\'t be used together"

    .line 12
    .line 13
    invoke-static {p4}, Ls3/a;->a(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    :goto_0
    iget-object p4, p0, Lv3/f1;->M:Lh3/c;

    .line 17
    .line 18
    if-eq p4, p5, :cond_1

    .line 19
    .line 20
    iput-object v2, p0, Lv3/f1;->M:Lh3/c;

    .line 21
    .line 22
    invoke-virtual {p0, v2, v0}, Lv3/f1;->E1(Lay0/k;Z)V

    .line 23
    .line 24
    .line 25
    iput-object p5, p0, Lv3/f1;->M:Lh3/c;

    .line 26
    .line 27
    :cond_1
    iget-object p4, p0, Lv3/f1;->L:Lv3/n1;

    .line 28
    .line 29
    if-nez p4, :cond_5

    .line 30
    .line 31
    invoke-static {v3}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 32
    .line 33
    .line 34
    move-result-object p4

    .line 35
    iget-object v0, p0, Lv3/f1;->I:Lkn/i0;

    .line 36
    .line 37
    if-nez v0, :cond_2

    .line 38
    .line 39
    new-instance v0, Lv3/c1;

    .line 40
    .line 41
    const/4 v2, 0x0

    .line 42
    invoke-direct {v0, p0, v2}, Lv3/c1;-><init>(Lv3/f1;I)V

    .line 43
    .line 44
    .line 45
    new-instance v2, Lkn/i0;

    .line 46
    .line 47
    const/4 v4, 0x3

    .line 48
    invoke-direct {v2, v4, p0, v0}, Lkn/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput-object v2, p0, Lv3/f1;->I:Lkn/i0;

    .line 52
    .line 53
    move-object v0, v2

    .line 54
    :cond_2
    check-cast p4, Lw3/t;

    .line 55
    .line 56
    iget-object v2, p0, Lv3/f1;->J:Lv3/c1;

    .line 57
    .line 58
    invoke-virtual {p4, v0, v2, p5}, Lw3/t;->h(Lay0/n;Lv3/c1;Lh3/c;)Lv3/n1;

    .line 59
    .line 60
    .line 61
    move-result-object p4

    .line 62
    iget-wide v4, p0, Lt3/e1;->f:J

    .line 63
    .line 64
    move-object p5, p4

    .line 65
    check-cast p5, Lw3/o1;

    .line 66
    .line 67
    invoke-virtual {p5, v4, v5}, Lw3/o1;->f(J)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p5, p1, p2}, Lw3/o1;->e(J)V

    .line 71
    .line 72
    .line 73
    iput-object p4, p0, Lv3/f1;->L:Lv3/n1;

    .line 74
    .line 75
    iput-boolean v1, v3, Lv3/h0;->L:Z

    .line 76
    .line 77
    invoke-virtual {v2}, Lv3/c1;->invoke()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_3
    iget-object p5, p0, Lv3/f1;->M:Lh3/c;

    .line 82
    .line 83
    if-eqz p5, :cond_4

    .line 84
    .line 85
    iput-object v2, p0, Lv3/f1;->M:Lh3/c;

    .line 86
    .line 87
    invoke-virtual {p0, v2, v0}, Lv3/f1;->E1(Lay0/k;Z)V

    .line 88
    .line 89
    .line 90
    :cond_4
    invoke-virtual {p0, p4, v0}, Lv3/f1;->E1(Lay0/k;Z)V

    .line 91
    .line 92
    .line 93
    :cond_5
    :goto_1
    iget-wide p4, p0, Lv3/f1;->C:J

    .line 94
    .line 95
    invoke-static {p4, p5, p1, p2}, Lt4/j;->b(JJ)Z

    .line 96
    .line 97
    .line 98
    move-result p4

    .line 99
    if-nez p4, :cond_8

    .line 100
    .line 101
    invoke-static {v3}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 102
    .line 103
    .line 104
    move-result-object p4

    .line 105
    const/high16 p5, -0x3f800000    # -4.0f

    .line 106
    .line 107
    check-cast p4, Lw3/t;

    .line 108
    .line 109
    invoke-virtual {p4, p5}, Lw3/t;->I(F)V

    .line 110
    .line 111
    .line 112
    iput-wide p1, p0, Lv3/f1;->C:J

    .line 113
    .line 114
    iget-object p4, v3, Lv3/h0;->I:Lv3/l0;

    .line 115
    .line 116
    iget-object p4, p4, Lv3/l0;->p:Lv3/y0;

    .line 117
    .line 118
    invoke-virtual {p4}, Lv3/y0;->F0()V

    .line 119
    .line 120
    .line 121
    iget-object p4, p0, Lv3/f1;->L:Lv3/n1;

    .line 122
    .line 123
    if-eqz p4, :cond_6

    .line 124
    .line 125
    check-cast p4, Lw3/o1;

    .line 126
    .line 127
    invoke-virtual {p4, p1, p2}, Lw3/o1;->e(J)V

    .line 128
    .line 129
    .line 130
    goto :goto_2

    .line 131
    :cond_6
    iget-object p1, p0, Lv3/f1;->t:Lv3/f1;

    .line 132
    .line 133
    if-eqz p1, :cond_7

    .line 134
    .line 135
    invoke-virtual {p1}, Lv3/f1;->m1()V

    .line 136
    .line 137
    .line 138
    :cond_7
    :goto_2
    invoke-virtual {v3}, Lv3/h0;->O()V

    .line 139
    .line 140
    .line 141
    invoke-static {p0}, Lv3/p0;->R0(Lv3/f1;)V

    .line 142
    .line 143
    .line 144
    iget-object p1, v3, Lv3/h0;->p:Lv3/o1;

    .line 145
    .line 146
    if-eqz p1, :cond_8

    .line 147
    .line 148
    check-cast p1, Lw3/t;

    .line 149
    .line 150
    invoke-virtual {p1, v3}, Lw3/t;->v(Lv3/h0;)V

    .line 151
    .line 152
    .line 153
    :cond_8
    iput p3, p0, Lv3/f1;->D:F

    .line 154
    .line 155
    iget-boolean p1, p0, Lv3/p0;->n:Z

    .line 156
    .line 157
    if-nez p1, :cond_9

    .line 158
    .line 159
    invoke-virtual {p0}, Lv3/f1;->N0()Lt3/r0;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    invoke-virtual {p0, p1}, Lv3/p0;->F0(Lt3/r0;)V

    .line 164
    .line 165
    .line 166
    :cond_9
    iget-object p1, v3, Lv3/h0;->H:Lg1/q;

    .line 167
    .line 168
    iget-object p1, p1, Lg1/q;->e:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast p1, Lv3/f1;

    .line 171
    .line 172
    if-ne p0, p1, :cond_a

    .line 173
    .line 174
    invoke-static {v3}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    check-cast p0, Lw3/t;

    .line 179
    .line 180
    invoke-virtual {p0}, Lw3/t;->getRectManager()Le4/a;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    iget-object p1, v3, Lv3/h0;->I:Lv3/l0;

    .line 185
    .line 186
    iget-object p1, p1, Lv3/l0;->p:Lv3/y0;

    .line 187
    .line 188
    iget-boolean p1, p1, Lv3/y0;->n:Z

    .line 189
    .line 190
    xor-int/2addr p1, v1

    .line 191
    invoke-virtual {p0, v3, p1}, Le4/a;->g(Lv3/h0;Z)V

    .line 192
    .line 193
    .line 194
    :cond_a
    return-void
.end method

.method public final w1(Ld3/a;ZZ)V
    .locals 10

    .line 1
    iget-object v0, p0, Lv3/f1;->L:Lv3/n1;

    .line 2
    .line 3
    const-wide v1, 0xffffffffL

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    const/16 v3, 0x20

    .line 9
    .line 10
    if-eqz v0, :cond_3

    .line 11
    .line 12
    iget-boolean v4, p0, Lv3/f1;->v:Z

    .line 13
    .line 14
    if-eqz v4, :cond_2

    .line 15
    .line 16
    if-eqz p3, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Lv3/f1;->e1()J

    .line 19
    .line 20
    .line 21
    move-result-wide p2

    .line 22
    shr-long v4, p2, v3

    .line 23
    .line 24
    long-to-int v4, v4

    .line 25
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 26
    .line 27
    .line 28
    move-result v4

    .line 29
    const/high16 v5, 0x40000000    # 2.0f

    .line 30
    .line 31
    div-float/2addr v4, v5

    .line 32
    and-long/2addr p2, v1

    .line 33
    long-to-int p2, p2

    .line 34
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    div-float/2addr p2, v5

    .line 39
    neg-float p3, v4

    .line 40
    neg-float v5, p2

    .line 41
    iget-wide v6, p0, Lt3/e1;->f:J

    .line 42
    .line 43
    shr-long v8, v6, v3

    .line 44
    .line 45
    long-to-int v8, v8

    .line 46
    int-to-float v8, v8

    .line 47
    add-float/2addr v8, v4

    .line 48
    and-long/2addr v6, v1

    .line 49
    long-to-int v4, v6

    .line 50
    int-to-float v4, v4

    .line 51
    add-float/2addr v4, p2

    .line 52
    invoke-virtual {p1, p3, v5, v8, v4}, Ld3/a;->f(FFFF)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    if-eqz p2, :cond_1

    .line 57
    .line 58
    iget-wide p2, p0, Lt3/e1;->f:J

    .line 59
    .line 60
    shr-long v4, p2, v3

    .line 61
    .line 62
    long-to-int v4, v4

    .line 63
    int-to-float v4, v4

    .line 64
    and-long/2addr p2, v1

    .line 65
    long-to-int p2, p2

    .line 66
    int-to-float p2, p2

    .line 67
    const/4 p3, 0x0

    .line 68
    invoke-virtual {p1, p3, p3, v4, p2}, Ld3/a;->f(FFFF)V

    .line 69
    .line 70
    .line 71
    :cond_1
    :goto_0
    invoke-virtual {p1}, Ld3/a;->g()Z

    .line 72
    .line 73
    .line 74
    move-result p2

    .line 75
    if-eqz p2, :cond_2

    .line 76
    .line 77
    return-void

    .line 78
    :cond_2
    const/4 p2, 0x0

    .line 79
    check-cast v0, Lw3/o1;

    .line 80
    .line 81
    invoke-virtual {v0, p1, p2}, Lw3/o1;->c(Ld3/a;Z)V

    .line 82
    .line 83
    .line 84
    :cond_3
    iget-wide p2, p0, Lv3/f1;->C:J

    .line 85
    .line 86
    shr-long v3, p2, v3

    .line 87
    .line 88
    long-to-int p0, v3

    .line 89
    iget v0, p1, Ld3/a;->b:F

    .line 90
    .line 91
    int-to-float p0, p0

    .line 92
    add-float/2addr v0, p0

    .line 93
    iput v0, p1, Ld3/a;->b:F

    .line 94
    .line 95
    iget v0, p1, Ld3/a;->d:F

    .line 96
    .line 97
    add-float/2addr v0, p0

    .line 98
    iput v0, p1, Ld3/a;->d:F

    .line 99
    .line 100
    and-long/2addr p2, v1

    .line 101
    long-to-int p0, p2

    .line 102
    iget p2, p1, Ld3/a;->c:F

    .line 103
    .line 104
    int-to-float p0, p0

    .line 105
    add-float/2addr p2, p0

    .line 106
    iput p2, p1, Ld3/a;->c:F

    .line 107
    .line 108
    iget p2, p1, Ld3/a;->e:F

    .line 109
    .line 110
    add-float/2addr p2, p0

    .line 111
    iput p2, p1, Ld3/a;->e:F

    .line 112
    .line 113
    return-void
.end method

.method public final x1()V
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/f1;->L:Lv3/n1;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lv3/f1;->M:Lh3/c;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iput-object v1, p0, Lv3/f1;->M:Lh3/c;

    .line 11
    .line 12
    :cond_0
    const/4 v0, 0x0

    .line 13
    invoke-virtual {p0, v1, v0}, Lv3/f1;->E1(Lay0/k;Z)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Lv3/h0;->X(Z)V

    .line 19
    .line 20
    .line 21
    :cond_1
    return-void
.end method

.method public final y1(Lt3/r0;)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lv3/f1;->A:Lt3/r0;

    .line 6
    .line 7
    if-eq v1, v2, :cond_18

    .line 8
    .line 9
    iput-object v1, v0, Lv3/f1;->A:Lt3/r0;

    .line 10
    .line 11
    iget-object v3, v0, Lv3/f1;->r:Lv3/h0;

    .line 12
    .line 13
    const/4 v4, 0x0

    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    invoke-interface {v1}, Lt3/r0;->o()I

    .line 17
    .line 18
    .line 19
    move-result v5

    .line 20
    invoke-interface {v2}, Lt3/r0;->o()I

    .line 21
    .line 22
    .line 23
    move-result v6

    .line 24
    if-ne v5, v6, :cond_0

    .line 25
    .line 26
    invoke-interface {v1}, Lt3/r0;->m()I

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    invoke-interface {v2}, Lt3/r0;->m()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eq v5, v2, :cond_f

    .line 35
    .line 36
    :cond_0
    invoke-interface {v1}, Lt3/r0;->o()I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    invoke-interface {v1}, Lt3/r0;->m()I

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    iget-object v6, v0, Lv3/f1;->L:Lv3/n1;

    .line 45
    .line 46
    const-wide v7, 0xffffffffL

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    const/16 v9, 0x20

    .line 52
    .line 53
    if-eqz v6, :cond_1

    .line 54
    .line 55
    int-to-long v10, v2

    .line 56
    shl-long/2addr v10, v9

    .line 57
    int-to-long v12, v5

    .line 58
    and-long/2addr v12, v7

    .line 59
    or-long/2addr v10, v12

    .line 60
    check-cast v6, Lw3/o1;

    .line 61
    .line 62
    invoke-virtual {v6, v10, v11}, Lw3/o1;->f(J)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_1
    invoke-virtual {v3}, Lv3/h0;->J()Z

    .line 67
    .line 68
    .line 69
    move-result v6

    .line 70
    if-eqz v6, :cond_2

    .line 71
    .line 72
    iget-object v6, v0, Lv3/f1;->t:Lv3/f1;

    .line 73
    .line 74
    if-eqz v6, :cond_2

    .line 75
    .line 76
    invoke-virtual {v6}, Lv3/f1;->m1()V

    .line 77
    .line 78
    .line 79
    :cond_2
    :goto_0
    int-to-long v10, v2

    .line 80
    shl-long v9, v10, v9

    .line 81
    .line 82
    int-to-long v5, v5

    .line 83
    and-long/2addr v5, v7

    .line 84
    or-long/2addr v5, v9

    .line 85
    invoke-virtual {v0, v5, v6}, Lt3/e1;->v0(J)V

    .line 86
    .line 87
    .line 88
    iget-object v2, v0, Lv3/f1;->w:Lay0/k;

    .line 89
    .line 90
    if-eqz v2, :cond_3

    .line 91
    .line 92
    invoke-virtual {v0, v4}, Lv3/f1;->F1(Z)Z

    .line 93
    .line 94
    .line 95
    :cond_3
    const/4 v2, 0x4

    .line 96
    invoke-static {v2}, Lv3/g1;->g(I)Z

    .line 97
    .line 98
    .line 99
    move-result v5

    .line 100
    invoke-virtual {v0}, Lv3/f1;->f1()Lx2/r;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    if-eqz v5, :cond_4

    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_4
    iget-object v6, v6, Lx2/r;->h:Lx2/r;

    .line 108
    .line 109
    if-nez v6, :cond_5

    .line 110
    .line 111
    goto/16 :goto_7

    .line 112
    .line 113
    :cond_5
    :goto_1
    invoke-virtual {v0, v5}, Lv3/f1;->h1(Z)Lx2/r;

    .line 114
    .line 115
    .line 116
    move-result-object v5

    .line 117
    :goto_2
    if-eqz v5, :cond_e

    .line 118
    .line 119
    iget v7, v5, Lx2/r;->g:I

    .line 120
    .line 121
    and-int/2addr v7, v2

    .line 122
    if-eqz v7, :cond_e

    .line 123
    .line 124
    iget v7, v5, Lx2/r;->f:I

    .line 125
    .line 126
    and-int/2addr v7, v2

    .line 127
    if-eqz v7, :cond_d

    .line 128
    .line 129
    const/4 v7, 0x0

    .line 130
    move-object v8, v5

    .line 131
    move-object v9, v7

    .line 132
    :goto_3
    if-eqz v8, :cond_d

    .line 133
    .line 134
    instance-of v10, v8, Lv3/p;

    .line 135
    .line 136
    if-eqz v10, :cond_6

    .line 137
    .line 138
    check-cast v8, Lv3/p;

    .line 139
    .line 140
    invoke-interface {v8}, Lv3/p;->m0()V

    .line 141
    .line 142
    .line 143
    goto :goto_6

    .line 144
    :cond_6
    iget v10, v8, Lx2/r;->f:I

    .line 145
    .line 146
    and-int/2addr v10, v2

    .line 147
    if-eqz v10, :cond_c

    .line 148
    .line 149
    instance-of v10, v8, Lv3/n;

    .line 150
    .line 151
    if-eqz v10, :cond_c

    .line 152
    .line 153
    move-object v10, v8

    .line 154
    check-cast v10, Lv3/n;

    .line 155
    .line 156
    iget-object v10, v10, Lv3/n;->s:Lx2/r;

    .line 157
    .line 158
    move v11, v4

    .line 159
    :goto_4
    const/4 v12, 0x1

    .line 160
    if-eqz v10, :cond_b

    .line 161
    .line 162
    iget v13, v10, Lx2/r;->f:I

    .line 163
    .line 164
    and-int/2addr v13, v2

    .line 165
    if-eqz v13, :cond_a

    .line 166
    .line 167
    add-int/lit8 v11, v11, 0x1

    .line 168
    .line 169
    if-ne v11, v12, :cond_7

    .line 170
    .line 171
    move-object v8, v10

    .line 172
    goto :goto_5

    .line 173
    :cond_7
    if-nez v9, :cond_8

    .line 174
    .line 175
    new-instance v9, Ln2/b;

    .line 176
    .line 177
    const/16 v12, 0x10

    .line 178
    .line 179
    new-array v12, v12, [Lx2/r;

    .line 180
    .line 181
    invoke-direct {v9, v12}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    :cond_8
    if-eqz v8, :cond_9

    .line 185
    .line 186
    invoke-virtual {v9, v8}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    move-object v8, v7

    .line 190
    :cond_9
    invoke-virtual {v9, v10}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    :cond_a
    :goto_5
    iget-object v10, v10, Lx2/r;->i:Lx2/r;

    .line 194
    .line 195
    goto :goto_4

    .line 196
    :cond_b
    if-ne v11, v12, :cond_c

    .line 197
    .line 198
    goto :goto_3

    .line 199
    :cond_c
    :goto_6
    invoke-static {v9}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 200
    .line 201
    .line 202
    move-result-object v8

    .line 203
    goto :goto_3

    .line 204
    :cond_d
    if-eq v5, v6, :cond_e

    .line 205
    .line 206
    iget-object v5, v5, Lx2/r;->i:Lx2/r;

    .line 207
    .line 208
    goto :goto_2

    .line 209
    :cond_e
    :goto_7
    iget-object v2, v3, Lv3/h0;->p:Lv3/o1;

    .line 210
    .line 211
    if-eqz v2, :cond_f

    .line 212
    .line 213
    check-cast v2, Lw3/t;

    .line 214
    .line 215
    invoke-virtual {v2, v3}, Lw3/t;->v(Lv3/h0;)V

    .line 216
    .line 217
    .line 218
    :cond_f
    iget-object v2, v0, Lv3/f1;->B:Landroidx/collection/h0;

    .line 219
    .line 220
    if-eqz v2, :cond_10

    .line 221
    .line 222
    iget v2, v2, Landroidx/collection/h0;->e:I

    .line 223
    .line 224
    if-eqz v2, :cond_10

    .line 225
    .line 226
    goto :goto_8

    .line 227
    :cond_10
    invoke-interface {v1}, Lt3/r0;->b()Ljava/util/Map;

    .line 228
    .line 229
    .line 230
    move-result-object v2

    .line 231
    invoke-interface {v2}, Ljava/util/Map;->isEmpty()Z

    .line 232
    .line 233
    .line 234
    move-result v2

    .line 235
    if-nez v2, :cond_18

    .line 236
    .line 237
    :goto_8
    iget-object v2, v0, Lv3/f1;->B:Landroidx/collection/h0;

    .line 238
    .line 239
    invoke-interface {v1}, Lt3/r0;->b()Ljava/util/Map;

    .line 240
    .line 241
    .line 242
    move-result-object v5

    .line 243
    if-nez v2, :cond_11

    .line 244
    .line 245
    goto :goto_b

    .line 246
    :cond_11
    iget v6, v2, Landroidx/collection/h0;->e:I

    .line 247
    .line 248
    invoke-interface {v5}, Ljava/util/Map;->size()I

    .line 249
    .line 250
    .line 251
    move-result v7

    .line 252
    if-eq v6, v7, :cond_12

    .line 253
    .line 254
    goto :goto_b

    .line 255
    :cond_12
    iget-object v6, v2, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 256
    .line 257
    iget-object v7, v2, Landroidx/collection/h0;->c:[I

    .line 258
    .line 259
    iget-object v2, v2, Landroidx/collection/h0;->a:[J

    .line 260
    .line 261
    array-length v8, v2

    .line 262
    add-int/lit8 v8, v8, -0x2

    .line 263
    .line 264
    if-ltz v8, :cond_18

    .line 265
    .line 266
    move v9, v4

    .line 267
    :goto_9
    aget-wide v10, v2, v9

    .line 268
    .line 269
    not-long v12, v10

    .line 270
    const/4 v14, 0x7

    .line 271
    shl-long/2addr v12, v14

    .line 272
    and-long/2addr v12, v10

    .line 273
    const-wide v14, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 274
    .line 275
    .line 276
    .line 277
    .line 278
    and-long/2addr v12, v14

    .line 279
    cmp-long v12, v12, v14

    .line 280
    .line 281
    if-eqz v12, :cond_17

    .line 282
    .line 283
    sub-int v12, v9, v8

    .line 284
    .line 285
    not-int v12, v12

    .line 286
    ushr-int/lit8 v12, v12, 0x1f

    .line 287
    .line 288
    const/16 v13, 0x8

    .line 289
    .line 290
    rsub-int/lit8 v12, v12, 0x8

    .line 291
    .line 292
    move v14, v4

    .line 293
    :goto_a
    if-ge v14, v12, :cond_16

    .line 294
    .line 295
    const-wide/16 v15, 0xff

    .line 296
    .line 297
    and-long/2addr v15, v10

    .line 298
    const-wide/16 v17, 0x80

    .line 299
    .line 300
    cmp-long v15, v15, v17

    .line 301
    .line 302
    if-gez v15, :cond_15

    .line 303
    .line 304
    shl-int/lit8 v15, v9, 0x3

    .line 305
    .line 306
    add-int/2addr v15, v14

    .line 307
    aget-object v16, v6, v15

    .line 308
    .line 309
    aget v15, v7, v15

    .line 310
    .line 311
    move-object/from16 v4, v16

    .line 312
    .line 313
    check-cast v4, Lt3/a;

    .line 314
    .line 315
    invoke-interface {v5, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v4

    .line 319
    check-cast v4, Ljava/lang/Integer;

    .line 320
    .line 321
    if-nez v4, :cond_13

    .line 322
    .line 323
    goto :goto_b

    .line 324
    :cond_13
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 325
    .line 326
    .line 327
    move-result v4

    .line 328
    if-eq v4, v15, :cond_15

    .line 329
    .line 330
    :goto_b
    iget-object v2, v3, Lv3/h0;->I:Lv3/l0;

    .line 331
    .line 332
    iget-object v2, v2, Lv3/l0;->p:Lv3/y0;

    .line 333
    .line 334
    iget-object v2, v2, Lv3/y0;->B:Lv3/i0;

    .line 335
    .line 336
    invoke-virtual {v2}, Lv3/i0;->f()V

    .line 337
    .line 338
    .line 339
    iget-object v2, v0, Lv3/f1;->B:Landroidx/collection/h0;

    .line 340
    .line 341
    if-nez v2, :cond_14

    .line 342
    .line 343
    sget-object v2, Landroidx/collection/v0;->a:Landroidx/collection/h0;

    .line 344
    .line 345
    new-instance v2, Landroidx/collection/h0;

    .line 346
    .line 347
    invoke-direct {v2}, Landroidx/collection/h0;-><init>()V

    .line 348
    .line 349
    .line 350
    iput-object v2, v0, Lv3/f1;->B:Landroidx/collection/h0;

    .line 351
    .line 352
    :cond_14
    invoke-virtual {v2}, Landroidx/collection/h0;->a()V

    .line 353
    .line 354
    .line 355
    invoke-interface {v1}, Lt3/r0;->b()Ljava/util/Map;

    .line 356
    .line 357
    .line 358
    move-result-object v0

    .line 359
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 360
    .line 361
    .line 362
    move-result-object v0

    .line 363
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 364
    .line 365
    .line 366
    move-result-object v0

    .line 367
    :goto_c
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 368
    .line 369
    .line 370
    move-result v1

    .line 371
    if-eqz v1, :cond_18

    .line 372
    .line 373
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v1

    .line 377
    check-cast v1, Ljava/util/Map$Entry;

    .line 378
    .line 379
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 380
    .line 381
    .line 382
    move-result-object v3

    .line 383
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 384
    .line 385
    .line 386
    move-result-object v1

    .line 387
    check-cast v1, Ljava/lang/Number;

    .line 388
    .line 389
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 390
    .line 391
    .line 392
    move-result v1

    .line 393
    invoke-virtual {v2, v1, v3}, Landroidx/collection/h0;->h(ILjava/lang/Object;)V

    .line 394
    .line 395
    .line 396
    goto :goto_c

    .line 397
    :cond_15
    shr-long/2addr v10, v13

    .line 398
    add-int/lit8 v14, v14, 0x1

    .line 399
    .line 400
    const/4 v4, 0x0

    .line 401
    goto :goto_a

    .line 402
    :cond_16
    if-ne v12, v13, :cond_18

    .line 403
    .line 404
    :cond_17
    if-eq v9, v8, :cond_18

    .line 405
    .line 406
    add-int/lit8 v9, v9, 0x1

    .line 407
    .line 408
    const/4 v4, 0x0

    .line 409
    goto/16 :goto_9

    .line 410
    .line 411
    :cond_18
    return-void
.end method

.method public final z(J)J
    .locals 1

    .line 1
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const-string v0, "LayoutCoordinate operations are only valid when isAttached is true"

    .line 10
    .line 11
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    iget-object v0, p0, Lv3/f1;->r:Lv3/h0;

    .line 15
    .line 16
    invoke-static {v0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Lw3/t;

    .line 21
    .line 22
    invoke-virtual {v0, p1, p2}, Lw3/t;->D(J)J

    .line 23
    .line 24
    .line 25
    move-result-wide p1

    .line 26
    invoke-static {p0}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-virtual {p0, v0, p1, p2}, Lv3/f1;->o1(Lt3/y;J)J

    .line 31
    .line 32
    .line 33
    move-result-wide p0

    .line 34
    return-wide p0
.end method
