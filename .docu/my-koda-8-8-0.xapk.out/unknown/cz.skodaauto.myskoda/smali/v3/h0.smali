.class public final Lv3/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/j;
.implements Lv3/p1;
.implements Lv3/k;


# static fields
.field public static final T:Lv3/c0;

.field public static final U:Lv3/b0;

.field public static final V:Lcom/salesforce/marketingcloud/analytics/piwama/m;


# instance fields
.field public A:Lt4/c;

.field public B:Lt4/m;

.field public C:Lw3/h2;

.field public D:Ll2/c0;

.field public E:Lv3/f0;

.field public F:Lv3/f0;

.field public G:Z

.field public final H:Lg1/q;

.field public final I:Lv3/l0;

.field public J:Lt3/m0;

.field public K:Lv3/f1;

.field public L:Z

.field public M:Lx2/s;

.field public N:Lx2/s;

.field public O:Lw4/c;

.field public P:Lp3/b0;

.field public Q:Z

.field public R:I

.field public S:Z

.field public final d:Z

.field public e:I

.field public f:J

.field public g:J

.field public h:J

.field public i:Z

.field public j:Lv3/h0;

.field public k:I

.field public final l:Lc2/k;

.field public m:Ln2/b;

.field public n:Z

.field public o:Lv3/h0;

.field public p:Lv3/o1;

.field public q:Lw4/o;

.field public r:I

.field public s:Z

.field public t:Z

.field public u:Ld4/l;

.field public v:Z

.field public final w:Ln2/b;

.field public x:Z

.field public y:Lt3/q0;

.field public z:Lb81/d;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lv3/c0;

    .line 2
    .line 3
    const-string v1, "Undefined intrinsics block and it is required"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lv3/e0;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lv3/h0;->T:Lv3/c0;

    .line 9
    .line 10
    new-instance v0, Lv3/b0;

    .line 11
    .line 12
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lv3/h0;->U:Lv3/b0;

    .line 16
    .line 17
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 18
    .line 19
    const/16 v1, 0x1a

    .line 20
    .line 21
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Lv3/h0;->V:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 25
    .line 26
    return-void
.end method

.method public constructor <init>(I)V
    .locals 2

    const/4 v0, 0x1

    and-int/2addr p1, v0

    if-eqz p1, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    :cond_0
    move p1, v0

    .line 1
    :goto_0
    sget-object v1, Ld4/n;->a:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicInteger;->addAndGet(I)I

    move-result v0

    .line 2
    invoke-direct {p0, v0, p1}, Lv3/h0;-><init>(IZ)V

    return-void
.end method

.method public constructor <init>(IZ)V
    .locals 4

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-boolean p2, p0, Lv3/h0;->d:Z

    .line 5
    iput p1, p0, Lv3/h0;->e:I

    const-wide p1, 0x7fffffff7fffffffL

    .line 6
    iput-wide p1, p0, Lv3/h0;->f:J

    const-wide/16 v0, 0x0

    .line 7
    iput-wide v0, p0, Lv3/h0;->g:J

    .line 8
    iput-wide p1, p0, Lv3/h0;->h:J

    const/4 p1, 0x1

    .line 9
    iput-boolean p1, p0, Lv3/h0;->i:Z

    .line 10
    new-instance p2, Lc2/k;

    .line 11
    new-instance v0, Ln2/b;

    const/16 v1, 0x10

    new-array v2, v1, [Lv3/h0;

    invoke-direct {v0, v2}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 12
    new-instance v2, La7/j;

    const/16 v3, 0x17

    invoke-direct {v2, p0, v3}, La7/j;-><init>(Ljava/lang/Object;I)V

    const/16 v3, 0x1a

    invoke-direct {p2, v3, v0, v2}, Lc2/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iput-object p2, p0, Lv3/h0;->l:Lc2/k;

    .line 13
    new-instance p2, Ln2/b;

    new-array v0, v1, [Lv3/h0;

    invoke-direct {p2, v0}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 14
    iput-object p2, p0, Lv3/h0;->w:Ln2/b;

    .line 15
    iput-boolean p1, p0, Lv3/h0;->x:Z

    .line 16
    sget-object p2, Lv3/h0;->T:Lv3/c0;

    iput-object p2, p0, Lv3/h0;->y:Lt3/q0;

    .line 17
    sget-object p2, Lv3/k0;->a:Lt4/d;

    .line 18
    iput-object p2, p0, Lv3/h0;->A:Lt4/c;

    .line 19
    sget-object p2, Lt4/m;->d:Lt4/m;

    iput-object p2, p0, Lv3/h0;->B:Lt4/m;

    .line 20
    sget-object p2, Lv3/h0;->U:Lv3/b0;

    iput-object p2, p0, Lv3/h0;->C:Lw3/h2;

    .line 21
    sget-object p2, Ll2/c0;->j1:Ll2/b0;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    sget-object p2, Ll2/b0;->b:Lt2/g;

    .line 23
    iput-object p2, p0, Lv3/h0;->D:Ll2/c0;

    .line 24
    sget-object p2, Lv3/f0;->f:Lv3/f0;

    iput-object p2, p0, Lv3/h0;->E:Lv3/f0;

    .line 25
    iput-object p2, p0, Lv3/h0;->F:Lv3/f0;

    .line 26
    new-instance p2, Lg1/q;

    invoke-direct {p2, p0}, Lg1/q;-><init>(Lv3/h0;)V

    iput-object p2, p0, Lv3/h0;->H:Lg1/q;

    .line 27
    new-instance p2, Lv3/l0;

    invoke-direct {p2, p0}, Lv3/l0;-><init>(Lv3/h0;)V

    iput-object p2, p0, Lv3/h0;->I:Lv3/l0;

    .line 28
    iput-boolean p1, p0, Lv3/h0;->L:Z

    .line 29
    sget-object p1, Lx2/p;->b:Lx2/p;

    iput-object p1, p0, Lv3/h0;->M:Lx2/s;

    return-void
.end method

.method public static R(Lv3/h0;)Z
    .locals 3

    .line 1
    iget-object v0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object v0, v0, Lv3/l0;->p:Lv3/y0;

    .line 4
    .line 5
    iget-boolean v1, v0, Lv3/y0;->m:Z

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    iget-wide v0, v0, Lt3/e1;->g:J

    .line 10
    .line 11
    new-instance v2, Lt4/a;

    .line 12
    .line 13
    invoke-direct {v2, v0, v1}, Lt4/a;-><init>(J)V

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v2, 0x0

    .line 18
    :goto_0
    invoke-virtual {p0, v2}, Lv3/h0;->Q(Lt4/a;)Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0
.end method

.method public static W(Lv3/h0;ZI)V
    .locals 4

    .line 1
    and-int/lit8 v0, p2, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move p1, v1

    .line 7
    :cond_0
    and-int/lit8 v0, p2, 0x2

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    move v0, v2

    .line 13
    goto :goto_0

    .line 14
    :cond_1
    move v0, v1

    .line 15
    :goto_0
    and-int/lit8 p2, p2, 0x4

    .line 16
    .line 17
    if-eqz p2, :cond_2

    .line 18
    .line 19
    move v1, v2

    .line 20
    :cond_2
    iget-object p2, p0, Lv3/h0;->j:Lv3/h0;

    .line 21
    .line 22
    if-eqz p2, :cond_3

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_3
    const-string p2, "Lookahead measure cannot be requested on a node that is not a part of the LookaheadScope"

    .line 26
    .line 27
    invoke-static {p2}, Ls3/a;->b(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    :goto_1
    iget-object p2, p0, Lv3/h0;->p:Lv3/o1;

    .line 31
    .line 32
    if-nez p2, :cond_4

    .line 33
    .line 34
    goto :goto_4

    .line 35
    :cond_4
    iget-boolean v3, p0, Lv3/h0;->s:Z

    .line 36
    .line 37
    if-nez v3, :cond_b

    .line 38
    .line 39
    iget-boolean v3, p0, Lv3/h0;->d:Z

    .line 40
    .line 41
    if-nez v3, :cond_b

    .line 42
    .line 43
    check-cast p2, Lw3/t;

    .line 44
    .line 45
    invoke-virtual {p2, p0, v2, p1, v0}, Lw3/t;->w(Lv3/h0;ZZZ)V

    .line 46
    .line 47
    .line 48
    if-eqz v1, :cond_b

    .line 49
    .line 50
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 51
    .line 52
    iget-object p0, p0, Lv3/l0;->q:Lv3/u0;

    .line 53
    .line 54
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-object p0, p0, Lv3/u0;->i:Lv3/l0;

    .line 58
    .line 59
    iget-object p2, p0, Lv3/l0;->a:Lv3/h0;

    .line 60
    .line 61
    invoke-virtual {p2}, Lv3/h0;->v()Lv3/h0;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 66
    .line 67
    iget-object p0, p0, Lv3/h0;->E:Lv3/f0;

    .line 68
    .line 69
    if-eqz p2, :cond_b

    .line 70
    .line 71
    sget-object v0, Lv3/f0;->f:Lv3/f0;

    .line 72
    .line 73
    if-eq p0, v0, :cond_b

    .line 74
    .line 75
    :goto_2
    iget-object v0, p2, Lv3/h0;->E:Lv3/f0;

    .line 76
    .line 77
    if-ne v0, p0, :cond_6

    .line 78
    .line 79
    invoke-virtual {p2}, Lv3/h0;->v()Lv3/h0;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    if-nez v0, :cond_5

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_5
    move-object p2, v0

    .line 87
    goto :goto_2

    .line 88
    :cond_6
    :goto_3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    if-eqz p0, :cond_9

    .line 93
    .line 94
    if-ne p0, v2, :cond_8

    .line 95
    .line 96
    iget-object p0, p2, Lv3/h0;->j:Lv3/h0;

    .line 97
    .line 98
    if-eqz p0, :cond_7

    .line 99
    .line 100
    invoke-virtual {p2, p1}, Lv3/h0;->V(Z)V

    .line 101
    .line 102
    .line 103
    return-void

    .line 104
    :cond_7
    invoke-virtual {p2, p1}, Lv3/h0;->X(Z)V

    .line 105
    .line 106
    .line 107
    return-void

    .line 108
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 109
    .line 110
    const-string p1, "Intrinsics isn\'t used by the parent"

    .line 111
    .line 112
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    :cond_9
    iget-object p0, p2, Lv3/h0;->j:Lv3/h0;

    .line 117
    .line 118
    const/4 v0, 0x6

    .line 119
    if-eqz p0, :cond_a

    .line 120
    .line 121
    invoke-static {p2, p1, v0}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 122
    .line 123
    .line 124
    return-void

    .line 125
    :cond_a
    invoke-static {p2, p1, v0}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 126
    .line 127
    .line 128
    :cond_b
    :goto_4
    return-void
.end method

.method public static Y(Lv3/h0;ZI)V
    .locals 4

    .line 1
    and-int/lit8 v0, p2, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move p1, v1

    .line 7
    :cond_0
    and-int/lit8 v0, p2, 0x2

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    move v0, v2

    .line 13
    goto :goto_0

    .line 14
    :cond_1
    move v0, v1

    .line 15
    :goto_0
    and-int/lit8 p2, p2, 0x4

    .line 16
    .line 17
    if-eqz p2, :cond_2

    .line 18
    .line 19
    move p2, v2

    .line 20
    goto :goto_1

    .line 21
    :cond_2
    move p2, v1

    .line 22
    :goto_1
    iget-boolean v3, p0, Lv3/h0;->s:Z

    .line 23
    .line 24
    if-nez v3, :cond_8

    .line 25
    .line 26
    iget-boolean v3, p0, Lv3/h0;->d:Z

    .line 27
    .line 28
    if-nez v3, :cond_8

    .line 29
    .line 30
    iget-object v3, p0, Lv3/h0;->p:Lv3/o1;

    .line 31
    .line 32
    if-nez v3, :cond_3

    .line 33
    .line 34
    goto :goto_4

    .line 35
    :cond_3
    check-cast v3, Lw3/t;

    .line 36
    .line 37
    invoke-virtual {v3, p0, v1, p1, v0}, Lw3/t;->w(Lv3/h0;ZZZ)V

    .line 38
    .line 39
    .line 40
    if-eqz p2, :cond_8

    .line 41
    .line 42
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 43
    .line 44
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 45
    .line 46
    iget-object p0, p0, Lv3/y0;->i:Lv3/l0;

    .line 47
    .line 48
    iget-object p2, p0, Lv3/l0;->a:Lv3/h0;

    .line 49
    .line 50
    invoke-virtual {p2}, Lv3/h0;->v()Lv3/h0;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 55
    .line 56
    iget-object p0, p0, Lv3/h0;->E:Lv3/f0;

    .line 57
    .line 58
    if-eqz p2, :cond_8

    .line 59
    .line 60
    sget-object v0, Lv3/f0;->f:Lv3/f0;

    .line 61
    .line 62
    if-eq p0, v0, :cond_8

    .line 63
    .line 64
    :goto_2
    iget-object v0, p2, Lv3/h0;->E:Lv3/f0;

    .line 65
    .line 66
    if-ne v0, p0, :cond_5

    .line 67
    .line 68
    invoke-virtual {p2}, Lv3/h0;->v()Lv3/h0;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    if-nez v0, :cond_4

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_4
    move-object p2, v0

    .line 76
    goto :goto_2

    .line 77
    :cond_5
    :goto_3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    if-eqz p0, :cond_7

    .line 82
    .line 83
    if-ne p0, v2, :cond_6

    .line 84
    .line 85
    invoke-virtual {p2, p1}, Lv3/h0;->X(Z)V

    .line 86
    .line 87
    .line 88
    return-void

    .line 89
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 90
    .line 91
    const-string p1, "Intrinsics isn\'t used by the parent"

    .line 92
    .line 93
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :cond_7
    const/4 p0, 0x6

    .line 98
    invoke-static {p2, p1, p0}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 99
    .line 100
    .line 101
    :cond_8
    :goto_4
    return-void
.end method

.method public static Z(Lv3/h0;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/l0;->d:Lv3/d0;

    .line 4
    .line 5
    sget-object v2, Lv3/g0;->a:[I

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    aget v1, v2, v1

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    if-ne v1, v2, :cond_4

    .line 15
    .line 16
    iget-boolean v1, v0, Lv3/l0;->e:Z

    .line 17
    .line 18
    const/4 v3, 0x6

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-static {p0, v2, v3}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    iget-boolean v0, v0, Lv3/l0;->f:Z

    .line 26
    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    invoke-virtual {p0, v2}, Lv3/h0;->V(Z)V

    .line 30
    .line 31
    .line 32
    :cond_1
    invoke-virtual {p0}, Lv3/h0;->r()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_2

    .line 37
    .line 38
    invoke-static {p0, v2, v3}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_2
    invoke-virtual {p0}, Lv3/h0;->q()Z

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-eqz v0, :cond_3

    .line 47
    .line 48
    invoke-virtual {p0, v2}, Lv3/h0;->X(Z)V

    .line 49
    .line 50
    .line 51
    :cond_3
    return-void

    .line 52
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    new-instance v1, Ljava/lang/StringBuilder;

    .line 55
    .line 56
    const-string v2, "Unexpected state "

    .line 57
    .line 58
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iget-object v0, v0, Lv3/l0;->d:Lv3/d0;

    .line 62
    .line 63
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw p0
.end method

.method private final k(Lv3/h0;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Cannot insert "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string v1, " because it already has a parent or an owner. This tree: "

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    invoke-virtual {p0, v1}, Lv3/h0;->h(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string p0, " Other tree: "

    .line 25
    .line 26
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    iget-object p0, p1, Lv3/h0;->o:Lv3/h0;

    .line 30
    .line 31
    if-eqz p0, :cond_0

    .line 32
    .line 33
    invoke-virtual {p0, v1}, Lv3/h0;->h(I)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 p0, 0x0

    .line 39
    :goto_0
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method


# virtual methods
.method public final A(JLv3/s;IZ)V
    .locals 9

    .line 1
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 2
    .line 3
    iget-object v0, p0, Lg1/q;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lv3/f1;

    .line 6
    .line 7
    sget-object v1, Lv3/f1;->N:Le3/k0;

    .line 8
    .line 9
    invoke-virtual {v0, p1, p2}, Lv3/f1;->c1(J)J

    .line 10
    .line 11
    .line 12
    move-result-wide v4

    .line 13
    iget-object p0, p0, Lg1/q;->e:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v2, p0

    .line 16
    check-cast v2, Lv3/f1;

    .line 17
    .line 18
    sget-object v3, Lv3/f1;->Q:Lv3/d;

    .line 19
    .line 20
    move-object v6, p3

    .line 21
    move v7, p4

    .line 22
    move v8, p5

    .line 23
    invoke-virtual/range {v2 .. v8}, Lv3/f1;->k1(Lv3/d;JLv3/s;IZ)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final B(ILv3/h0;)V
    .locals 2

    .line 1
    iget-object v0, p2, Lv3/h0;->o:Lv3/h0;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p2, Lv3/h0;->p:Lv3/o1;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-direct {p0, p2}, Lv3/h0;->k(Lv3/h0;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    :cond_1
    :goto_0
    iput-object p0, p2, Lv3/h0;->o:Lv3/h0;

    .line 18
    .line 19
    iget-object v0, p0, Lv3/h0;->l:Lc2/k;

    .line 20
    .line 21
    iget-object v1, v0, Lc2/k;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v1, Ln2/b;

    .line 24
    .line 25
    invoke-virtual {v1, p1, p2}, Ln2/b;->b(ILjava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    iget-object p1, v0, Lc2/k;->f:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p1, La7/j;

    .line 31
    .line 32
    invoke-virtual {p1}, La7/j;->invoke()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0}, Lv3/h0;->P()V

    .line 36
    .line 37
    .line 38
    iget-boolean p1, p2, Lv3/h0;->d:Z

    .line 39
    .line 40
    if-eqz p1, :cond_2

    .line 41
    .line 42
    iget p1, p0, Lv3/h0;->k:I

    .line 43
    .line 44
    add-int/lit8 p1, p1, 0x1

    .line 45
    .line 46
    iput p1, p0, Lv3/h0;->k:I

    .line 47
    .line 48
    :cond_2
    invoke-virtual {p0}, Lv3/h0;->H()V

    .line 49
    .line 50
    .line 51
    iget-object p1, p0, Lv3/h0;->p:Lv3/o1;

    .line 52
    .line 53
    if-eqz p1, :cond_3

    .line 54
    .line 55
    invoke-virtual {p2, p1}, Lv3/h0;->c(Lv3/o1;)V

    .line 56
    .line 57
    .line 58
    :cond_3
    iget-object p1, p2, Lv3/h0;->I:Lv3/l0;

    .line 59
    .line 60
    iget p1, p1, Lv3/l0;->l:I

    .line 61
    .line 62
    if-lez p1, :cond_4

    .line 63
    .line 64
    iget-object p1, p0, Lv3/h0;->I:Lv3/l0;

    .line 65
    .line 66
    iget v0, p1, Lv3/l0;->l:I

    .line 67
    .line 68
    add-int/lit8 v0, v0, 0x1

    .line 69
    .line 70
    invoke-virtual {p1, v0}, Lv3/l0;->d(I)V

    .line 71
    .line 72
    .line 73
    :cond_4
    iget p1, p2, Lv3/h0;->R:I

    .line 74
    .line 75
    if-lez p1, :cond_5

    .line 76
    .line 77
    iget p1, p0, Lv3/h0;->R:I

    .line 78
    .line 79
    add-int/lit8 p1, p1, 0x1

    .line 80
    .line 81
    invoke-virtual {p0, p1}, Lv3/h0;->f0(I)V

    .line 82
    .line 83
    .line 84
    :cond_5
    return-void
.end method

.method public final C()V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lv3/h0;->L:Z

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    iget-object v0, p0, Lv3/h0;->H:Lg1/q;

    .line 6
    .line 7
    iget-object v1, v0, Lg1/q;->d:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v1, Lv3/u;

    .line 10
    .line 11
    iget-object v0, v0, Lg1/q;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lv3/f1;

    .line 14
    .line 15
    iget-object v0, v0, Lv3/f1;->t:Lv3/f1;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    iput-object v2, p0, Lv3/h0;->K:Lv3/f1;

    .line 19
    .line 20
    :goto_0
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    if-nez v3, :cond_3

    .line 25
    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    iget-object v3, v1, Lv3/f1;->L:Lv3/n1;

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_0
    move-object v3, v2

    .line 32
    :goto_1
    if-eqz v3, :cond_1

    .line 33
    .line 34
    iput-object v1, p0, Lv3/h0;->K:Lv3/f1;

    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_1
    if-eqz v1, :cond_2

    .line 38
    .line 39
    iget-object v1, v1, Lv3/f1;->t:Lv3/f1;

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    move-object v1, v2

    .line 43
    goto :goto_0

    .line 44
    :cond_3
    :goto_2
    iget-object v0, p0, Lv3/h0;->K:Lv3/f1;

    .line 45
    .line 46
    if-eqz v0, :cond_5

    .line 47
    .line 48
    iget-object v1, v0, Lv3/f1;->L:Lv3/n1;

    .line 49
    .line 50
    if-eqz v1, :cond_4

    .line 51
    .line 52
    goto :goto_3

    .line 53
    :cond_4
    const-string p0, "layer was not set"

    .line 54
    .line 55
    invoke-static {p0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    throw p0

    .line 60
    :cond_5
    :goto_3
    if-eqz v0, :cond_6

    .line 61
    .line 62
    invoke-virtual {v0}, Lv3/f1;->m1()V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :cond_6
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    if-eqz p0, :cond_7

    .line 71
    .line 72
    invoke-virtual {p0}, Lv3/h0;->C()V

    .line 73
    .line 74
    .line 75
    :cond_7
    return-void
.end method

.method public final D()V
    .locals 3

    .line 1
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 2
    .line 3
    iget-object v0, p0, Lg1/q;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lv3/f1;

    .line 6
    .line 7
    iget-object v1, p0, Lg1/q;->d:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v1, Lv3/u;

    .line 10
    .line 11
    :goto_0
    if-eq v0, v1, :cond_1

    .line 12
    .line 13
    const-string v2, "null cannot be cast to non-null type androidx.compose.ui.node.LayoutModifierNodeCoordinator"

    .line 14
    .line 15
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    check-cast v0, Lv3/a0;

    .line 19
    .line 20
    iget-object v2, v0, Lv3/f1;->L:Lv3/n1;

    .line 21
    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    invoke-interface {v2}, Lv3/n1;->invalidate()V

    .line 25
    .line 26
    .line 27
    :cond_0
    iget-object v0, v0, Lv3/f1;->s:Lv3/f1;

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    iget-object p0, p0, Lg1/q;->d:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lv3/u;

    .line 33
    .line 34
    iget-object p0, p0, Lv3/f1;->L:Lv3/n1;

    .line 35
    .line 36
    if-eqz p0, :cond_2

    .line 37
    .line 38
    invoke-interface {p0}, Lv3/n1;->invalidate()V

    .line 39
    .line 40
    .line 41
    :cond_2
    return-void
.end method

.method public final E()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lv3/h0;->d:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lv3/h0;->E()V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void

    .line 15
    :cond_1
    iget-object v0, p0, Lv3/h0;->j:Lv3/h0;

    .line 16
    .line 17
    const/4 v1, 0x7

    .line 18
    const/4 v2, 0x0

    .line 19
    if-eqz v0, :cond_2

    .line 20
    .line 21
    invoke-static {p0, v2, v1}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_2
    invoke-static {p0, v2, v1}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final F()V
    .locals 4

    .line 1
    iget-wide v0, p0, Lv3/h0;->f:J

    .line 2
    .line 3
    const-wide v2, 0x7fffffff7fffffffL

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    invoke-static {v0, v1, v2, v3}, Lt4/j;->b(JJ)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_0
    iput-wide v2, p0, Lv3/h0;->f:J

    .line 16
    .line 17
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 22
    .line 23
    iget p0, p0, Ln2/b;->f:I

    .line 24
    .line 25
    const/4 v1, 0x0

    .line 26
    :goto_0
    if-ge v1, p0, :cond_1

    .line 27
    .line 28
    aget-object v2, v0, v1

    .line 29
    .line 30
    check-cast v2, Lv3/h0;

    .line 31
    .line 32
    invoke-virtual {v2}, Lv3/h0;->F()V

    .line 33
    .line 34
    .line 35
    add-int/lit8 v1, v1, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    :goto_1
    return-void
.end method

.method public final G()V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lv3/h0;->v:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Lv3/h0;->H:Lg1/q;

    .line 7
    .line 8
    iget-object v0, v0, Lg1/q;->c:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lv3/b1;

    .line 11
    .line 12
    iget-object v0, v0, Lx2/r;->i:Lx2/r;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_1
    iget-object v0, p0, Lv3/h0;->N:Lx2/s;

    .line 19
    .line 20
    if-eqz v0, :cond_2

    .line 21
    .line 22
    :goto_0
    iput-boolean v1, p0, Lv3/h0;->t:Z

    .line 23
    .line 24
    return-void

    .line 25
    :cond_2
    iget-object v0, p0, Lv3/h0;->u:Ld4/l;

    .line 26
    .line 27
    iput-boolean v1, p0, Lv3/h0;->v:Z

    .line 28
    .line 29
    new-instance v1, Lkotlin/jvm/internal/f0;

    .line 30
    .line 31
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 32
    .line 33
    .line 34
    new-instance v2, Ld4/l;

    .line 35
    .line 36
    invoke-direct {v2}, Ld4/l;-><init>()V

    .line 37
    .line 38
    .line 39
    iput-object v2, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 40
    .line 41
    invoke-static {p0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    check-cast v2, Lw3/t;

    .line 46
    .line 47
    invoke-virtual {v2}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    new-instance v3, La4/b;

    .line 52
    .line 53
    const/4 v4, 0x7

    .line 54
    invoke-direct {v3, v4, p0, v1}, La4/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-object v4, v2, Lv3/q1;->d:Lv3/e;

    .line 58
    .line 59
    invoke-virtual {v2, p0, v4, v3}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 60
    .line 61
    .line 62
    const/4 v2, 0x0

    .line 63
    iput-boolean v2, p0, Lv3/h0;->v:Z

    .line 64
    .line 65
    iget-object v1, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v1, Ld4/l;

    .line 68
    .line 69
    iput-object v1, p0, Lv3/h0;->u:Ld4/l;

    .line 70
    .line 71
    iput-boolean v2, p0, Lv3/h0;->t:Z

    .line 72
    .line 73
    invoke-static {p0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    check-cast v1, Lw3/t;

    .line 78
    .line 79
    invoke-virtual {v1}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    invoke-virtual {v2, p0, v0}, Ld4/s;->b(Lv3/h0;Ld4/l;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v1}, Lw3/t;->y()V

    .line 87
    .line 88
    .line 89
    return-void
.end method

.method public final H()V
    .locals 1

    .line 1
    iget v0, p0, Lv3/h0;->k:I

    .line 2
    .line 3
    if-lez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lv3/h0;->n:Z

    .line 7
    .line 8
    :cond_0
    iget-boolean v0, p0, Lv3/h0;->d:Z

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    iget-object p0, p0, Lv3/h0;->o:Lv3/h0;

    .line 13
    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    invoke-virtual {p0}, Lv3/h0;->H()V

    .line 17
    .line 18
    .line 19
    :cond_1
    return-void
.end method

.method public final I()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/h0;->p:Lv3/o1;

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

.method public final J()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 4
    .line 5
    iget-boolean p0, p0, Lv3/y0;->w:Z

    .line 6
    .line 7
    return p0
.end method

.method public final K()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->q:Lv3/u0;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lv3/u0;->w()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return-object p0
.end method

.method public final L()V
    .locals 6

    .line 1
    iget-object v0, p0, Lv3/h0;->E:Lv3/f0;

    .line 2
    .line 3
    sget-object v1, Lv3/f0;->f:Lv3/f0;

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lv3/h0;->g()V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 11
    .line 12
    iget-object p0, p0, Lv3/l0;->q:Lv3/u0;

    .line 13
    .line 14
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    const/4 v1, 0x1

    .line 19
    :try_start_0
    iput-boolean v1, p0, Lv3/u0;->j:Z

    .line 20
    .line 21
    iget-boolean v1, p0, Lv3/u0;->o:Z

    .line 22
    .line 23
    if-nez v1, :cond_1

    .line 24
    .line 25
    const-string v1, "replace() called on item that was not placed"

    .line 26
    .line 27
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :catchall_0
    move-exception v1

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    :goto_0
    iput-boolean v0, p0, Lv3/u0;->B:Z

    .line 34
    .line 35
    invoke-virtual {p0}, Lv3/u0;->w()Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    iget-wide v2, p0, Lv3/u0;->r:J

    .line 40
    .line 41
    iget-object v4, p0, Lv3/u0;->s:Lay0/k;

    .line 42
    .line 43
    iget-object v5, p0, Lv3/u0;->t:Lh3/c;

    .line 44
    .line 45
    invoke-virtual {p0, v2, v3, v4, v5}, Lv3/u0;->J0(JLay0/k;Lh3/c;)V

    .line 46
    .line 47
    .line 48
    if-eqz v1, :cond_2

    .line 49
    .line 50
    iget-boolean v1, p0, Lv3/u0;->B:Z

    .line 51
    .line 52
    if-nez v1, :cond_2

    .line 53
    .line 54
    iget-object v1, p0, Lv3/u0;->i:Lv3/l0;

    .line 55
    .line 56
    iget-object v1, v1, Lv3/l0;->a:Lv3/h0;

    .line 57
    .line 58
    invoke-virtual {v1}, Lv3/h0;->v()Lv3/h0;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    if-eqz v1, :cond_2

    .line 63
    .line 64
    invoke-virtual {v1, v0}, Lv3/h0;->V(Z)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 65
    .line 66
    .line 67
    :cond_2
    iput-boolean v0, p0, Lv3/u0;->j:Z

    .line 68
    .line 69
    return-void

    .line 70
    :goto_1
    iput-boolean v0, p0, Lv3/u0;->j:Z

    .line 71
    .line 72
    throw v1
.end method

.method public final M(III)V
    .locals 6

    .line 1
    if-ne p1, p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    const/4 v0, 0x0

    .line 5
    :goto_0
    if-ge v0, p3, :cond_3

    .line 6
    .line 7
    if-le p1, p2, :cond_1

    .line 8
    .line 9
    add-int v1, p1, v0

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_1
    move v1, p1

    .line 13
    :goto_1
    if-le p1, p2, :cond_2

    .line 14
    .line 15
    add-int v2, p2, v0

    .line 16
    .line 17
    goto :goto_2

    .line 18
    :cond_2
    add-int v2, p2, p3

    .line 19
    .line 20
    add-int/lit8 v2, v2, -0x2

    .line 21
    .line 22
    :goto_2
    iget-object v3, p0, Lv3/h0;->l:Lc2/k;

    .line 23
    .line 24
    iget-object v4, v3, Lc2/k;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v4, Ln2/b;

    .line 27
    .line 28
    iget-object v5, v3, Lc2/k;->f:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v5, La7/j;

    .line 31
    .line 32
    invoke-virtual {v4, v1}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-virtual {v5}, La7/j;->invoke()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    check-cast v1, Lv3/h0;

    .line 40
    .line 41
    iget-object v3, v3, Lc2/k;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v3, Ln2/b;

    .line 44
    .line 45
    invoke-virtual {v3, v2, v1}, Ln2/b;->b(ILjava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v5}, La7/j;->invoke()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    add-int/lit8 v0, v0, 0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_3
    invoke-virtual {p0}, Lv3/h0;->P()V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0}, Lv3/h0;->H()V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p0}, Lv3/h0;->E()V

    .line 61
    .line 62
    .line 63
    return-void
.end method

.method public final N(Lv3/h0;)V
    .locals 4

    .line 1
    iget-object v0, p1, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget v0, v0, Lv3/l0;->l:I

    .line 4
    .line 5
    if-lez v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lv3/h0;->I:Lv3/l0;

    .line 8
    .line 9
    iget v1, v0, Lv3/l0;->l:I

    .line 10
    .line 11
    add-int/lit8 v1, v1, -0x1

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Lv3/l0;->d(I)V

    .line 14
    .line 15
    .line 16
    :cond_0
    iget-object v0, p0, Lv3/h0;->p:Lv3/o1;

    .line 17
    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    invoke-virtual {p1}, Lv3/h0;->i()V

    .line 21
    .line 22
    .line 23
    :cond_1
    const/4 v0, 0x0

    .line 24
    iput-object v0, p1, Lv3/h0;->o:Lv3/h0;

    .line 25
    .line 26
    iget v1, p1, Lv3/h0;->R:I

    .line 27
    .line 28
    if-lez v1, :cond_2

    .line 29
    .line 30
    iget v1, p0, Lv3/h0;->R:I

    .line 31
    .line 32
    add-int/lit8 v1, v1, -0x1

    .line 33
    .line 34
    invoke-virtual {p0, v1}, Lv3/h0;->f0(I)V

    .line 35
    .line 36
    .line 37
    :cond_2
    iget-object v1, p1, Lv3/h0;->H:Lg1/q;

    .line 38
    .line 39
    iget-object v1, v1, Lg1/q;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v1, Lv3/f1;

    .line 42
    .line 43
    iput-object v0, v1, Lv3/f1;->t:Lv3/f1;

    .line 44
    .line 45
    iget-boolean v1, p1, Lv3/h0;->d:Z

    .line 46
    .line 47
    if-eqz v1, :cond_3

    .line 48
    .line 49
    iget v1, p0, Lv3/h0;->k:I

    .line 50
    .line 51
    add-int/lit8 v1, v1, -0x1

    .line 52
    .line 53
    iput v1, p0, Lv3/h0;->k:I

    .line 54
    .line 55
    iget-object p1, p1, Lv3/h0;->l:Lc2/k;

    .line 56
    .line 57
    iget-object p1, p1, Lc2/k;->e:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p1, Ln2/b;

    .line 60
    .line 61
    iget-object v1, p1, Ln2/b;->d:[Ljava/lang/Object;

    .line 62
    .line 63
    iget p1, p1, Ln2/b;->f:I

    .line 64
    .line 65
    const/4 v2, 0x0

    .line 66
    :goto_0
    if-ge v2, p1, :cond_3

    .line 67
    .line 68
    aget-object v3, v1, v2

    .line 69
    .line 70
    check-cast v3, Lv3/h0;

    .line 71
    .line 72
    iget-object v3, v3, Lv3/h0;->H:Lg1/q;

    .line 73
    .line 74
    iget-object v3, v3, Lg1/q;->e:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v3, Lv3/f1;

    .line 77
    .line 78
    iput-object v0, v3, Lv3/f1;->t:Lv3/f1;

    .line 79
    .line 80
    add-int/lit8 v2, v2, 0x1

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_3
    invoke-virtual {p0}, Lv3/h0;->H()V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0}, Lv3/h0;->P()V

    .line 87
    .line 88
    .line 89
    return-void
.end method

.method public final O()V
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lv3/h0;->i:Z

    .line 3
    .line 4
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 9
    .line 10
    iget p0, p0, Ln2/b;->f:I

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    :goto_0
    if-ge v1, p0, :cond_0

    .line 14
    .line 15
    aget-object v2, v0, v1

    .line 16
    .line 17
    check-cast v2, Lv3/h0;

    .line 18
    .line 19
    invoke-virtual {v2}, Lv3/h0;->F()V

    .line 20
    .line 21
    .line 22
    add-int/lit8 v1, v1, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-void
.end method

.method public final P()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lv3/h0;->d:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lv3/h0;->P()V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void

    .line 15
    :cond_1
    const/4 v0, 0x1

    .line 16
    iput-boolean v0, p0, Lv3/h0;->x:Z

    .line 17
    .line 18
    return-void
.end method

.method public final Q(Lt4/a;)Z
    .locals 2

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    iget-object v0, p0, Lv3/h0;->E:Lv3/f0;

    .line 4
    .line 5
    sget-object v1, Lv3/f0;->f:Lv3/f0;

    .line 6
    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lv3/h0;->d()V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 13
    .line 14
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 15
    .line 16
    iget-wide v0, p1, Lt4/a;->a:J

    .line 17
    .line 18
    invoke-virtual {p0, v0, v1}, Lv3/y0;->O0(J)Z

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

.method public final S()V
    .locals 4

    .line 1
    iget-object v0, p0, Lv3/h0;->l:Lc2/k;

    .line 2
    .line 3
    iget-object v1, v0, Lc2/k;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Ln2/b;

    .line 6
    .line 7
    iget-object v2, v0, Lc2/k;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v2, Ln2/b;

    .line 10
    .line 11
    iget v1, v1, Ln2/b;->f:I

    .line 12
    .line 13
    add-int/lit8 v1, v1, -0x1

    .line 14
    .line 15
    :goto_0
    const/4 v3, -0x1

    .line 16
    if-ge v3, v1, :cond_0

    .line 17
    .line 18
    iget-object v3, v2, Ln2/b;->d:[Ljava/lang/Object;

    .line 19
    .line 20
    aget-object v3, v3, v1

    .line 21
    .line 22
    check-cast v3, Lv3/h0;

    .line 23
    .line 24
    invoke-virtual {p0, v3}, Lv3/h0;->N(Lv3/h0;)V

    .line 25
    .line 26
    .line 27
    add-int/lit8 v1, v1, -0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-virtual {v2}, Ln2/b;->i()V

    .line 31
    .line 32
    .line 33
    iget-object p0, v0, Lc2/k;->f:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, La7/j;

    .line 36
    .line 37
    invoke-virtual {p0}, La7/j;->invoke()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public final T(II)V
    .locals 2

    .line 1
    if-ltz p2, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 5
    .line 6
    const-string v1, "count ("

    .line 7
    .line 8
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    const-string v1, ") must be greater than 0"

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    :goto_0
    add-int/2addr p2, p1

    .line 27
    add-int/lit8 p2, p2, -0x1

    .line 28
    .line 29
    if-gt p1, p2, :cond_1

    .line 30
    .line 31
    :goto_1
    iget-object v0, p0, Lv3/h0;->l:Lc2/k;

    .line 32
    .line 33
    iget-object v1, v0, Lc2/k;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v1, Ln2/b;

    .line 36
    .line 37
    iget-object v1, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 38
    .line 39
    aget-object v1, v1, p2

    .line 40
    .line 41
    check-cast v1, Lv3/h0;

    .line 42
    .line 43
    invoke-virtual {p0, v1}, Lv3/h0;->N(Lv3/h0;)V

    .line 44
    .line 45
    .line 46
    iget-object v1, v0, Lc2/k;->e:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v1, Ln2/b;

    .line 49
    .line 50
    invoke-virtual {v1, p2}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    iget-object v0, v0, Lc2/k;->f:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v0, La7/j;

    .line 57
    .line 58
    invoke-virtual {v0}, La7/j;->invoke()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    check-cast v1, Lv3/h0;

    .line 62
    .line 63
    if-eq p2, p1, :cond_1

    .line 64
    .line 65
    add-int/lit8 p2, p2, -0x1

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_1
    return-void
.end method

.method public final U()V
    .locals 8

    .line 1
    iget-object v0, p0, Lv3/h0;->E:Lv3/f0;

    .line 2
    .line 3
    sget-object v1, Lv3/f0;->f:Lv3/f0;

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lv3/h0;->g()V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 11
    .line 12
    iget-object v1, p0, Lv3/l0;->p:Lv3/y0;

    .line 13
    .line 14
    iget-object p0, v1, Lv3/y0;->i:Lv3/l0;

    .line 15
    .line 16
    const/4 v7, 0x0

    .line 17
    const/4 v0, 0x1

    .line 18
    :try_start_0
    iput-boolean v0, v1, Lv3/y0;->j:Z

    .line 19
    .line 20
    iget-boolean v0, v1, Lv3/y0;->n:Z

    .line 21
    .line 22
    if-nez v0, :cond_1

    .line 23
    .line 24
    const-string v0, "replace called on unplaced item"

    .line 25
    .line 26
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :catchall_0
    move-exception v0

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    :goto_0
    iget-boolean v0, v1, Lv3/y0;->w:Z

    .line 33
    .line 34
    iget-wide v2, v1, Lv3/y0;->q:J

    .line 35
    .line 36
    iget v4, v1, Lv3/y0;->t:F

    .line 37
    .line 38
    iget-object v5, v1, Lv3/y0;->r:Lay0/k;

    .line 39
    .line 40
    iget-object v6, v1, Lv3/y0;->s:Lh3/c;

    .line 41
    .line 42
    invoke-virtual/range {v1 .. v6}, Lv3/y0;->M0(JFLay0/k;Lh3/c;)V

    .line 43
    .line 44
    .line 45
    if-eqz v0, :cond_2

    .line 46
    .line 47
    iget-boolean v0, v1, Lv3/y0;->J:Z

    .line 48
    .line 49
    if-nez v0, :cond_2

    .line 50
    .line 51
    iget-object v0, p0, Lv3/l0;->a:Lv3/h0;

    .line 52
    .line 53
    invoke-virtual {v0}, Lv3/h0;->v()Lv3/h0;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    if-eqz v0, :cond_2

    .line 58
    .line 59
    invoke-virtual {v0, v7}, Lv3/h0;->X(Z)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 60
    .line 61
    .line 62
    :cond_2
    iput-boolean v7, v1, Lv3/y0;->j:Z

    .line 63
    .line 64
    return-void

    .line 65
    :goto_1
    :try_start_1
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 66
    .line 67
    invoke-virtual {p0, v0}, Lv3/h0;->b0(Ljava/lang/Throwable;)V

    .line 68
    .line 69
    .line 70
    const/4 p0, 0x0

    .line 71
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 72
    :catchall_1
    move-exception v0

    .line 73
    move-object p0, v0

    .line 74
    iput-boolean v7, v1, Lv3/y0;->j:Z

    .line 75
    .line 76
    throw p0
.end method

.method public final V(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lv3/h0;->d:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lv3/h0;->p:Lv3/o1;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    check-cast v0, Lw3/t;

    .line 11
    .line 12
    invoke-virtual {v0, p0, v1, p1}, Lw3/t;->x(Lv3/h0;ZZ)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method

.method public final X(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lv3/h0;->d:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lv3/h0;->p:Lv3/o1;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    check-cast v0, Lw3/t;

    .line 11
    .line 12
    invoke-virtual {v0, p0, v1, p1}, Lw3/t;->x(Lv3/h0;ZZ)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method

.method public final a()V
    .locals 4

    .line 1
    iget-object v0, p0, Lv3/h0;->q:Lw4/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lw4/g;->a()V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object v0, p0, Lv3/h0;->J:Lt3/m0;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Lt3/m0;->g(Z)V

    .line 14
    .line 15
    .line 16
    :cond_1
    iput-boolean v1, p0, Lv3/h0;->S:Z

    .line 17
    .line 18
    iget-object v0, p0, Lv3/h0;->H:Lg1/q;

    .line 19
    .line 20
    iget-object v0, v0, Lg1/q;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v0, Lv3/z1;

    .line 23
    .line 24
    move-object v1, v0

    .line 25
    :goto_0
    if-eqz v1, :cond_3

    .line 26
    .line 27
    iget-boolean v2, v1, Lx2/r;->q:Z

    .line 28
    .line 29
    if-eqz v2, :cond_2

    .line 30
    .line 31
    invoke-virtual {v1}, Lx2/r;->S0()V

    .line 32
    .line 33
    .line 34
    :cond_2
    iget-object v1, v1, Lx2/r;->h:Lx2/r;

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_3
    move-object v1, v0

    .line 38
    :goto_1
    if-eqz v1, :cond_5

    .line 39
    .line 40
    iget-boolean v2, v1, Lx2/r;->q:Z

    .line 41
    .line 42
    if-eqz v2, :cond_4

    .line 43
    .line 44
    invoke-virtual {v1}, Lx2/r;->U0()V

    .line 45
    .line 46
    .line 47
    :cond_4
    iget-object v1, v1, Lx2/r;->h:Lx2/r;

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_5
    :goto_2
    if-eqz v0, :cond_7

    .line 51
    .line 52
    iget-boolean v1, v0, Lx2/r;->q:Z

    .line 53
    .line 54
    if-eqz v1, :cond_6

    .line 55
    .line 56
    invoke-virtual {v0}, Lx2/r;->O0()V

    .line 57
    .line 58
    .line 59
    :cond_6
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_7
    invoke-virtual {p0}, Lv3/h0;->I()Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    const/4 v1, 0x0

    .line 67
    if-eqz v0, :cond_8

    .line 68
    .line 69
    const/4 v0, 0x0

    .line 70
    iput-object v0, p0, Lv3/h0;->u:Ld4/l;

    .line 71
    .line 72
    iput-boolean v1, p0, Lv3/h0;->t:Z

    .line 73
    .line 74
    :cond_8
    iget-object v0, p0, Lv3/h0;->p:Lv3/o1;

    .line 75
    .line 76
    if-eqz v0, :cond_9

    .line 77
    .line 78
    check-cast v0, Lw3/t;

    .line 79
    .line 80
    invoke-virtual {v0}, Lw3/t;->getRectManager()Le4/a;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    invoke-virtual {v2, p0}, Le4/a;->j(Lv3/h0;)V

    .line 85
    .line 86
    .line 87
    iget-object v0, v0, Lw3/t;->I:Ly2/b;

    .line 88
    .line 89
    if-eqz v0, :cond_9

    .line 90
    .line 91
    iget-object v2, v0, Ly2/b;->h:Landroidx/collection/c0;

    .line 92
    .line 93
    iget v3, p0, Lv3/h0;->e:I

    .line 94
    .line 95
    invoke-virtual {v2, v3}, Landroidx/collection/c0;->e(I)Z

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    if-eqz v2, :cond_9

    .line 100
    .line 101
    iget-object v2, v0, Ly2/b;->a:Lpv/g;

    .line 102
    .line 103
    iget-object v0, v0, Ly2/b;->c:Lw3/t;

    .line 104
    .line 105
    iget p0, p0, Lv3/h0;->e:I

    .line 106
    .line 107
    invoke-virtual {v2, v0, p0, v1}, Lpv/g;->m(Landroid/view/View;IZ)V

    .line 108
    .line 109
    .line 110
    :cond_9
    return-void
.end method

.method public final a0()V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 6
    .line 7
    iget p0, p0, Ln2/b;->f:I

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    :goto_0
    if-ge v1, p0, :cond_1

    .line 11
    .line 12
    aget-object v2, v0, v1

    .line 13
    .line 14
    check-cast v2, Lv3/h0;

    .line 15
    .line 16
    iget-object v3, v2, Lv3/h0;->F:Lv3/f0;

    .line 17
    .line 18
    iput-object v3, v2, Lv3/h0;->E:Lv3/f0;

    .line 19
    .line 20
    sget-object v4, Lv3/f0;->f:Lv3/f0;

    .line 21
    .line 22
    if-eq v3, v4, :cond_0

    .line 23
    .line 24
    invoke-virtual {v2}, Lv3/h0;->a0()V

    .line 25
    .line 26
    .line 27
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    return-void
.end method

.method public final b(Lx2/s;)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lv3/h0;->H:Lg1/q;

    .line 6
    .line 7
    const/16 v7, 0x10

    .line 8
    .line 9
    invoke-virtual {v2, v7}, Lg1/q;->i(I)Z

    .line 10
    .line 11
    .line 12
    move-result v8

    .line 13
    iget-object v3, v2, Lg1/q;->f:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v9, v3

    .line 16
    check-cast v9, Lv3/z1;

    .line 17
    .line 18
    const/16 v10, 0x400

    .line 19
    .line 20
    invoke-virtual {v2, v10}, Lg1/q;->i(I)Z

    .line 21
    .line 22
    .line 23
    move-result v11

    .line 24
    iput-object v1, v0, Lv3/h0;->M:Lx2/s;

    .line 25
    .line 26
    iget-object v3, v2, Lg1/q;->d:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v3, Lv3/u;

    .line 29
    .line 30
    iget-object v4, v2, Lg1/q;->b:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v4, Lv3/h0;

    .line 33
    .line 34
    iget-object v5, v2, Lg1/q;->g:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v5, Lx2/r;

    .line 37
    .line 38
    iget-object v6, v2, Lg1/q;->c:Ljava/lang/Object;

    .line 39
    .line 40
    move-object v12, v6

    .line 41
    check-cast v12, Lv3/b1;

    .line 42
    .line 43
    if-eq v5, v12, :cond_0

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    const-string v5, "padChain called on already padded chain"

    .line 47
    .line 48
    invoke-static {v5}, Ls3/a;->b(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    :goto_0
    iget-object v5, v2, Lg1/q;->g:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v5, Lx2/r;

    .line 54
    .line 55
    iput-object v12, v5, Lx2/r;->h:Lx2/r;

    .line 56
    .line 57
    iput-object v5, v12, Lx2/r;->i:Lx2/r;

    .line 58
    .line 59
    iget-object v5, v2, Lg1/q;->h:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v5, Ln2/b;

    .line 62
    .line 63
    if-eqz v5, :cond_1

    .line 64
    .line 65
    iget v6, v5, Ln2/b;->f:I

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_1
    const/4 v6, 0x0

    .line 69
    :goto_1
    iget-object v14, v2, Lg1/q;->i:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v14, Ln2/b;

    .line 72
    .line 73
    if-nez v14, :cond_2

    .line 74
    .line 75
    new-instance v14, Ln2/b;

    .line 76
    .line 77
    new-array v15, v7, [Lx2/q;

    .line 78
    .line 79
    invoke-direct {v14, v15}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    :cond_2
    iget-object v15, v2, Lg1/q;->j:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v15, Ln2/b;

    .line 85
    .line 86
    invoke-virtual {v15, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    const/16 v16, 0x0

    .line 90
    .line 91
    :goto_2
    iget v1, v15, Ln2/b;->f:I

    .line 92
    .line 93
    if-eqz v1, :cond_6

    .line 94
    .line 95
    add-int/lit8 v1, v1, -0x1

    .line 96
    .line 97
    invoke-virtual {v15, v1}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    check-cast v1, Lx2/s;

    .line 102
    .line 103
    instance-of v13, v1, Lx2/l;

    .line 104
    .line 105
    if-eqz v13, :cond_3

    .line 106
    .line 107
    check-cast v1, Lx2/l;

    .line 108
    .line 109
    iget-object v13, v1, Lx2/l;->c:Lx2/s;

    .line 110
    .line 111
    invoke-virtual {v15, v13}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    iget-object v1, v1, Lx2/l;->b:Lx2/s;

    .line 115
    .line 116
    invoke-virtual {v15, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    goto :goto_4

    .line 120
    :cond_3
    instance-of v13, v1, Lx2/q;

    .line 121
    .line 122
    if-eqz v13, :cond_4

    .line 123
    .line 124
    invoke-virtual {v14, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    goto :goto_4

    .line 128
    :cond_4
    if-nez v16, :cond_5

    .line 129
    .line 130
    new-instance v13, La3/f;

    .line 131
    .line 132
    const/16 v10, 0x1d

    .line 133
    .line 134
    invoke-direct {v13, v14, v10}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 135
    .line 136
    .line 137
    move-object/from16 v16, v13

    .line 138
    .line 139
    goto :goto_3

    .line 140
    :cond_5
    move-object/from16 v13, v16

    .line 141
    .line 142
    :goto_3
    invoke-interface {v1, v13}, Lx2/s;->b(Lay0/k;)Z

    .line 143
    .line 144
    .line 145
    :goto_4
    const/16 v10, 0x400

    .line 146
    .line 147
    goto :goto_2

    .line 148
    :cond_6
    iget v1, v14, Ln2/b;->f:I

    .line 149
    .line 150
    const-string v13, "expected prior modifier list to be non-empty"

    .line 151
    .line 152
    if-ne v1, v6, :cond_11

    .line 153
    .line 154
    iget-object v1, v12, Lx2/r;->i:Lx2/r;

    .line 155
    .line 156
    move-object v3, v2

    .line 157
    const/4 v2, 0x0

    .line 158
    :goto_5
    if-eqz v1, :cond_c

    .line 159
    .line 160
    if-ge v2, v6, :cond_c

    .line 161
    .line 162
    if-eqz v5, :cond_b

    .line 163
    .line 164
    const/16 v16, 0x2

    .line 165
    .line 166
    iget-object v10, v5, Ln2/b;->d:[Ljava/lang/Object;

    .line 167
    .line 168
    aget-object v10, v10, v2

    .line 169
    .line 170
    check-cast v10, Lx2/q;

    .line 171
    .line 172
    iget-object v7, v14, Ln2/b;->d:[Ljava/lang/Object;

    .line 173
    .line 174
    aget-object v7, v7, v2

    .line 175
    .line 176
    check-cast v7, Lx2/q;

    .line 177
    .line 178
    invoke-static {v10, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v17

    .line 182
    if-eqz v17, :cond_7

    .line 183
    .line 184
    move-object/from16 v18, v3

    .line 185
    .line 186
    move/from16 v3, v16

    .line 187
    .line 188
    goto :goto_6

    .line 189
    :cond_7
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 190
    .line 191
    .line 192
    move-result-object v15

    .line 193
    move-object/from16 v18, v3

    .line 194
    .line 195
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 196
    .line 197
    .line 198
    move-result-object v3

    .line 199
    if-ne v15, v3, :cond_8

    .line 200
    .line 201
    const/4 v3, 0x1

    .line 202
    goto :goto_6

    .line 203
    :cond_8
    const/4 v3, 0x0

    .line 204
    :goto_6
    if-eqz v3, :cond_a

    .line 205
    .line 206
    const/4 v15, 0x1

    .line 207
    if-eq v3, v15, :cond_9

    .line 208
    .line 209
    goto :goto_7

    .line 210
    :cond_9
    invoke-static {v10, v7, v1}, Lg1/q;->p(Lx2/q;Lx2/q;Lx2/r;)V

    .line 211
    .line 212
    .line 213
    :goto_7
    iget-object v1, v1, Lx2/r;->i:Lx2/r;

    .line 214
    .line 215
    add-int/lit8 v2, v2, 0x1

    .line 216
    .line 217
    move-object/from16 v3, v18

    .line 218
    .line 219
    const/16 v7, 0x10

    .line 220
    .line 221
    goto :goto_5

    .line 222
    :cond_a
    iget-object v1, v1, Lx2/r;->h:Lx2/r;

    .line 223
    .line 224
    goto :goto_8

    .line 225
    :cond_b
    invoke-static {v13}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    throw v0

    .line 230
    :cond_c
    move-object/from16 v18, v3

    .line 231
    .line 232
    const/16 v16, 0x2

    .line 233
    .line 234
    :goto_8
    if-ge v2, v6, :cond_10

    .line 235
    .line 236
    if-eqz v5, :cond_f

    .line 237
    .line 238
    if-eqz v1, :cond_e

    .line 239
    .line 240
    iget-object v3, v4, Lv3/h0;->N:Lx2/s;

    .line 241
    .line 242
    if-eqz v3, :cond_d

    .line 243
    .line 244
    const/16 v17, 0x1

    .line 245
    .line 246
    :goto_9
    const/4 v15, 0x1

    .line 247
    goto :goto_a

    .line 248
    :cond_d
    const/16 v17, 0x0

    .line 249
    .line 250
    goto :goto_9

    .line 251
    :goto_a
    xor-int/lit8 v6, v17, 0x1

    .line 252
    .line 253
    move-object v3, v5

    .line 254
    move-object v4, v14

    .line 255
    const/4 v7, 0x0

    .line 256
    move-object v5, v1

    .line 257
    move-object/from16 v1, v18

    .line 258
    .line 259
    invoke-virtual/range {v1 .. v6}, Lg1/q;->n(ILn2/b;Ln2/b;Lx2/r;Z)V

    .line 260
    .line 261
    .line 262
    move-object v5, v3

    .line 263
    move-object v5, v12

    .line 264
    :goto_b
    const/4 v15, 0x1

    .line 265
    goto/16 :goto_13

    .line 266
    .line 267
    :cond_e
    const-string v0, "structuralUpdate requires a non-null tail"

    .line 268
    .line 269
    invoke-static {v0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 270
    .line 271
    .line 272
    move-result-object v0

    .line 273
    throw v0

    .line 274
    :cond_f
    invoke-static {v13}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 275
    .line 276
    .line 277
    move-result-object v0

    .line 278
    throw v0

    .line 279
    :cond_10
    move-object/from16 v2, v18

    .line 280
    .line 281
    const/4 v7, 0x0

    .line 282
    goto :goto_10

    .line 283
    :cond_11
    const/4 v7, 0x0

    .line 284
    const/16 v16, 0x2

    .line 285
    .line 286
    iget-object v10, v4, Lv3/h0;->N:Lx2/s;

    .line 287
    .line 288
    if-eqz v10, :cond_14

    .line 289
    .line 290
    if-nez v6, :cond_14

    .line 291
    .line 292
    move-object v3, v12

    .line 293
    const/4 v1, 0x0

    .line 294
    :goto_c
    iget v4, v14, Ln2/b;->f:I

    .line 295
    .line 296
    if-ge v1, v4, :cond_12

    .line 297
    .line 298
    iget-object v4, v14, Ln2/b;->d:[Ljava/lang/Object;

    .line 299
    .line 300
    aget-object v4, v4, v1

    .line 301
    .line 302
    check-cast v4, Lx2/q;

    .line 303
    .line 304
    invoke-static {v4, v3}, Lg1/q;->e(Lx2/q;Lx2/r;)Lx2/r;

    .line 305
    .line 306
    .line 307
    move-result-object v3

    .line 308
    add-int/lit8 v1, v1, 0x1

    .line 309
    .line 310
    goto :goto_c

    .line 311
    :cond_12
    iget-object v1, v9, Lx2/r;->h:Lx2/r;

    .line 312
    .line 313
    const/4 v3, 0x0

    .line 314
    :goto_d
    if-eqz v1, :cond_13

    .line 315
    .line 316
    if-eq v1, v12, :cond_13

    .line 317
    .line 318
    iget v4, v1, Lx2/r;->f:I

    .line 319
    .line 320
    or-int/2addr v3, v4

    .line 321
    iput v3, v1, Lx2/r;->g:I

    .line 322
    .line 323
    iget-object v1, v1, Lx2/r;->h:Lx2/r;

    .line 324
    .line 325
    goto :goto_d

    .line 326
    :cond_13
    move-object v1, v2

    .line 327
    move-object v3, v5

    .line 328
    move-object v5, v12

    .line 329
    move-object v4, v14

    .line 330
    goto :goto_b

    .line 331
    :cond_14
    if-nez v1, :cond_18

    .line 332
    .line 333
    if-eqz v5, :cond_17

    .line 334
    .line 335
    iget-object v1, v12, Lx2/r;->i:Lx2/r;

    .line 336
    .line 337
    const/4 v6, 0x0

    .line 338
    :goto_e
    if-eqz v1, :cond_15

    .line 339
    .line 340
    iget v10, v5, Ln2/b;->f:I

    .line 341
    .line 342
    if-ge v6, v10, :cond_15

    .line 343
    .line 344
    invoke-static {v1}, Lg1/q;->f(Lx2/r;)Lx2/r;

    .line 345
    .line 346
    .line 347
    move-result-object v1

    .line 348
    iget-object v1, v1, Lx2/r;->i:Lx2/r;

    .line 349
    .line 350
    add-int/lit8 v6, v6, 0x1

    .line 351
    .line 352
    goto :goto_e

    .line 353
    :cond_15
    invoke-virtual {v4}, Lv3/h0;->v()Lv3/h0;

    .line 354
    .line 355
    .line 356
    move-result-object v1

    .line 357
    if-eqz v1, :cond_16

    .line 358
    .line 359
    iget-object v1, v1, Lv3/h0;->H:Lg1/q;

    .line 360
    .line 361
    iget-object v1, v1, Lg1/q;->d:Ljava/lang/Object;

    .line 362
    .line 363
    check-cast v1, Lv3/u;

    .line 364
    .line 365
    goto :goto_f

    .line 366
    :cond_16
    move-object v1, v7

    .line 367
    :goto_f
    iput-object v1, v3, Lv3/f1;->t:Lv3/f1;

    .line 368
    .line 369
    iput-object v3, v2, Lg1/q;->e:Ljava/lang/Object;

    .line 370
    .line 371
    :goto_10
    move-object v1, v2

    .line 372
    move-object v3, v5

    .line 373
    move-object v5, v12

    .line 374
    move-object v4, v14

    .line 375
    const/4 v15, 0x0

    .line 376
    goto :goto_13

    .line 377
    :cond_17
    invoke-static {v13}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 378
    .line 379
    .line 380
    move-result-object v0

    .line 381
    throw v0

    .line 382
    :cond_18
    if-nez v5, :cond_19

    .line 383
    .line 384
    new-instance v5, Ln2/b;

    .line 385
    .line 386
    const/16 v1, 0x10

    .line 387
    .line 388
    new-array v3, v1, [Lx2/q;

    .line 389
    .line 390
    invoke-direct {v5, v3}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 391
    .line 392
    .line 393
    :cond_19
    move-object v3, v5

    .line 394
    if-eqz v10, :cond_1a

    .line 395
    .line 396
    const/4 v15, 0x1

    .line 397
    :goto_11
    const/16 v17, 0x1

    .line 398
    .line 399
    goto :goto_12

    .line 400
    :cond_1a
    const/4 v15, 0x0

    .line 401
    goto :goto_11

    .line 402
    :goto_12
    xor-int/lit8 v6, v15, 0x1

    .line 403
    .line 404
    move-object v1, v2

    .line 405
    const/4 v2, 0x0

    .line 406
    move-object v5, v12

    .line 407
    move-object v4, v14

    .line 408
    invoke-virtual/range {v1 .. v6}, Lg1/q;->n(ILn2/b;Ln2/b;Lx2/r;Z)V

    .line 409
    .line 410
    .line 411
    move/from16 v15, v17

    .line 412
    .line 413
    :goto_13
    iput-object v4, v1, Lg1/q;->h:Ljava/lang/Object;

    .line 414
    .line 415
    if-eqz v3, :cond_1b

    .line 416
    .line 417
    invoke-virtual {v3}, Ln2/b;->i()V

    .line 418
    .line 419
    .line 420
    goto :goto_14

    .line 421
    :cond_1b
    move-object v3, v7

    .line 422
    :goto_14
    iput-object v3, v1, Lg1/q;->i:Ljava/lang/Object;

    .line 423
    .line 424
    iget-object v2, v5, Lx2/r;->i:Lx2/r;

    .line 425
    .line 426
    if-nez v2, :cond_1c

    .line 427
    .line 428
    goto :goto_15

    .line 429
    :cond_1c
    move-object v9, v2

    .line 430
    :goto_15
    iput-object v7, v9, Lx2/r;->h:Lx2/r;

    .line 431
    .line 432
    iput-object v7, v5, Lx2/r;->i:Lx2/r;

    .line 433
    .line 434
    const/4 v2, -0x1

    .line 435
    iput v2, v5, Lx2/r;->g:I

    .line 436
    .line 437
    iput-object v7, v5, Lx2/r;->k:Lv3/f1;

    .line 438
    .line 439
    if-eq v9, v5, :cond_1d

    .line 440
    .line 441
    goto :goto_16

    .line 442
    :cond_1d
    const-string v2, "trimChain did not update the head"

    .line 443
    .line 444
    invoke-static {v2}, Ls3/a;->b(Ljava/lang/String;)V

    .line 445
    .line 446
    .line 447
    :goto_16
    iput-object v9, v1, Lg1/q;->g:Ljava/lang/Object;

    .line 448
    .line 449
    if-eqz v15, :cond_1e

    .line 450
    .line 451
    invoke-virtual {v1}, Lg1/q;->o()V

    .line 452
    .line 453
    .line 454
    :cond_1e
    const/16 v2, 0x10

    .line 455
    .line 456
    invoke-virtual {v1, v2}, Lg1/q;->i(I)Z

    .line 457
    .line 458
    .line 459
    move-result v2

    .line 460
    const/16 v3, 0x400

    .line 461
    .line 462
    invoke-virtual {v1, v3}, Lg1/q;->i(I)Z

    .line 463
    .line 464
    .line 465
    move-result v3

    .line 466
    iget-object v4, v0, Lv3/h0;->I:Lv3/l0;

    .line 467
    .line 468
    invoke-virtual {v4}, Lv3/l0;->j()V

    .line 469
    .line 470
    .line 471
    iget-object v4, v0, Lv3/h0;->j:Lv3/h0;

    .line 472
    .line 473
    if-nez v4, :cond_1f

    .line 474
    .line 475
    const/16 v4, 0x200

    .line 476
    .line 477
    invoke-virtual {v1, v4}, Lg1/q;->i(I)Z

    .line 478
    .line 479
    .line 480
    move-result v1

    .line 481
    if-eqz v1, :cond_1f

    .line 482
    .line 483
    invoke-virtual {v0, v0}, Lv3/h0;->g0(Lv3/h0;)V

    .line 484
    .line 485
    .line 486
    :cond_1f
    if-ne v8, v2, :cond_20

    .line 487
    .line 488
    if-eq v11, v3, :cond_22

    .line 489
    .line 490
    :cond_20
    invoke-static {v0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 491
    .line 492
    .line 493
    move-result-object v1

    .line 494
    check-cast v1, Lw3/t;

    .line 495
    .line 496
    invoke-virtual {v1}, Lw3/t;->getRectManager()Le4/a;

    .line 497
    .line 498
    .line 499
    move-result-object v1

    .line 500
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 501
    .line 502
    .line 503
    invoke-virtual {v0}, Lv3/h0;->I()Z

    .line 504
    .line 505
    .line 506
    move-result v4

    .line 507
    if-eqz v4, :cond_22

    .line 508
    .line 509
    iget-object v1, v1, Le4/a;->a:Lbb/g0;

    .line 510
    .line 511
    iget v0, v0, Lv3/h0;->e:I

    .line 512
    .line 513
    const v4, 0x3ffffff

    .line 514
    .line 515
    .line 516
    and-int/2addr v0, v4

    .line 517
    iget-object v5, v1, Lbb/g0;->f:Ljava/lang/Object;

    .line 518
    .line 519
    check-cast v5, [J

    .line 520
    .line 521
    iget v1, v1, Lbb/g0;->e:I

    .line 522
    .line 523
    const/4 v13, 0x0

    .line 524
    :goto_17
    array-length v6, v5

    .line 525
    add-int/lit8 v6, v6, -0x2

    .line 526
    .line 527
    if-ge v13, v6, :cond_22

    .line 528
    .line 529
    if-ge v13, v1, :cond_22

    .line 530
    .line 531
    add-int/lit8 v6, v13, 0x2

    .line 532
    .line 533
    aget-wide v7, v5, v6

    .line 534
    .line 535
    long-to-int v9, v7

    .line 536
    and-int/2addr v9, v4

    .line 537
    if-ne v9, v0, :cond_21

    .line 538
    .line 539
    const-wide v0, 0x3fffffffffffffffL    # 1.9999999999999998

    .line 540
    .line 541
    .line 542
    .line 543
    .line 544
    and-long/2addr v0, v7

    .line 545
    const-wide/high16 v7, 0x4000000000000000L    # 2.0

    .line 546
    .line 547
    int-to-long v3, v3

    .line 548
    mul-long/2addr v3, v7

    .line 549
    or-long/2addr v0, v3

    .line 550
    const-wide/high16 v3, -0x8000000000000000L

    .line 551
    .line 552
    int-to-long v7, v2

    .line 553
    mul-long/2addr v7, v3

    .line 554
    or-long/2addr v0, v7

    .line 555
    aput-wide v0, v5, v6

    .line 556
    .line 557
    return-void

    .line 558
    :cond_21
    add-int/lit8 v13, v13, 0x3

    .line 559
    .line 560
    goto :goto_17

    .line 561
    :cond_22
    return-void
.end method

.method public final b0(Ljava/lang/Throwable;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lv3/h0;->D:Ll2/c0;

    .line 2
    .line 3
    sget-object v1, Lw2/c;->a:Ll2/u2;

    .line 4
    .line 5
    check-cast v0, Lt2/g;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    invoke-static {v0, v1}, Ll2/b;->q(Ll2/p1;Ll2/s1;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Lw2/b;

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    new-instance v1, Lvu/d;

    .line 19
    .line 20
    const/4 v2, 0x4

    .line 21
    invoke-direct {v1, v2, v0, p0}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    invoke-static {p1, v1}, Llp/tc;->c(Ljava/lang/Throwable;Lay0/a;)Z

    .line 25
    .line 26
    .line 27
    :cond_0
    throw p1
.end method

.method public final c(Lv3/o1;)V
    .locals 9

    .line 1
    iget-object v0, p0, Lv3/h0;->p:Lv3/o1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v2, "Cannot attach "

    .line 10
    .line 11
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v2, " as it already is attached.  Tree: "

    .line 18
    .line 19
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v1}, Lv3/h0;->h(I)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    :goto_0
    iget-object v0, p0, Lv3/h0;->o:Lv3/h0;

    .line 37
    .line 38
    const/4 v2, 0x0

    .line 39
    if-eqz v0, :cond_4

    .line 40
    .line 41
    iget-object v0, v0, Lv3/h0;->p:Lv3/o1;

    .line 42
    .line 43
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_1

    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string v3, "Attaching to a different owner("

    .line 53
    .line 54
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v3, ") than the parent\'s owner("

    .line 61
    .line 62
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    if-eqz v3, :cond_2

    .line 70
    .line 71
    iget-object v3, v3, Lv3/h0;->p:Lv3/o1;

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_2
    move-object v3, v2

    .line 75
    :goto_1
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    const-string v3, "). This tree: "

    .line 79
    .line 80
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {p0, v1}, Lv3/h0;->h(I)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v3

    .line 87
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    const-string v3, " Parent tree: "

    .line 91
    .line 92
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    iget-object v3, p0, Lv3/h0;->o:Lv3/h0;

    .line 96
    .line 97
    if-eqz v3, :cond_3

    .line 98
    .line 99
    invoke-virtual {v3, v1}, Lv3/h0;->h(I)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    goto :goto_2

    .line 104
    :cond_3
    move-object v3, v2

    .line 105
    :goto_2
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    :cond_4
    :goto_3
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    iget-object v3, p0, Lv3/h0;->I:Lv3/l0;

    .line 120
    .line 121
    const/4 v4, 0x1

    .line 122
    if-nez v0, :cond_5

    .line 123
    .line 124
    iget-object v5, v3, Lv3/l0;->p:Lv3/y0;

    .line 125
    .line 126
    iput-boolean v4, v5, Lv3/y0;->w:Z

    .line 127
    .line 128
    iget-object v5, v3, Lv3/l0;->q:Lv3/u0;

    .line 129
    .line 130
    if-eqz v5, :cond_5

    .line 131
    .line 132
    sget-object v6, Lv3/r0;->d:Lv3/r0;

    .line 133
    .line 134
    iput-object v6, v5, Lv3/u0;->u:Lv3/r0;

    .line 135
    .line 136
    :cond_5
    iget-object v5, p0, Lv3/h0;->H:Lg1/q;

    .line 137
    .line 138
    iget-object v6, v5, Lg1/q;->e:Ljava/lang/Object;

    .line 139
    .line 140
    check-cast v6, Lv3/f1;

    .line 141
    .line 142
    if-eqz v0, :cond_6

    .line 143
    .line 144
    iget-object v7, v0, Lv3/h0;->H:Lg1/q;

    .line 145
    .line 146
    iget-object v7, v7, Lg1/q;->d:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v7, Lv3/u;

    .line 149
    .line 150
    goto :goto_4

    .line 151
    :cond_6
    move-object v7, v2

    .line 152
    :goto_4
    iput-object v7, v6, Lv3/f1;->t:Lv3/f1;

    .line 153
    .line 154
    iput-object p1, p0, Lv3/h0;->p:Lv3/o1;

    .line 155
    .line 156
    if-eqz v0, :cond_7

    .line 157
    .line 158
    iget v6, v0, Lv3/h0;->r:I

    .line 159
    .line 160
    goto :goto_5

    .line 161
    :cond_7
    const/4 v6, -0x1

    .line 162
    :goto_5
    add-int/2addr v6, v4

    .line 163
    iput v6, p0, Lv3/h0;->r:I

    .line 164
    .line 165
    iget-object v6, p0, Lv3/h0;->N:Lx2/s;

    .line 166
    .line 167
    if-eqz v6, :cond_8

    .line 168
    .line 169
    invoke-virtual {p0, v6}, Lv3/h0;->b(Lx2/s;)V

    .line 170
    .line 171
    .line 172
    :cond_8
    iput-object v2, p0, Lv3/h0;->N:Lx2/s;

    .line 173
    .line 174
    move-object v2, p1

    .line 175
    check-cast v2, Lw3/t;

    .line 176
    .line 177
    invoke-virtual {v2}, Lw3/t;->getLayoutNodes()Landroidx/collection/b0;

    .line 178
    .line 179
    .line 180
    move-result-object v6

    .line 181
    iget v7, p0, Lv3/h0;->e:I

    .line 182
    .line 183
    invoke-virtual {v6, v7, p0}, Landroidx/collection/b0;->h(ILjava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    iget-object v6, p0, Lv3/h0;->o:Lv3/h0;

    .line 187
    .line 188
    if-eqz v6, :cond_9

    .line 189
    .line 190
    iget-object v6, v6, Lv3/h0;->j:Lv3/h0;

    .line 191
    .line 192
    if-nez v6, :cond_a

    .line 193
    .line 194
    :cond_9
    iget-object v6, p0, Lv3/h0;->j:Lv3/h0;

    .line 195
    .line 196
    :cond_a
    invoke-virtual {p0, v6}, Lv3/h0;->g0(Lv3/h0;)V

    .line 197
    .line 198
    .line 199
    iget-object v6, p0, Lv3/h0;->j:Lv3/h0;

    .line 200
    .line 201
    if-nez v6, :cond_b

    .line 202
    .line 203
    const/16 v6, 0x200

    .line 204
    .line 205
    invoke-virtual {v5, v6}, Lg1/q;->i(I)Z

    .line 206
    .line 207
    .line 208
    move-result v6

    .line 209
    if-eqz v6, :cond_b

    .line 210
    .line 211
    invoke-virtual {p0, p0}, Lv3/h0;->g0(Lv3/h0;)V

    .line 212
    .line 213
    .line 214
    :cond_b
    iget-boolean v6, p0, Lv3/h0;->S:Z

    .line 215
    .line 216
    if-nez v6, :cond_c

    .line 217
    .line 218
    iget-object v6, v5, Lg1/q;->g:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast v6, Lx2/r;

    .line 221
    .line 222
    :goto_6
    if-eqz v6, :cond_c

    .line 223
    .line 224
    invoke-virtual {v6}, Lx2/r;->N0()V

    .line 225
    .line 226
    .line 227
    iget-object v6, v6, Lx2/r;->i:Lx2/r;

    .line 228
    .line 229
    goto :goto_6

    .line 230
    :cond_c
    iget-object v6, p0, Lv3/h0;->l:Lc2/k;

    .line 231
    .line 232
    iget-object v6, v6, Lc2/k;->e:Ljava/lang/Object;

    .line 233
    .line 234
    check-cast v6, Ln2/b;

    .line 235
    .line 236
    iget-object v7, v6, Ln2/b;->d:[Ljava/lang/Object;

    .line 237
    .line 238
    iget v6, v6, Ln2/b;->f:I

    .line 239
    .line 240
    :goto_7
    if-ge v1, v6, :cond_d

    .line 241
    .line 242
    aget-object v8, v7, v1

    .line 243
    .line 244
    check-cast v8, Lv3/h0;

    .line 245
    .line 246
    invoke-virtual {v8, p1}, Lv3/h0;->c(Lv3/o1;)V

    .line 247
    .line 248
    .line 249
    add-int/lit8 v1, v1, 0x1

    .line 250
    .line 251
    goto :goto_7

    .line 252
    :cond_d
    iget-boolean v1, p0, Lv3/h0;->S:Z

    .line 253
    .line 254
    if-nez v1, :cond_e

    .line 255
    .line 256
    invoke-virtual {v5}, Lg1/q;->l()V

    .line 257
    .line 258
    .line 259
    :cond_e
    invoke-virtual {p0}, Lv3/h0;->E()V

    .line 260
    .line 261
    .line 262
    if-eqz v0, :cond_f

    .line 263
    .line 264
    invoke-virtual {v0}, Lv3/h0;->E()V

    .line 265
    .line 266
    .line 267
    :cond_f
    iget-object v0, p0, Lv3/h0;->O:Lw4/c;

    .line 268
    .line 269
    if-eqz v0, :cond_10

    .line 270
    .line 271
    invoke-virtual {v0, p1}, Lw4/c;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    :cond_10
    invoke-virtual {v3}, Lv3/l0;->j()V

    .line 275
    .line 276
    .line 277
    iget-boolean p1, p0, Lv3/h0;->S:Z

    .line 278
    .line 279
    if-nez p1, :cond_11

    .line 280
    .line 281
    const/16 p1, 0x8

    .line 282
    .line 283
    invoke-virtual {v5, p1}, Lg1/q;->i(I)Z

    .line 284
    .line 285
    .line 286
    move-result p1

    .line 287
    if-eqz p1, :cond_11

    .line 288
    .line 289
    invoke-virtual {p0}, Lv3/h0;->G()V

    .line 290
    .line 291
    .line 292
    :cond_11
    iget-object p1, v2, Lw3/t;->I:Ly2/b;

    .line 293
    .line 294
    if-eqz p1, :cond_12

    .line 295
    .line 296
    invoke-virtual {p0}, Lv3/h0;->x()Ld4/l;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    if-eqz v0, :cond_12

    .line 301
    .line 302
    iget-object v0, v0, Ld4/l;->d:Landroidx/collection/q0;

    .line 303
    .line 304
    sget-object v1, Ld4/v;->q:Ld4/z;

    .line 305
    .line 306
    invoke-virtual {v0, v1}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 307
    .line 308
    .line 309
    move-result v0

    .line 310
    if-ne v0, v4, :cond_12

    .line 311
    .line 312
    iget-object v0, p1, Ly2/b;->h:Landroidx/collection/c0;

    .line 313
    .line 314
    iget v1, p0, Lv3/h0;->e:I

    .line 315
    .line 316
    invoke-virtual {v0, v1}, Landroidx/collection/c0;->a(I)Z

    .line 317
    .line 318
    .line 319
    iget-object v0, p1, Ly2/b;->a:Lpv/g;

    .line 320
    .line 321
    iget-object p1, p1, Ly2/b;->c:Lw3/t;

    .line 322
    .line 323
    iget p0, p0, Lv3/h0;->e:I

    .line 324
    .line 325
    invoke-virtual {v0, p1, p0, v4}, Lpv/g;->m(Landroid/view/View;IZ)V

    .line 326
    .line 327
    .line 328
    :cond_12
    return-void
.end method

.method public final c0(Ll2/c0;)V
    .locals 7

    .line 1
    iput-object p1, p0, Lv3/h0;->D:Ll2/c0;

    .line 2
    .line 3
    sget-object v0, Lw3/h1;->h:Ll2/u2;

    .line 4
    .line 5
    check-cast p1, Lt2/g;

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    invoke-static {p1, v0}, Ll2/b;->q(Ll2/p1;Ll2/s1;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Lt4/c;

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lv3/h0;->d0(Lt4/c;)V

    .line 17
    .line 18
    .line 19
    sget-object v0, Lw3/h1;->n:Ll2/u2;

    .line 20
    .line 21
    invoke-static {p1, v0}, Ll2/b;->q(Ll2/p1;Ll2/s1;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Lt4/m;

    .line 26
    .line 27
    iget-object v1, p0, Lv3/h0;->B:Lt4/m;

    .line 28
    .line 29
    iget-object v2, p0, Lv3/h0;->H:Lg1/q;

    .line 30
    .line 31
    if-eq v1, v0, :cond_1

    .line 32
    .line 33
    iput-object v0, p0, Lv3/h0;->B:Lt4/m;

    .line 34
    .line 35
    invoke-virtual {p0}, Lv3/h0;->E()V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    if-eqz v0, :cond_0

    .line 43
    .line 44
    invoke-virtual {v0}, Lv3/h0;->C()V

    .line 45
    .line 46
    .line 47
    :cond_0
    invoke-virtual {p0}, Lv3/h0;->D()V

    .line 48
    .line 49
    .line 50
    iget-object v0, v2, Lg1/q;->g:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v0, Lx2/r;

    .line 53
    .line 54
    :goto_0
    if-eqz v0, :cond_1

    .line 55
    .line 56
    invoke-interface {v0}, Lv3/m;->E()V

    .line 57
    .line 58
    .line 59
    iget-object v0, v0, Lx2/r;->i:Lx2/r;

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_1
    sget-object v0, Lw3/h1;->s:Ll2/u2;

    .line 63
    .line 64
    invoke-static {p1, v0}, Ll2/b;->q(Ll2/p1;Ll2/s1;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    check-cast p1, Lw3/h2;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lv3/h0;->j0(Lw3/h2;)V

    .line 71
    .line 72
    .line 73
    iget-object p0, v2, Lg1/q;->g:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast p0, Lx2/r;

    .line 76
    .line 77
    iget p1, p0, Lx2/r;->g:I

    .line 78
    .line 79
    const v0, 0x8000

    .line 80
    .line 81
    .line 82
    and-int/2addr p1, v0

    .line 83
    if-eqz p1, :cond_b

    .line 84
    .line 85
    :goto_1
    if-eqz p0, :cond_b

    .line 86
    .line 87
    iget p1, p0, Lx2/r;->f:I

    .line 88
    .line 89
    and-int/2addr p1, v0

    .line 90
    if-eqz p1, :cond_a

    .line 91
    .line 92
    const/4 p1, 0x0

    .line 93
    move-object v1, p0

    .line 94
    move-object v2, p1

    .line 95
    :goto_2
    if-eqz v1, :cond_a

    .line 96
    .line 97
    instance-of v3, v1, Lv3/l;

    .line 98
    .line 99
    const/4 v4, 0x1

    .line 100
    if-eqz v3, :cond_3

    .line 101
    .line 102
    check-cast v1, Lv3/l;

    .line 103
    .line 104
    check-cast v1, Lx2/r;

    .line 105
    .line 106
    iget-object v1, v1, Lx2/r;->d:Lx2/r;

    .line 107
    .line 108
    iget-boolean v3, v1, Lx2/r;->q:Z

    .line 109
    .line 110
    if-eqz v3, :cond_2

    .line 111
    .line 112
    invoke-static {v1}, Lv3/g1;->c(Lx2/r;)V

    .line 113
    .line 114
    .line 115
    goto :goto_5

    .line 116
    :cond_2
    iput-boolean v4, v1, Lx2/r;->m:Z

    .line 117
    .line 118
    goto :goto_5

    .line 119
    :cond_3
    iget v3, v1, Lx2/r;->f:I

    .line 120
    .line 121
    and-int/2addr v3, v0

    .line 122
    if-eqz v3, :cond_9

    .line 123
    .line 124
    instance-of v3, v1, Lv3/n;

    .line 125
    .line 126
    if-eqz v3, :cond_9

    .line 127
    .line 128
    move-object v3, v1

    .line 129
    check-cast v3, Lv3/n;

    .line 130
    .line 131
    iget-object v3, v3, Lv3/n;->s:Lx2/r;

    .line 132
    .line 133
    const/4 v5, 0x0

    .line 134
    :goto_3
    if-eqz v3, :cond_8

    .line 135
    .line 136
    iget v6, v3, Lx2/r;->f:I

    .line 137
    .line 138
    and-int/2addr v6, v0

    .line 139
    if-eqz v6, :cond_7

    .line 140
    .line 141
    add-int/lit8 v5, v5, 0x1

    .line 142
    .line 143
    if-ne v5, v4, :cond_4

    .line 144
    .line 145
    move-object v1, v3

    .line 146
    goto :goto_4

    .line 147
    :cond_4
    if-nez v2, :cond_5

    .line 148
    .line 149
    new-instance v2, Ln2/b;

    .line 150
    .line 151
    const/16 v6, 0x10

    .line 152
    .line 153
    new-array v6, v6, [Lx2/r;

    .line 154
    .line 155
    invoke-direct {v2, v6}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    :cond_5
    if-eqz v1, :cond_6

    .line 159
    .line 160
    invoke-virtual {v2, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    move-object v1, p1

    .line 164
    :cond_6
    invoke-virtual {v2, v3}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    :cond_7
    :goto_4
    iget-object v3, v3, Lx2/r;->i:Lx2/r;

    .line 168
    .line 169
    goto :goto_3

    .line 170
    :cond_8
    if-ne v5, v4, :cond_9

    .line 171
    .line 172
    goto :goto_2

    .line 173
    :cond_9
    :goto_5
    invoke-static {v2}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    goto :goto_2

    .line 178
    :cond_a
    iget p1, p0, Lx2/r;->g:I

    .line 179
    .line 180
    and-int/2addr p1, v0

    .line 181
    if-eqz p1, :cond_b

    .line 182
    .line 183
    iget-object p0, p0, Lx2/r;->i:Lx2/r;

    .line 184
    .line 185
    goto :goto_1

    .line 186
    :cond_b
    return-void
.end method

.method public final d()V
    .locals 5

    .line 1
    iget-object v0, p0, Lv3/h0;->E:Lv3/f0;

    .line 2
    .line 3
    iput-object v0, p0, Lv3/h0;->F:Lv3/f0;

    .line 4
    .line 5
    sget-object v0, Lv3/f0;->f:Lv3/f0;

    .line 6
    .line 7
    iput-object v0, p0, Lv3/h0;->E:Lv3/f0;

    .line 8
    .line 9
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 14
    .line 15
    iget p0, p0, Ln2/b;->f:I

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    :goto_0
    if-ge v1, p0, :cond_1

    .line 19
    .line 20
    aget-object v2, v0, v1

    .line 21
    .line 22
    check-cast v2, Lv3/h0;

    .line 23
    .line 24
    iget-object v3, v2, Lv3/h0;->E:Lv3/f0;

    .line 25
    .line 26
    sget-object v4, Lv3/f0;->f:Lv3/f0;

    .line 27
    .line 28
    if-eq v3, v4, :cond_0

    .line 29
    .line 30
    invoke-virtual {v2}, Lv3/h0;->d()V

    .line 31
    .line 32
    .line 33
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    return-void
.end method

.method public final d0(Lt4/c;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/h0;->A:Lt4/c;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iput-object p1, p0, Lv3/h0;->A:Lt4/c;

    .line 10
    .line 11
    invoke-virtual {p0}, Lv3/h0;->E()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    invoke-virtual {p1}, Lv3/h0;->C()V

    .line 21
    .line 22
    .line 23
    :cond_0
    invoke-virtual {p0}, Lv3/h0;->D()V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 27
    .line 28
    iget-object p0, p0, Lg1/q;->g:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p0, Lx2/r;

    .line 31
    .line 32
    :goto_0
    if-eqz p0, :cond_1

    .line 33
    .line 34
    invoke-interface {p0}, Lv3/m;->d()V

    .line 35
    .line 36
    .line 37
    iget-object p0, p0, Lx2/r;->i:Lx2/r;

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    return-void
.end method

.method public final e()V
    .locals 8

    .line 1
    invoke-virtual {p0}, Lv3/h0;->I()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-string v0, "onReuse is only expected on attached node"

    .line 8
    .line 9
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, Lv3/h0;->q:Lw4/o;

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    invoke-virtual {v0}, Lw4/g;->e()V

    .line 17
    .line 18
    .line 19
    :cond_1
    iget-object v0, p0, Lv3/h0;->J:Lt3/m0;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Lt3/m0;->g(Z)V

    .line 25
    .line 26
    .line 27
    :cond_2
    iput-boolean v1, p0, Lv3/h0;->v:Z

    .line 28
    .line 29
    iget-boolean v0, p0, Lv3/h0;->S:Z

    .line 30
    .line 31
    iget-object v2, p0, Lv3/h0;->H:Lg1/q;

    .line 32
    .line 33
    if-eqz v0, :cond_3

    .line 34
    .line 35
    iput-boolean v1, p0, Lv3/h0;->S:Z

    .line 36
    .line 37
    goto :goto_3

    .line 38
    :cond_3
    iget-object v0, v2, Lg1/q;->f:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v0, Lv3/z1;

    .line 41
    .line 42
    move-object v3, v0

    .line 43
    :goto_0
    if-eqz v3, :cond_5

    .line 44
    .line 45
    iget-boolean v4, v3, Lx2/r;->q:Z

    .line 46
    .line 47
    if-eqz v4, :cond_4

    .line 48
    .line 49
    invoke-virtual {v3}, Lx2/r;->S0()V

    .line 50
    .line 51
    .line 52
    :cond_4
    iget-object v3, v3, Lx2/r;->h:Lx2/r;

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_5
    move-object v3, v0

    .line 56
    :goto_1
    if-eqz v3, :cond_7

    .line 57
    .line 58
    iget-boolean v4, v3, Lx2/r;->q:Z

    .line 59
    .line 60
    if-eqz v4, :cond_6

    .line 61
    .line 62
    invoke-virtual {v3}, Lx2/r;->U0()V

    .line 63
    .line 64
    .line 65
    :cond_6
    iget-object v3, v3, Lx2/r;->h:Lx2/r;

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_7
    :goto_2
    if-eqz v0, :cond_9

    .line 69
    .line 70
    iget-boolean v3, v0, Lx2/r;->q:Z

    .line 71
    .line 72
    if-eqz v3, :cond_8

    .line 73
    .line 74
    invoke-virtual {v0}, Lx2/r;->O0()V

    .line 75
    .line 76
    .line 77
    :cond_8
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_9
    :goto_3
    iget v0, p0, Lv3/h0;->e:I

    .line 81
    .line 82
    sget-object v3, Ld4/n;->a:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 83
    .line 84
    const/4 v4, 0x1

    .line 85
    invoke-virtual {v3, v4}, Ljava/util/concurrent/atomic/AtomicInteger;->addAndGet(I)I

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    iput v3, p0, Lv3/h0;->e:I

    .line 90
    .line 91
    iget-object v3, p0, Lv3/h0;->p:Lv3/o1;

    .line 92
    .line 93
    if-eqz v3, :cond_a

    .line 94
    .line 95
    check-cast v3, Lw3/t;

    .line 96
    .line 97
    invoke-virtual {v3}, Lw3/t;->getLayoutNodes()Landroidx/collection/b0;

    .line 98
    .line 99
    .line 100
    move-result-object v5

    .line 101
    invoke-virtual {v5, v0}, Landroidx/collection/b0;->g(I)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    invoke-virtual {v3}, Lw3/t;->getLayoutNodes()Landroidx/collection/b0;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    iget v5, p0, Lv3/h0;->e:I

    .line 109
    .line 110
    invoke-virtual {v3, v5, p0}, Landroidx/collection/b0;->h(ILjava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    :cond_a
    iget-object v3, v2, Lg1/q;->g:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v3, Lx2/r;

    .line 116
    .line 117
    :goto_4
    if-eqz v3, :cond_b

    .line 118
    .line 119
    invoke-virtual {v3}, Lx2/r;->N0()V

    .line 120
    .line 121
    .line 122
    iget-object v3, v3, Lx2/r;->i:Lx2/r;

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_b
    invoke-virtual {v2}, Lg1/q;->l()V

    .line 126
    .line 127
    .line 128
    const/16 v3, 0x8

    .line 129
    .line 130
    invoke-virtual {v2, v3}, Lg1/q;->i(I)Z

    .line 131
    .line 132
    .line 133
    move-result v2

    .line 134
    if-eqz v2, :cond_c

    .line 135
    .line 136
    invoke-virtual {p0}, Lv3/h0;->G()V

    .line 137
    .line 138
    .line 139
    :cond_c
    invoke-static {p0}, Lv3/h0;->Z(Lv3/h0;)V

    .line 140
    .line 141
    .line 142
    iget-object v2, p0, Lv3/h0;->p:Lv3/o1;

    .line 143
    .line 144
    if-eqz v2, :cond_f

    .line 145
    .line 146
    check-cast v2, Lw3/t;

    .line 147
    .line 148
    iget-object v3, v2, Lw3/t;->I:Ly2/b;

    .line 149
    .line 150
    if-eqz v3, :cond_e

    .line 151
    .line 152
    iget-object v5, v3, Ly2/b;->c:Lw3/t;

    .line 153
    .line 154
    iget-object v6, v3, Ly2/b;->a:Lpv/g;

    .line 155
    .line 156
    iget-object v3, v3, Ly2/b;->h:Landroidx/collection/c0;

    .line 157
    .line 158
    invoke-virtual {v3, v0}, Landroidx/collection/c0;->e(I)Z

    .line 159
    .line 160
    .line 161
    move-result v7

    .line 162
    if-eqz v7, :cond_d

    .line 163
    .line 164
    invoke-virtual {v6, v5, v0, v1}, Lpv/g;->m(Landroid/view/View;IZ)V

    .line 165
    .line 166
    .line 167
    :cond_d
    invoke-virtual {p0}, Lv3/h0;->x()Ld4/l;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    if-eqz v0, :cond_e

    .line 172
    .line 173
    iget-object v0, v0, Ld4/l;->d:Landroidx/collection/q0;

    .line 174
    .line 175
    sget-object v1, Ld4/v;->q:Ld4/z;

    .line 176
    .line 177
    invoke-virtual {v0, v1}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v0

    .line 181
    if-ne v0, v4, :cond_e

    .line 182
    .line 183
    iget v0, p0, Lv3/h0;->e:I

    .line 184
    .line 185
    invoke-virtual {v3, v0}, Landroidx/collection/c0;->a(I)Z

    .line 186
    .line 187
    .line 188
    iget v0, p0, Lv3/h0;->e:I

    .line 189
    .line 190
    invoke-virtual {v6, v5, v0, v4}, Lpv/g;->m(Landroid/view/View;IZ)V

    .line 191
    .line 192
    .line 193
    :cond_e
    invoke-virtual {v2}, Lw3/t;->getRectManager()Le4/a;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    invoke-virtual {v0, p0, v4}, Le4/a;->g(Lv3/h0;Z)V

    .line 198
    .line 199
    .line 200
    :cond_f
    return-void
.end method

.method public final e0()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv3/h0;->I()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final f()V
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/h0;->q:Lw4/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lw4/g;->f()V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object v0, p0, Lv3/h0;->J:Lt3/m0;

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    invoke-virtual {v0}, Lt3/m0;->f()V

    .line 13
    .line 14
    .line 15
    :cond_1
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 16
    .line 17
    iget-object v0, p0, Lg1/q;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lv3/f1;

    .line 20
    .line 21
    iget-object p0, p0, Lg1/q;->d:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lv3/u;

    .line 24
    .line 25
    iget-object p0, p0, Lv3/f1;->s:Lv3/f1;

    .line 26
    .line 27
    :goto_0
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-nez v1, :cond_2

    .line 32
    .line 33
    if-eqz v0, :cond_2

    .line 34
    .line 35
    invoke-virtual {v0}, Lv3/f1;->s1()V

    .line 36
    .line 37
    .line 38
    iget-object v0, v0, Lv3/f1;->s:Lv3/f1;

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    return-void
.end method

.method public final f0(I)V
    .locals 2

    .line 1
    iget v0, p0, Lv3/h0;->R:I

    .line 2
    .line 3
    if-eq v0, p1, :cond_2

    .line 4
    .line 5
    if-lez p1, :cond_0

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget v1, v0, Lv3/h0;->R:I

    .line 16
    .line 17
    add-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Lv3/h0;->f0(I)V

    .line 20
    .line 21
    .line 22
    :cond_0
    if-nez p1, :cond_1

    .line 23
    .line 24
    iget v0, p0, Lv3/h0;->R:I

    .line 25
    .line 26
    if-lez v0, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    iget v1, v0, Lv3/h0;->R:I

    .line 35
    .line 36
    add-int/lit8 v1, v1, -0x1

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Lv3/h0;->f0(I)V

    .line 39
    .line 40
    .line 41
    :cond_1
    iput p1, p0, Lv3/h0;->R:I

    .line 42
    .line 43
    :cond_2
    return-void
.end method

.method public final g()V
    .locals 5

    .line 1
    iget-object v0, p0, Lv3/h0;->E:Lv3/f0;

    .line 2
    .line 3
    iput-object v0, p0, Lv3/h0;->F:Lv3/f0;

    .line 4
    .line 5
    sget-object v0, Lv3/f0;->f:Lv3/f0;

    .line 6
    .line 7
    iput-object v0, p0, Lv3/h0;->E:Lv3/f0;

    .line 8
    .line 9
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 14
    .line 15
    iget p0, p0, Ln2/b;->f:I

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    :goto_0
    if-ge v1, p0, :cond_1

    .line 19
    .line 20
    aget-object v2, v0, v1

    .line 21
    .line 22
    check-cast v2, Lv3/h0;

    .line 23
    .line 24
    iget-object v3, v2, Lv3/h0;->E:Lv3/f0;

    .line 25
    .line 26
    sget-object v4, Lv3/f0;->e:Lv3/f0;

    .line 27
    .line 28
    if-ne v3, v4, :cond_0

    .line 29
    .line 30
    invoke-virtual {v2}, Lv3/h0;->g()V

    .line 31
    .line 32
    .line 33
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    return-void
.end method

.method public final g0(Lv3/h0;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/h0;->j:Lv3/h0;

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    iput-object p1, p0, Lv3/h0;->j:Lv3/h0;

    .line 10
    .line 11
    iget-object v0, p0, Lv3/h0;->I:Lv3/l0;

    .line 12
    .line 13
    if-eqz p1, :cond_1

    .line 14
    .line 15
    iget-object p1, v0, Lv3/l0;->q:Lv3/u0;

    .line 16
    .line 17
    if-nez p1, :cond_0

    .line 18
    .line 19
    new-instance p1, Lv3/u0;

    .line 20
    .line 21
    invoke-direct {p1, v0}, Lv3/u0;-><init>(Lv3/l0;)V

    .line 22
    .line 23
    .line 24
    iput-object p1, v0, Lv3/l0;->q:Lv3/u0;

    .line 25
    .line 26
    :cond_0
    iget-object p1, p0, Lv3/h0;->H:Lg1/q;

    .line 27
    .line 28
    iget-object v0, p1, Lg1/q;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v0, Lv3/f1;

    .line 31
    .line 32
    iget-object p1, p1, Lg1/q;->d:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p1, Lv3/u;

    .line 35
    .line 36
    iget-object p1, p1, Lv3/f1;->s:Lv3/f1;

    .line 37
    .line 38
    :goto_0
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-nez v1, :cond_2

    .line 43
    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    invoke-virtual {v0}, Lv3/f1;->a1()V

    .line 47
    .line 48
    .line 49
    iget-object v0, v0, Lv3/f1;->s:Lv3/f1;

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    const/4 p1, 0x0

    .line 53
    iput-object p1, v0, Lv3/l0;->q:Lv3/u0;

    .line 54
    .line 55
    const/4 p1, 0x0

    .line 56
    iput-boolean p1, v0, Lv3/l0;->f:Z

    .line 57
    .line 58
    iput-boolean p1, v0, Lv3/l0;->e:Z

    .line 59
    .line 60
    :cond_2
    invoke-virtual {p0}, Lv3/h0;->E()V

    .line 61
    .line 62
    .line 63
    :cond_3
    return-void
.end method

.method public final h(I)Ljava/lang/String;
    .locals 6

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    move v2, v1

    .line 8
    :goto_0
    if-ge v2, p1, :cond_0

    .line 9
    .line 10
    const-string v3, "  "

    .line 11
    .line 12
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    add-int/lit8 v2, v2, 0x1

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const-string v2, "|-"

    .line 19
    .line 20
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Lv3/h0;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const/16 v2, 0xa

    .line 31
    .line 32
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    iget-object v2, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 40
    .line 41
    iget p0, p0, Ln2/b;->f:I

    .line 42
    .line 43
    move v3, v1

    .line 44
    :goto_1
    if-ge v3, p0, :cond_1

    .line 45
    .line 46
    aget-object v4, v2, v3

    .line 47
    .line 48
    check-cast v4, Lv3/h0;

    .line 49
    .line 50
    add-int/lit8 v5, p1, 0x1

    .line 51
    .line 52
    invoke-virtual {v4, v5}, Lv3/h0;->h(I)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    add-int/lit8 v3, v3, 0x1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    if-nez p1, :cond_2

    .line 67
    .line 68
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    add-int/lit8 p1, p1, -0x1

    .line 73
    .line 74
    invoke-virtual {p0, v1, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    const-string p1, "substring(...)"

    .line 79
    .line 80
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    :cond_2
    return-object p0
.end method

.method public final h0(Lt3/q0;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/h0;->y:Lt3/q0;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iput-object p1, p0, Lv3/h0;->y:Lt3/q0;

    .line 10
    .line 11
    iget-object v0, p0, Lv3/h0;->z:Lb81/d;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget-object v0, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Ll2/j1;

    .line 18
    .line 19
    invoke-virtual {v0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    invoke-virtual {p0}, Lv3/h0;->E()V

    .line 23
    .line 24
    .line 25
    :cond_1
    return-void
.end method

.method public final i()V
    .locals 11

    .line 1
    iget-object v0, p0, Lv3/h0;->p:Lv3/o1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v3, "Cannot detach node that is already detached!  Tree: "

    .line 10
    .line 11
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    invoke-virtual {p0, v2}, Lv3/h0;->h(I)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    :cond_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {p0}, Ls3/a;->c(Ljava/lang/String;)Ljava/lang/Void;

    .line 32
    .line 33
    .line 34
    new-instance p0, La8/r0;

    .line 35
    .line 36
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_1
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    iget-object v4, p0, Lv3/h0;->I:Lv3/l0;

    .line 45
    .line 46
    if-eqz v3, :cond_2

    .line 47
    .line 48
    invoke-virtual {v3}, Lv3/h0;->C()V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v3}, Lv3/h0;->E()V

    .line 52
    .line 53
    .line 54
    iget-object v3, v4, Lv3/l0;->p:Lv3/y0;

    .line 55
    .line 56
    sget-object v5, Lv3/f0;->f:Lv3/f0;

    .line 57
    .line 58
    iput-object v5, v3, Lv3/y0;->o:Lv3/f0;

    .line 59
    .line 60
    iget-object v3, v4, Lv3/l0;->q:Lv3/u0;

    .line 61
    .line 62
    if-eqz v3, :cond_2

    .line 63
    .line 64
    iput-object v5, v3, Lv3/u0;->m:Lv3/f0;

    .line 65
    .line 66
    :cond_2
    iget-object v3, v4, Lv3/l0;->p:Lv3/y0;

    .line 67
    .line 68
    iget-object v3, v3, Lv3/y0;->B:Lv3/i0;

    .line 69
    .line 70
    const/4 v5, 0x1

    .line 71
    iput-boolean v5, v3, Lv3/i0;->b:Z

    .line 72
    .line 73
    iput-boolean v2, v3, Lv3/i0;->c:Z

    .line 74
    .line 75
    iput-boolean v2, v3, Lv3/i0;->e:Z

    .line 76
    .line 77
    iput-boolean v2, v3, Lv3/i0;->d:Z

    .line 78
    .line 79
    iput-boolean v2, v3, Lv3/i0;->f:Z

    .line 80
    .line 81
    iput-boolean v2, v3, Lv3/i0;->g:Z

    .line 82
    .line 83
    iput-object v1, v3, Lv3/i0;->h:Lv3/a;

    .line 84
    .line 85
    iget-object v3, v4, Lv3/l0;->q:Lv3/u0;

    .line 86
    .line 87
    if-eqz v3, :cond_3

    .line 88
    .line 89
    iget-object v3, v3, Lv3/u0;->v:Lv3/i0;

    .line 90
    .line 91
    if-eqz v3, :cond_3

    .line 92
    .line 93
    iput-boolean v5, v3, Lv3/i0;->b:Z

    .line 94
    .line 95
    iput-boolean v2, v3, Lv3/i0;->c:Z

    .line 96
    .line 97
    iput-boolean v2, v3, Lv3/i0;->e:Z

    .line 98
    .line 99
    iput-boolean v2, v3, Lv3/i0;->d:Z

    .line 100
    .line 101
    iput-boolean v2, v3, Lv3/i0;->f:Z

    .line 102
    .line 103
    iput-boolean v2, v3, Lv3/i0;->g:Z

    .line 104
    .line 105
    iput-object v1, v3, Lv3/i0;->h:Lv3/a;

    .line 106
    .line 107
    :cond_3
    iget-object v3, p0, Lv3/h0;->H:Lg1/q;

    .line 108
    .line 109
    iget-object v6, v3, Lg1/q;->e:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v6, Lv3/f1;

    .line 112
    .line 113
    iget-object v7, v3, Lg1/q;->f:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v7, Lv3/z1;

    .line 116
    .line 117
    iget-object v8, v3, Lg1/q;->d:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast v8, Lv3/u;

    .line 120
    .line 121
    iget-object v8, v8, Lv3/f1;->s:Lv3/f1;

    .line 122
    .line 123
    :goto_0
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v9

    .line 127
    if-nez v9, :cond_4

    .line 128
    .line 129
    if-eqz v6, :cond_4

    .line 130
    .line 131
    invoke-virtual {v6}, Lv3/f1;->x1()V

    .line 132
    .line 133
    .line 134
    iget-object v6, v6, Lv3/f1;->s:Lv3/f1;

    .line 135
    .line 136
    goto :goto_0

    .line 137
    :cond_4
    iget-object v6, p0, Lv3/h0;->P:Lp3/b0;

    .line 138
    .line 139
    if-eqz v6, :cond_5

    .line 140
    .line 141
    invoke-virtual {v6, v0}, Lp3/b0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    :cond_5
    move-object v6, v7

    .line 145
    :goto_1
    if-eqz v6, :cond_7

    .line 146
    .line 147
    iget-boolean v8, v6, Lx2/r;->q:Z

    .line 148
    .line 149
    if-eqz v8, :cond_6

    .line 150
    .line 151
    invoke-virtual {v6}, Lx2/r;->U0()V

    .line 152
    .line 153
    .line 154
    :cond_6
    iget-object v6, v6, Lx2/r;->h:Lx2/r;

    .line 155
    .line 156
    goto :goto_1

    .line 157
    :cond_7
    iput-boolean v5, p0, Lv3/h0;->s:Z

    .line 158
    .line 159
    iget-object v6, p0, Lv3/h0;->l:Lc2/k;

    .line 160
    .line 161
    iget-object v6, v6, Lc2/k;->e:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast v6, Ln2/b;

    .line 164
    .line 165
    iget-object v8, v6, Ln2/b;->d:[Ljava/lang/Object;

    .line 166
    .line 167
    iget v6, v6, Ln2/b;->f:I

    .line 168
    .line 169
    move v9, v2

    .line 170
    :goto_2
    if-ge v9, v6, :cond_8

    .line 171
    .line 172
    aget-object v10, v8, v9

    .line 173
    .line 174
    check-cast v10, Lv3/h0;

    .line 175
    .line 176
    invoke-virtual {v10}, Lv3/h0;->i()V

    .line 177
    .line 178
    .line 179
    add-int/lit8 v9, v9, 0x1

    .line 180
    .line 181
    goto :goto_2

    .line 182
    :cond_8
    iput-boolean v2, p0, Lv3/h0;->s:Z

    .line 183
    .line 184
    :goto_3
    if-eqz v7, :cond_a

    .line 185
    .line 186
    iget-boolean v6, v7, Lx2/r;->q:Z

    .line 187
    .line 188
    if-eqz v6, :cond_9

    .line 189
    .line 190
    invoke-virtual {v7}, Lx2/r;->O0()V

    .line 191
    .line 192
    .line 193
    :cond_9
    iget-object v7, v7, Lx2/r;->h:Lx2/r;

    .line 194
    .line 195
    goto :goto_3

    .line 196
    :cond_a
    check-cast v0, Lw3/t;

    .line 197
    .line 198
    invoke-virtual {v0}, Lw3/t;->getLayoutNodes()Landroidx/collection/b0;

    .line 199
    .line 200
    .line 201
    move-result-object v6

    .line 202
    iget v7, p0, Lv3/h0;->e:I

    .line 203
    .line 204
    invoke-virtual {v6, v7}, Landroidx/collection/b0;->g(I)Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    iget-object v6, v0, Lw3/t;->R:Lv3/w0;

    .line 208
    .line 209
    iget-object v7, v6, Lv3/w0;->b:Lrn/i;

    .line 210
    .line 211
    iget-object v8, v7, Lrn/i;->e:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast v8, Lt1/j0;

    .line 214
    .line 215
    invoke-virtual {v8, p0}, Lt1/j0;->n(Lv3/h0;)Z

    .line 216
    .line 217
    .line 218
    iget-object v8, v7, Lrn/i;->f:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast v8, Lt1/j0;

    .line 221
    .line 222
    invoke-virtual {v8, p0}, Lt1/j0;->n(Lv3/h0;)Z

    .line 223
    .line 224
    .line 225
    iget-object v7, v7, Lrn/i;->g:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast v7, Lt1/j0;

    .line 228
    .line 229
    invoke-virtual {v7, p0}, Lt1/j0;->n(Lv3/h0;)Z

    .line 230
    .line 231
    .line 232
    iget-object v6, v6, Lv3/w0;->e:Lvp/y1;

    .line 233
    .line 234
    iget-object v6, v6, Lvp/y1;->e:Ljava/lang/Object;

    .line 235
    .line 236
    check-cast v6, Ln2/b;

    .line 237
    .line 238
    invoke-virtual {v6, p0}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 239
    .line 240
    .line 241
    iput-boolean v5, v0, Lw3/t;->J:Z

    .line 242
    .line 243
    invoke-virtual {v0}, Lw3/t;->getRectManager()Le4/a;

    .line 244
    .line 245
    .line 246
    move-result-object v5

    .line 247
    invoke-virtual {v5, p0}, Le4/a;->j(Lv3/h0;)V

    .line 248
    .line 249
    .line 250
    iget-object v5, v0, Lw3/t;->I:Ly2/b;

    .line 251
    .line 252
    if-eqz v5, :cond_b

    .line 253
    .line 254
    iget-object v6, v5, Ly2/b;->h:Landroidx/collection/c0;

    .line 255
    .line 256
    iget v7, p0, Lv3/h0;->e:I

    .line 257
    .line 258
    invoke-virtual {v6, v7}, Landroidx/collection/c0;->e(I)Z

    .line 259
    .line 260
    .line 261
    move-result v6

    .line 262
    if-eqz v6, :cond_b

    .line 263
    .line 264
    iget-object v6, v5, Ly2/b;->a:Lpv/g;

    .line 265
    .line 266
    iget-object v5, v5, Ly2/b;->c:Lw3/t;

    .line 267
    .line 268
    iget v7, p0, Lv3/h0;->e:I

    .line 269
    .line 270
    invoke-virtual {v6, v5, v7, v2}, Lpv/g;->m(Landroid/view/View;IZ)V

    .line 271
    .line 272
    .line 273
    :cond_b
    iput-object v1, p0, Lv3/h0;->p:Lv3/o1;

    .line 274
    .line 275
    const-wide v5, 0x7fffffff7fffffffL

    .line 276
    .line 277
    .line 278
    .line 279
    .line 280
    iput-wide v5, p0, Lv3/h0;->f:J

    .line 281
    .line 282
    invoke-virtual {p0, v1}, Lv3/h0;->g0(Lv3/h0;)V

    .line 283
    .line 284
    .line 285
    iput v2, p0, Lv3/h0;->r:I

    .line 286
    .line 287
    iget-object v5, v4, Lv3/l0;->p:Lv3/y0;

    .line 288
    .line 289
    const v6, 0x7fffffff

    .line 290
    .line 291
    .line 292
    iput v6, v5, Lv3/y0;->l:I

    .line 293
    .line 294
    iput v6, v5, Lv3/y0;->k:I

    .line 295
    .line 296
    iput-boolean v2, v5, Lv3/y0;->w:Z

    .line 297
    .line 298
    iget-object v4, v4, Lv3/l0;->q:Lv3/u0;

    .line 299
    .line 300
    if-eqz v4, :cond_c

    .line 301
    .line 302
    iput v6, v4, Lv3/u0;->l:I

    .line 303
    .line 304
    iput v6, v4, Lv3/u0;->k:I

    .line 305
    .line 306
    sget-object v5, Lv3/r0;->f:Lv3/r0;

    .line 307
    .line 308
    iput-object v5, v4, Lv3/u0;->u:Lv3/r0;

    .line 309
    .line 310
    :cond_c
    const/16 v4, 0x8

    .line 311
    .line 312
    invoke-virtual {v3, v4}, Lg1/q;->i(I)Z

    .line 313
    .line 314
    .line 315
    move-result v3

    .line 316
    if-eqz v3, :cond_d

    .line 317
    .line 318
    iget-object v3, p0, Lv3/h0;->u:Ld4/l;

    .line 319
    .line 320
    iput-object v1, p0, Lv3/h0;->u:Ld4/l;

    .line 321
    .line 322
    iput-boolean v2, p0, Lv3/h0;->t:Z

    .line 323
    .line 324
    invoke-virtual {v0}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 325
    .line 326
    .line 327
    move-result-object v1

    .line 328
    invoke-virtual {v1, p0, v3}, Ld4/s;->b(Lv3/h0;Ld4/l;)V

    .line 329
    .line 330
    .line 331
    invoke-virtual {v0}, Lw3/t;->y()V

    .line 332
    .line 333
    .line 334
    :cond_d
    return-void
.end method

.method public final i0(Lx2/s;)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lv3/h0;->d:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lv3/h0;->M:Lx2/s;

    .line 6
    .line 7
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const-string v0, "Modifiers are not supported on virtual LayoutNodes"

    .line 13
    .line 14
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    :cond_1
    :goto_0
    iget-boolean v0, p0, Lv3/h0;->S:Z

    .line 18
    .line 19
    if-eqz v0, :cond_2

    .line 20
    .line 21
    const-string v0, "modifier is updated when deactivated"

    .line 22
    .line 23
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    :cond_2
    invoke-virtual {p0}, Lv3/h0;->I()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_4

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Lv3/h0;->b(Lx2/s;)V

    .line 33
    .line 34
    .line 35
    iget-boolean p1, p0, Lv3/h0;->t:Z

    .line 36
    .line 37
    if-eqz p1, :cond_3

    .line 38
    .line 39
    invoke-virtual {p0}, Lv3/h0;->G()V

    .line 40
    .line 41
    .line 42
    :cond_3
    return-void

    .line 43
    :cond_4
    iput-object p1, p0, Lv3/h0;->N:Lx2/s;

    .line 44
    .line 45
    return-void
.end method

.method public final j(Le3/r;Lh3/c;)V
    .locals 1

    .line 1
    :try_start_0
    iget-object v0, p0, Lv3/h0;->H:Lg1/q;

    .line 2
    .line 3
    iget-object v0, v0, Lg1/q;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lv3/f1;

    .line 6
    .line 7
    invoke-virtual {v0, p1, p2}, Lv3/f1;->Y0(Le3/r;Lh3/c;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p1

    .line 12
    invoke-virtual {p0, p1}, Lv3/h0;->b0(Ljava/lang/Throwable;)V

    .line 13
    .line 14
    .line 15
    const/4 p0, 0x0

    .line 16
    throw p0
.end method

.method public final j0(Lw3/h2;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lv3/h0;->C:Lw3/h2;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_8

    .line 8
    .line 9
    iput-object p1, p0, Lv3/h0;->C:Lw3/h2;

    .line 10
    .line 11
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 12
    .line 13
    iget-object p0, p0, Lg1/q;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lx2/r;

    .line 16
    .line 17
    iget p1, p0, Lx2/r;->g:I

    .line 18
    .line 19
    const/16 v0, 0x10

    .line 20
    .line 21
    and-int/2addr p1, v0

    .line 22
    if-eqz p1, :cond_8

    .line 23
    .line 24
    :goto_0
    if-eqz p0, :cond_8

    .line 25
    .line 26
    iget p1, p0, Lx2/r;->f:I

    .line 27
    .line 28
    and-int/2addr p1, v0

    .line 29
    if-eqz p1, :cond_7

    .line 30
    .line 31
    const/4 p1, 0x0

    .line 32
    move-object v1, p0

    .line 33
    move-object v2, p1

    .line 34
    :goto_1
    if-eqz v1, :cond_7

    .line 35
    .line 36
    instance-of v3, v1, Lv3/t1;

    .line 37
    .line 38
    if-eqz v3, :cond_0

    .line 39
    .line 40
    check-cast v1, Lv3/t1;

    .line 41
    .line 42
    invoke-interface {v1}, Lv3/t1;->H0()V

    .line 43
    .line 44
    .line 45
    goto :goto_4

    .line 46
    :cond_0
    iget v3, v1, Lx2/r;->f:I

    .line 47
    .line 48
    and-int/2addr v3, v0

    .line 49
    if-eqz v3, :cond_6

    .line 50
    .line 51
    instance-of v3, v1, Lv3/n;

    .line 52
    .line 53
    if-eqz v3, :cond_6

    .line 54
    .line 55
    move-object v3, v1

    .line 56
    check-cast v3, Lv3/n;

    .line 57
    .line 58
    iget-object v3, v3, Lv3/n;->s:Lx2/r;

    .line 59
    .line 60
    const/4 v4, 0x0

    .line 61
    :goto_2
    const/4 v5, 0x1

    .line 62
    if-eqz v3, :cond_5

    .line 63
    .line 64
    iget v6, v3, Lx2/r;->f:I

    .line 65
    .line 66
    and-int/2addr v6, v0

    .line 67
    if-eqz v6, :cond_4

    .line 68
    .line 69
    add-int/lit8 v4, v4, 0x1

    .line 70
    .line 71
    if-ne v4, v5, :cond_1

    .line 72
    .line 73
    move-object v1, v3

    .line 74
    goto :goto_3

    .line 75
    :cond_1
    if-nez v2, :cond_2

    .line 76
    .line 77
    new-instance v2, Ln2/b;

    .line 78
    .line 79
    new-array v5, v0, [Lx2/r;

    .line 80
    .line 81
    invoke-direct {v2, v5}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    :cond_2
    if-eqz v1, :cond_3

    .line 85
    .line 86
    invoke-virtual {v2, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    move-object v1, p1

    .line 90
    :cond_3
    invoke-virtual {v2, v3}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    :cond_4
    :goto_3
    iget-object v3, v3, Lx2/r;->i:Lx2/r;

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_5
    if-ne v4, v5, :cond_6

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_6
    :goto_4
    invoke-static {v2}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    goto :goto_1

    .line 104
    :cond_7
    iget p1, p0, Lx2/r;->g:I

    .line 105
    .line 106
    and-int/2addr p1, v0

    .line 107
    if-eqz p1, :cond_8

    .line 108
    .line 109
    iget-object p0, p0, Lx2/r;->i:Lx2/r;

    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_8
    return-void
.end method

.method public final k0()V
    .locals 6

    .line 1
    iget v0, p0, Lv3/h0;->k:I

    .line 2
    .line 3
    if-lez v0, :cond_3

    .line 4
    .line 5
    iget-boolean v0, p0, Lv3/h0;->n:Z

    .line 6
    .line 7
    if-eqz v0, :cond_3

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    iput-boolean v0, p0, Lv3/h0;->n:Z

    .line 11
    .line 12
    iget-object v1, p0, Lv3/h0;->m:Ln2/b;

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    new-instance v1, Ln2/b;

    .line 17
    .line 18
    const/16 v2, 0x10

    .line 19
    .line 20
    new-array v2, v2, [Lv3/h0;

    .line 21
    .line 22
    invoke-direct {v1, v2}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iput-object v1, p0, Lv3/h0;->m:Ln2/b;

    .line 26
    .line 27
    :cond_0
    invoke-virtual {v1}, Ln2/b;->i()V

    .line 28
    .line 29
    .line 30
    iget-object v2, p0, Lv3/h0;->l:Lc2/k;

    .line 31
    .line 32
    iget-object v2, v2, Lc2/k;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v2, Ln2/b;

    .line 35
    .line 36
    iget-object v3, v2, Ln2/b;->d:[Ljava/lang/Object;

    .line 37
    .line 38
    iget v2, v2, Ln2/b;->f:I

    .line 39
    .line 40
    :goto_0
    if-ge v0, v2, :cond_2

    .line 41
    .line 42
    aget-object v4, v3, v0

    .line 43
    .line 44
    check-cast v4, Lv3/h0;

    .line 45
    .line 46
    iget-boolean v5, v4, Lv3/h0;->d:Z

    .line 47
    .line 48
    if-eqz v5, :cond_1

    .line 49
    .line 50
    invoke-virtual {v4}, Lv3/h0;->z()Ln2/b;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    iget v5, v1, Ln2/b;->f:I

    .line 55
    .line 56
    invoke-virtual {v1, v5, v4}, Ln2/b;->f(ILn2/b;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    invoke-virtual {v1, v4}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    :goto_1
    add-int/lit8 v0, v0, 0x1

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 67
    .line 68
    iget-object v0, p0, Lv3/l0;->p:Lv3/y0;

    .line 69
    .line 70
    const/4 v1, 0x1

    .line 71
    iput-boolean v1, v0, Lv3/y0;->D:Z

    .line 72
    .line 73
    iget-object p0, p0, Lv3/l0;->q:Lv3/u0;

    .line 74
    .line 75
    if-eqz p0, :cond_3

    .line 76
    .line 77
    iput-boolean v1, p0, Lv3/u0;->x:Z

    .line 78
    .line 79
    :cond_3
    return-void
.end method

.method public final l()V
    .locals 3

    .line 1
    iget-object v0, p0, Lv3/h0;->j:Lv3/h0;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    const/4 v2, 0x0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static {p0, v2, v1}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 8
    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    invoke-static {p0, v2, v1}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 12
    .line 13
    .line 14
    :goto_0
    iget-object v0, p0, Lv3/h0;->I:Lv3/l0;

    .line 15
    .line 16
    iget-object v0, v0, Lv3/l0;->p:Lv3/y0;

    .line 17
    .line 18
    iget-boolean v1, v0, Lv3/y0;->m:Z

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    iget-wide v0, v0, Lt3/e1;->g:J

    .line 23
    .line 24
    new-instance v2, Lt4/a;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lt4/a;-><init>(J)V

    .line 27
    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/4 v2, 0x0

    .line 31
    :goto_1
    if-eqz v2, :cond_2

    .line 32
    .line 33
    iget-object v0, p0, Lv3/h0;->p:Lv3/o1;

    .line 34
    .line 35
    if-eqz v0, :cond_3

    .line 36
    .line 37
    iget-wide v1, v2, Lt4/a;->a:J

    .line 38
    .line 39
    check-cast v0, Lw3/t;

    .line 40
    .line 41
    invoke-virtual {v0, p0, v1, v2}, Lw3/t;->s(Lv3/h0;J)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_2
    iget-object p0, p0, Lv3/h0;->p:Lv3/o1;

    .line 46
    .line 47
    if-eqz p0, :cond_3

    .line 48
    .line 49
    const/4 v0, 0x1

    .line 50
    check-cast p0, Lw3/t;

    .line 51
    .line 52
    invoke-virtual {p0, v0}, Lw3/t;->r(Z)V

    .line 53
    .line 54
    .line 55
    :cond_3
    return-void
.end method

.method public final m()Ljava/util/List;
    .locals 9

    .line 1
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->q:Lv3/u0;

    .line 4
    .line 5
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lv3/u0;->w:Ln2/b;

    .line 9
    .line 10
    iget-object v1, p0, Lv3/u0;->i:Lv3/l0;

    .line 11
    .line 12
    iget-object v2, v1, Lv3/l0;->a:Lv3/h0;

    .line 13
    .line 14
    invoke-virtual {v2}, Lv3/h0;->o()Ljava/util/List;

    .line 15
    .line 16
    .line 17
    iget-boolean v2, p0, Lv3/u0;->x:Z

    .line 18
    .line 19
    if-nez v2, :cond_0

    .line 20
    .line 21
    invoke-virtual {v0}, Ln2/b;->h()Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :cond_0
    iget-object v1, v1, Lv3/l0;->a:Lv3/h0;

    .line 27
    .line 28
    invoke-virtual {v1}, Lv3/h0;->z()Ln2/b;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    iget-object v3, v2, Ln2/b;->d:[Ljava/lang/Object;

    .line 33
    .line 34
    iget v2, v2, Ln2/b;->f:I

    .line 35
    .line 36
    const/4 v4, 0x0

    .line 37
    move v5, v4

    .line 38
    :goto_0
    if-ge v5, v2, :cond_2

    .line 39
    .line 40
    aget-object v6, v3, v5

    .line 41
    .line 42
    check-cast v6, Lv3/h0;

    .line 43
    .line 44
    iget v7, v0, Ln2/b;->f:I

    .line 45
    .line 46
    if-gt v7, v5, :cond_1

    .line 47
    .line 48
    iget-object v6, v6, Lv3/h0;->I:Lv3/l0;

    .line 49
    .line 50
    iget-object v6, v6, Lv3/l0;->q:Lv3/u0;

    .line 51
    .line 52
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    iget-object v6, v6, Lv3/h0;->I:Lv3/l0;

    .line 60
    .line 61
    iget-object v6, v6, Lv3/l0;->q:Lv3/u0;

    .line 62
    .line 63
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object v7, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 67
    .line 68
    aget-object v8, v7, v5

    .line 69
    .line 70
    aput-object v6, v7, v5

    .line 71
    .line 72
    :goto_1
    add-int/lit8 v5, v5, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_2
    invoke-virtual {v1}, Lv3/h0;->o()Ljava/util/List;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    check-cast v1, Landroidx/collection/j0;

    .line 80
    .line 81
    iget-object v1, v1, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v1, Ln2/b;

    .line 84
    .line 85
    iget v1, v1, Ln2/b;->f:I

    .line 86
    .line 87
    iget v2, v0, Ln2/b;->f:I

    .line 88
    .line 89
    invoke-virtual {v0, v1, v2}, Ln2/b;->n(II)V

    .line 90
    .line 91
    .line 92
    iput-boolean v4, p0, Lv3/u0;->x:Z

    .line 93
    .line 94
    invoke-virtual {v0}, Ln2/b;->h()Ljava/util/List;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    return-object p0
.end method

.method public final n()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 4
    .line 5
    invoke-virtual {p0}, Lv3/y0;->B0()Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final o()Ljava/util/List;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ln2/b;->h()Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final p()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/h0;->l:Lc2/k;

    .line 2
    .line 3
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ln2/b;

    .line 6
    .line 7
    invoke-virtual {p0}, Ln2/b;->h()Ljava/util/List;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final q()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 4
    .line 5
    iget-boolean p0, p0, Lv3/y0;->z:Z

    .line 6
    .line 7
    return p0
.end method

.method public final r()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 4
    .line 5
    iget-boolean p0, p0, Lv3/y0;->y:Z

    .line 6
    .line 7
    return p0
.end method

.method public final s()Lv3/f0;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 4
    .line 5
    iget-object p0, p0, Lv3/y0;->o:Lv3/f0;

    .line 6
    .line 7
    return-object p0
.end method

.method public final t()Lv3/f0;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->q:Lv3/u0;

    .line 4
    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    iget-object p0, p0, Lv3/u0;->m:Lv3/f0;

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-object p0

    .line 13
    :cond_1
    :goto_0
    sget-object p0, Lv3/f0;->f:Lv3/f0;

    .line 14
    .line 15
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lw3/h0;->A(Ljava/lang/Object;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, " children: "

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0}, Lv3/h0;->o()Ljava/util/List;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    check-cast v1, Landroidx/collection/j0;

    .line 23
    .line 24
    iget-object v1, v1, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Ln2/b;

    .line 27
    .line 28
    iget v1, v1, Ln2/b;->f:I

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, " measurePolicy: "

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lv3/h0;->y:Lt3/q0;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, " deactivated: "

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-boolean p0, p0, Lv3/h0;->S:Z

    .line 49
    .line 50
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0
.end method

.method public final u()Lb81/d;
    .locals 2

    .line 1
    iget-object v0, p0, Lv3/h0;->z:Lb81/d;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lb81/d;

    .line 6
    .line 7
    iget-object v1, p0, Lv3/h0;->y:Lt3/q0;

    .line 8
    .line 9
    invoke-direct {v0, p0, v1}, Lb81/d;-><init>(Lv3/h0;Lt3/q0;)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lv3/h0;->z:Lb81/d;

    .line 13
    .line 14
    :cond_0
    return-object v0
.end method

.method public final v()Lv3/h0;
    .locals 2

    .line 1
    iget-object p0, p0, Lv3/h0;->o:Lv3/h0;

    .line 2
    .line 3
    :goto_0
    if-eqz p0, :cond_0

    .line 4
    .line 5
    iget-boolean v0, p0, Lv3/h0;->d:Z

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    if-ne v0, v1, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Lv3/h0;->o:Lv3/h0;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    return-object p0
.end method

.method public final w()I
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 4
    .line 5
    iget p0, p0, Lv3/y0;->l:I

    .line 6
    .line 7
    return p0
.end method

.method public final x()Ld4/l;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lv3/h0;->I()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget-boolean v0, p0, Lv3/h0;->S:Z

    .line 8
    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    iget-object v0, p0, Lv3/h0;->H:Lg1/q;

    .line 12
    .line 13
    const/16 v1, 0x8

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Lg1/q;->i(I)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    iget-object p0, p0, Lv3/h0;->u:Ld4/l;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 26
    return-object p0
.end method

.method public final y()Ln2/b;
    .locals 5

    .line 1
    iget-boolean v0, p0, Lv3/h0;->x:Z

    .line 2
    .line 3
    iget-object v1, p0, Lv3/h0;->w:Ln2/b;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v1}, Ln2/b;->i()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget v2, v1, Ln2/b;->f:I

    .line 15
    .line 16
    invoke-virtual {v1, v2, v0}, Ln2/b;->f(ILn2/b;)V

    .line 17
    .line 18
    .line 19
    iget-object v0, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 20
    .line 21
    iget v2, v1, Ln2/b;->f:I

    .line 22
    .line 23
    sget-object v3, Lv3/h0;->V:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 24
    .line 25
    const/4 v4, 0x0

    .line 26
    invoke-static {v0, v3, v4, v2}, Lmx0/n;->T([Ljava/lang/Object;Ljava/util/Comparator;II)V

    .line 27
    .line 28
    .line 29
    iput-boolean v4, p0, Lv3/h0;->x:Z

    .line 30
    .line 31
    :cond_0
    return-object v1
.end method

.method public final z()Ln2/b;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lv3/h0;->k0()V

    .line 2
    .line 3
    .line 4
    iget v0, p0, Lv3/h0;->k:I

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lv3/h0;->l:Lc2/k;

    .line 9
    .line 10
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ln2/b;

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_0
    iget-object p0, p0, Lv3/h0;->m:Ln2/b;

    .line 16
    .line 17
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-object p0
.end method
