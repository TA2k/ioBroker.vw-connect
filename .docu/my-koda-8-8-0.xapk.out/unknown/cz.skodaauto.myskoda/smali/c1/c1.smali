.class public final Lc1/c1;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final v:Lc1/l;

.field public static final w:Lc1/l;


# instance fields
.field public final f:Ll2/j1;

.field public final g:Ll2/j1;

.field public h:Ljava/lang/Object;

.field public i:Lc1/w1;

.field public j:J

.field public final k:La71/u;

.field public final l:Ll2/f1;

.field public m:Lvy0/l;

.field public final n:Lez0/c;

.field public final o:Lc1/r0;

.field public p:J

.field public final q:Landroidx/collection/l0;

.field public r:Lc1/v0;

.field public final s:Lc1/u0;

.field public t:F

.field public final u:Lc1/u0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lc1/l;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lc1/l;-><init>(F)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lc1/c1;->v:Lc1/l;

    .line 8
    .line 9
    new-instance v0, Lc1/l;

    .line 10
    .line 11
    const/high16 v1, 0x3f800000    # 1.0f

    .line 12
    .line 13
    invoke-direct {v0, v1}, Lc1/l;-><init>(F)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lc1/c1;->w:Lc1/l;

    .line 17
    .line 18
    return-void
.end method

.method public constructor <init>(Lz9/k;)V
    .locals 2

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-direct {p0, v0}, Lap0/o;-><init>(I)V

    .line 3
    .line 4
    .line 5
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iput-object v0, p0, Lc1/c1;->f:Ll2/j1;

    .line 10
    .line 11
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Lc1/c1;->g:Ll2/j1;

    .line 16
    .line 17
    iput-object p1, p0, Lc1/c1;->h:Ljava/lang/Object;

    .line 18
    .line 19
    new-instance p1, La71/u;

    .line 20
    .line 21
    const/16 v0, 0x15

    .line 22
    .line 23
    invoke-direct {p1, p0, v0}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    iput-object p1, p0, Lc1/c1;->k:La71/u;

    .line 27
    .line 28
    new-instance p1, Ll2/f1;

    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    invoke-direct {p1, v0}, Ll2/f1;-><init>(F)V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Lc1/c1;->l:Ll2/f1;

    .line 35
    .line 36
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iput-object p1, p0, Lc1/c1;->n:Lez0/c;

    .line 41
    .line 42
    new-instance p1, Lc1/r0;

    .line 43
    .line 44
    invoke-direct {p1}, Lc1/r0;-><init>()V

    .line 45
    .line 46
    .line 47
    iput-object p1, p0, Lc1/c1;->o:Lc1/r0;

    .line 48
    .line 49
    const-wide/high16 v0, -0x8000000000000000L

    .line 50
    .line 51
    iput-wide v0, p0, Lc1/c1;->p:J

    .line 52
    .line 53
    new-instance p1, Landroidx/collection/l0;

    .line 54
    .line 55
    invoke-direct {p1}, Landroidx/collection/l0;-><init>()V

    .line 56
    .line 57
    .line 58
    iput-object p1, p0, Lc1/c1;->q:Landroidx/collection/l0;

    .line 59
    .line 60
    new-instance p1, Lc1/u0;

    .line 61
    .line 62
    const/4 v0, 0x0

    .line 63
    invoke-direct {p1, p0, v0}, Lc1/u0;-><init>(Lc1/c1;I)V

    .line 64
    .line 65
    .line 66
    iput-object p1, p0, Lc1/c1;->s:Lc1/u0;

    .line 67
    .line 68
    new-instance p1, Lc1/u0;

    .line 69
    .line 70
    const/4 v0, 0x1

    .line 71
    invoke-direct {p1, p0, v0}, Lc1/u0;-><init>(Lc1/c1;I)V

    .line 72
    .line 73
    .line 74
    iput-object p1, p0, Lc1/c1;->u:Lc1/u0;

    .line 75
    .line 76
    return-void
.end method

.method public static final b0(Lc1/c1;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lc1/c1;->i:Lc1/w1;

    .line 2
    .line 3
    iget-object v1, p0, Lc1/c1;->l:Ll2/f1;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget-object v2, p0, Lc1/c1;->r:Lc1/v0;

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    if-nez v2, :cond_4

    .line 12
    .line 13
    iget-wide v4, p0, Lc1/c1;->j:J

    .line 14
    .line 15
    const-wide/16 v6, 0x0

    .line 16
    .line 17
    cmp-long v2, v4, v6

    .line 18
    .line 19
    if-lez v2, :cond_3

    .line 20
    .line 21
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    const/high16 v4, 0x3f800000    # 1.0f

    .line 26
    .line 27
    cmpg-float v2, v2, v4

    .line 28
    .line 29
    if-nez v2, :cond_1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    iget-object v2, p0, Lc1/c1;->g:Ll2/j1;

    .line 33
    .line 34
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    iget-object v4, p0, Lc1/c1;->f:Ll2/j1;

    .line 39
    .line 40
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    new-instance v2, Lc1/v0;

    .line 52
    .line 53
    invoke-direct {v2}, Lc1/v0;-><init>()V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    iput v4, v2, Lc1/v0;->d:F

    .line 61
    .line 62
    iget-wide v4, p0, Lc1/c1;->j:J

    .line 63
    .line 64
    iput-wide v4, v2, Lc1/v0;->g:J

    .line 65
    .line 66
    long-to-double v4, v4

    .line 67
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 68
    .line 69
    .line 70
    move-result v6

    .line 71
    float-to-double v6, v6

    .line 72
    const-wide/high16 v8, 0x3ff0000000000000L    # 1.0

    .line 73
    .line 74
    sub-double/2addr v8, v6

    .line 75
    mul-double/2addr v8, v4

    .line 76
    invoke-static {v8, v9}, Lcy0/a;->j(D)J

    .line 77
    .line 78
    .line 79
    move-result-wide v4

    .line 80
    iput-wide v4, v2, Lc1/v0;->h:J

    .line 81
    .line 82
    const/4 v4, 0x0

    .line 83
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    iget-object v5, v2, Lc1/v0;->e:Lc1/l;

    .line 88
    .line 89
    invoke-virtual {v5, v4, v1}, Lc1/l;->e(IF)V

    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_3
    :goto_0
    move-object v2, v3

    .line 94
    :cond_4
    :goto_1
    if-eqz v2, :cond_5

    .line 95
    .line 96
    iget-wide v4, p0, Lc1/c1;->j:J

    .line 97
    .line 98
    iput-wide v4, v2, Lc1/v0;->g:J

    .line 99
    .line 100
    iget-object v1, p0, Lc1/c1;->q:Landroidx/collection/l0;

    .line 101
    .line 102
    invoke-virtual {v1, v2}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0, v2}, Lc1/w1;->m(Lc1/v0;)V

    .line 106
    .line 107
    .line 108
    :cond_5
    iput-object v3, p0, Lc1/c1;->r:Lc1/v0;

    .line 109
    .line 110
    return-void
.end method

.method public static final c0(Lc1/c1;Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget-object v0, p0, Lc1/c1;->q:Landroidx/collection/l0;

    .line 2
    .line 3
    instance-of v1, p1, Lc1/x0;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p1

    .line 8
    check-cast v1, Lc1/x0;

    .line 9
    .line 10
    iget v2, v1, Lc1/x0;->f:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lc1/x0;->f:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lc1/x0;

    .line 23
    .line 24
    invoke-direct {v1, p0, p1}, Lc1/x0;-><init>(Lc1/c1;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v1, Lc1/x0;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lc1/x0;->f:I

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    const-wide/high16 v6, -0x8000000000000000L

    .line 36
    .line 37
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    if-eqz v3, :cond_3

    .line 40
    .line 41
    if-eq v3, v5, :cond_2

    .line 42
    .line 43
    if-ne v3, v4, :cond_1

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    :goto_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0}, Landroidx/collection/l0;->g()Z

    .line 62
    .line 63
    .line 64
    move-result p1

    .line 65
    if-eqz p1, :cond_4

    .line 66
    .line 67
    iget-object p1, p0, Lc1/c1;->r:Lc1/v0;

    .line 68
    .line 69
    if-nez p1, :cond_4

    .line 70
    .line 71
    return-object v8

    .line 72
    :cond_4
    invoke-interface {v1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    invoke-static {p1}, Lc1/d;->p(Lpx0/g;)F

    .line 77
    .line 78
    .line 79
    move-result p1

    .line 80
    const/4 v3, 0x0

    .line 81
    cmpg-float p1, p1, v3

    .line 82
    .line 83
    if-nez p1, :cond_5

    .line 84
    .line 85
    invoke-virtual {p0}, Lc1/c1;->g0()V

    .line 86
    .line 87
    .line 88
    iput-wide v6, p0, Lc1/c1;->p:J

    .line 89
    .line 90
    return-object v8

    .line 91
    :cond_5
    iget-wide v9, p0, Lc1/c1;->p:J

    .line 92
    .line 93
    cmp-long p1, v9, v6

    .line 94
    .line 95
    if-nez p1, :cond_6

    .line 96
    .line 97
    iget-object p1, p0, Lc1/c1;->s:Lc1/u0;

    .line 98
    .line 99
    iput v5, v1, Lc1/x0;->f:I

    .line 100
    .line 101
    invoke-interface {v1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    invoke-static {v3}, Ll2/b;->k(Lpx0/g;)Ll2/y0;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    invoke-interface {v3, p1, v1}, Ll2/y0;->q(Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    if-ne p1, v2, :cond_6

    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_6
    :goto_2
    invoke-virtual {v0}, Landroidx/collection/l0;->h()Z

    .line 117
    .line 118
    .line 119
    move-result p1

    .line 120
    if-nez p1, :cond_8

    .line 121
    .line 122
    iget-object p1, p0, Lc1/c1;->r:Lc1/v0;

    .line 123
    .line 124
    if-eqz p1, :cond_7

    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_7
    iput-wide v6, p0, Lc1/c1;->p:J

    .line 128
    .line 129
    return-object v8

    .line 130
    :cond_8
    :goto_3
    iput v4, v1, Lc1/x0;->f:I

    .line 131
    .line 132
    invoke-virtual {p0, v1}, Lc1/c1;->f0(Lrx0/c;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    if-ne p1, v2, :cond_6

    .line 137
    .line 138
    :goto_4
    return-object v2
.end method

.method public static final d0(Lc1/c1;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lc1/c1;->n:Lez0/c;

    .line 2
    .line 3
    instance-of v1, p1, Lc1/a1;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p1

    .line 8
    check-cast v1, Lc1/a1;

    .line 9
    .line 10
    iget v2, v1, Lc1/a1;->g:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lc1/a1;->g:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lc1/a1;

    .line 23
    .line 24
    invoke-direct {v1, p0, p1}, Lc1/a1;-><init>(Lc1/c1;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v1, Lc1/a1;->e:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lc1/a1;->g:I

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v3, :cond_3

    .line 36
    .line 37
    if-eq v3, v5, :cond_2

    .line 38
    .line 39
    if-ne v3, v4, :cond_1

    .line 40
    .line 41
    iget-object v0, v1, Lc1/a1;->d:Ljava/lang/Object;

    .line 42
    .line 43
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_3

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    iget-object v3, v1, Lc1/a1;->d:Ljava/lang/Object;

    .line 56
    .line 57
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    move-object p1, v3

    .line 61
    goto :goto_1

    .line 62
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget-object p1, p0, Lc1/c1;->f:Ll2/j1;

    .line 66
    .line 67
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    iput-object p1, v1, Lc1/a1;->d:Ljava/lang/Object;

    .line 72
    .line 73
    iput v5, v1, Lc1/a1;->g:I

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    if-ne v3, v2, :cond_4

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_4
    :goto_1
    iput-object p1, v1, Lc1/a1;->d:Ljava/lang/Object;

    .line 83
    .line 84
    iput v4, v1, Lc1/a1;->g:I

    .line 85
    .line 86
    new-instance v3, Lvy0/l;

    .line 87
    .line 88
    invoke-static {v1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    invoke-direct {v3, v5, v1}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v3}, Lvy0/l;->q()V

    .line 96
    .line 97
    .line 98
    iput-object v3, p0, Lc1/c1;->m:Lvy0/l;

    .line 99
    .line 100
    const/4 v1, 0x0

    .line 101
    invoke-virtual {v0, v1}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v3}, Lvy0/l;->p()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    if-ne v0, v2, :cond_5

    .line 109
    .line 110
    :goto_2
    return-object v2

    .line 111
    :cond_5
    move-object v6, v0

    .line 112
    move-object v0, p1

    .line 113
    move-object p1, v6

    .line 114
    :goto_3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result p1

    .line 118
    if-eqz p1, :cond_6

    .line 119
    .line 120
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object p0

    .line 123
    :cond_6
    const-wide/high16 v0, -0x8000000000000000L

    .line 124
    .line 125
    iput-wide v0, p0, Lc1/c1;->p:J

    .line 126
    .line 127
    new-instance p0, Ljava/util/concurrent/CancellationException;

    .line 128
    .line 129
    const-string p1, "targetState while waiting for composition"

    .line 130
    .line 131
    invoke-direct {p0, p1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    throw p0
.end method

.method public static final e0(Lc1/c1;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget-object v0, p0, Lc1/c1;->n:Lez0/c;

    .line 2
    .line 3
    instance-of v1, p1, Lc1/b1;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p1

    .line 8
    check-cast v1, Lc1/b1;

    .line 9
    .line 10
    iget v2, v1, Lc1/b1;->g:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lc1/b1;->g:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lc1/b1;

    .line 23
    .line 24
    invoke-direct {v1, p0, p1}, Lc1/b1;-><init>(Lc1/c1;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v1, Lc1/b1;->e:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lc1/b1;->g:I

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v3, :cond_3

    .line 36
    .line 37
    if-eq v3, v5, :cond_2

    .line 38
    .line 39
    if-ne v3, v4, :cond_1

    .line 40
    .line 41
    iget-object v0, v1, Lc1/b1;->d:Ljava/lang/Object;

    .line 42
    .line 43
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_3

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    iget-object v3, v1, Lc1/b1;->d:Ljava/lang/Object;

    .line 56
    .line 57
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    move-object p1, v3

    .line 61
    goto :goto_1

    .line 62
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget-object p1, p0, Lc1/c1;->f:Ll2/j1;

    .line 66
    .line 67
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    iput-object p1, v1, Lc1/b1;->d:Ljava/lang/Object;

    .line 72
    .line 73
    iput v5, v1, Lc1/b1;->g:I

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    if-ne v3, v2, :cond_4

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_4
    :goto_1
    iget-object v3, p0, Lc1/c1;->h:Ljava/lang/Object;

    .line 83
    .line 84
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    const/4 v6, 0x0

    .line 89
    if-eqz v3, :cond_5

    .line 90
    .line 91
    invoke-virtual {v0, v6}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    goto :goto_4

    .line 95
    :cond_5
    iput-object p1, v1, Lc1/b1;->d:Ljava/lang/Object;

    .line 96
    .line 97
    iput v4, v1, Lc1/b1;->g:I

    .line 98
    .line 99
    new-instance v3, Lvy0/l;

    .line 100
    .line 101
    invoke-static {v1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    invoke-direct {v3, v5, v1}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v3}, Lvy0/l;->q()V

    .line 109
    .line 110
    .line 111
    iput-object v3, p0, Lc1/c1;->m:Lvy0/l;

    .line 112
    .line 113
    invoke-virtual {v0, v6}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v3}, Lvy0/l;->p()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    if-ne v0, v2, :cond_6

    .line 121
    .line 122
    :goto_2
    return-object v2

    .line 123
    :cond_6
    move-object v7, v0

    .line 124
    move-object v0, p1

    .line 125
    move-object p1, v7

    .line 126
    :goto_3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    if-eqz v1, :cond_7

    .line 131
    .line 132
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 133
    .line 134
    return-object p0

    .line 135
    :cond_7
    const-wide/high16 v1, -0x8000000000000000L

    .line 136
    .line 137
    iput-wide v1, p0, Lc1/c1;->p:J

    .line 138
    .line 139
    new-instance p0, Ljava/util/concurrent/CancellationException;

    .line 140
    .line 141
    new-instance v1, Ljava/lang/StringBuilder;

    .line 142
    .line 143
    const-string v2, "snapTo() was canceled because state was changed to "

    .line 144
    .line 145
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    const-string p1, " instead of "

    .line 152
    .line 153
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    invoke-direct {p0, p1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    throw p0
.end method

.method public static h0(Lc1/v0;J)V
    .locals 8

    .line 1
    iget-wide v0, p0, Lc1/v0;->a:J

    .line 2
    .line 3
    iget-object v5, p0, Lc1/v0;->e:Lc1/l;

    .line 4
    .line 5
    add-long v3, v0, p1

    .line 6
    .line 7
    iput-wide v3, p0, Lc1/v0;->a:J

    .line 8
    .line 9
    iget-wide p1, p0, Lc1/v0;->h:J

    .line 10
    .line 11
    cmp-long v0, v3, p1

    .line 12
    .line 13
    const/high16 v1, 0x3f800000    # 1.0f

    .line 14
    .line 15
    if-ltz v0, :cond_0

    .line 16
    .line 17
    iput v1, p0, Lc1/v0;->d:F

    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    iget-object v2, p0, Lc1/v0;->b:Lc1/g2;

    .line 21
    .line 22
    const/4 v0, 0x0

    .line 23
    if-eqz v2, :cond_2

    .line 24
    .line 25
    iget-object p1, p0, Lc1/v0;->f:Lc1/l;

    .line 26
    .line 27
    if-nez p1, :cond_1

    .line 28
    .line 29
    sget-object p1, Lc1/c1;->v:Lc1/l;

    .line 30
    .line 31
    :cond_1
    move-object v7, p1

    .line 32
    sget-object v6, Lc1/c1;->w:Lc1/l;

    .line 33
    .line 34
    invoke-interface/range {v2 .. v7}, Lc1/d2;->t(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    check-cast p1, Lc1/l;

    .line 39
    .line 40
    invoke-virtual {p1, v0}, Lc1/l;->a(I)F

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    const/4 p2, 0x0

    .line 45
    invoke-static {p1, p2, v1}, Lkp/r9;->d(FFF)F

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    iput p1, p0, Lc1/v0;->d:F

    .line 50
    .line 51
    return-void

    .line 52
    :cond_2
    invoke-virtual {v5, v0}, Lc1/l;->a(I)F

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    long-to-float v2, v3

    .line 57
    long-to-float p1, p1

    .line 58
    div-float/2addr v2, p1

    .line 59
    const/4 p1, 0x1

    .line 60
    int-to-float p1, p1

    .line 61
    sub-float/2addr p1, v2

    .line 62
    mul-float/2addr p1, v0

    .line 63
    mul-float/2addr v2, v1

    .line 64
    add-float/2addr v2, p1

    .line 65
    iput v2, p0, Lc1/v0;->d:F

    .line 66
    .line 67
    return-void
.end method


# virtual methods
.method public final D()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/c1;->g:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final F()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/c1;->f:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final T(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/c1;->g:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final V(Lc1/w1;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lc1/c1;->i:Lc1/w1;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v1, "An instance of SeekableTransitionState has been used in different Transitions. Previous instance: "

    .line 15
    .line 16
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object v1, p0, Lc1/c1;->i:Lc1/w1;

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string v1, ", new instance: "

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-static {v0}, Lc1/s0;->b(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    :cond_1
    :goto_0
    iput-object p1, p0, Lc1/c1;->i:Lc1/w1;

    .line 40
    .line 41
    return-void
.end method

.method public final W()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lc1/c1;->i:Lc1/w1;

    .line 3
    .line 4
    sget-object v0, Lc1/z1;->b:Ljava/lang/Object;

    .line 5
    .line 6
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Lv2/r;

    .line 11
    .line 12
    invoke-virtual {v0, p0}, Lv2/r;->b(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final f0(Lrx0/c;)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-interface {p1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lc1/d;->p(Lpx0/g;)F

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    cmpg-float v1, v0, v1

    .line 11
    .line 12
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    if-gtz v1, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Lc1/c1;->g0()V

    .line 17
    .line 18
    .line 19
    return-object v2

    .line 20
    :cond_0
    iput v0, p0, Lc1/c1;->t:F

    .line 21
    .line 22
    invoke-interface {p1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-static {v0}, Ll2/b;->k(Lpx0/g;)Ll2/y0;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iget-object p0, p0, Lc1/c1;->u:Lc1/u0;

    .line 31
    .line 32
    invoke-interface {v0, p0, p1}, Ll2/y0;->q(Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 37
    .line 38
    if-ne p0, p1, :cond_1

    .line 39
    .line 40
    return-object p0

    .line 41
    :cond_1
    return-object v2
.end method

.method public final g0()V
    .locals 1

    .line 1
    iget-object v0, p0, Lc1/c1;->i:Lc1/w1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lc1/w1;->c()V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object v0, p0, Lc1/c1;->q:Landroidx/collection/l0;

    .line 9
    .line 10
    invoke-virtual {v0}, Landroidx/collection/l0;->c()V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lc1/c1;->r:Lc1/v0;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-object v0, p0, Lc1/c1;->r:Lc1/v0;

    .line 19
    .line 20
    const/high16 v0, 0x3f800000    # 1.0f

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Lc1/c1;->k0(F)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Lc1/c1;->j0()V

    .line 26
    .line 27
    .line 28
    :cond_1
    return-void
.end method

.method public final i0(FLjava/lang/Object;Lrx0/i;)Ljava/lang/Object;
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    cmpg-float v0, v0, p1

    .line 3
    .line 4
    if-gtz v0, :cond_0

    .line 5
    .line 6
    const/high16 v0, 0x3f800000    # 1.0f

    .line 7
    .line 8
    cmpg-float v0, p1, v0

    .line 9
    .line 10
    if-gtz v0, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v1, "Expecting fraction between 0 and 1. Got "

    .line 16
    .line 17
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-static {v0}, Lc1/s0;->a(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object v5, p0, Lc1/c1;->i:Lc1/w1;

    .line 31
    .line 32
    if-nez v5, :cond_1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    iget-object v0, p0, Lc1/c1;->f:Ll2/j1;

    .line 36
    .line 37
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    new-instance v1, Lc1/z0;

    .line 42
    .line 43
    const/4 v7, 0x0

    .line 44
    move-object v4, p0

    .line 45
    move v6, p1

    .line 46
    move-object v2, p2

    .line 47
    invoke-direct/range {v1 .. v7}, Lc1/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Lc1/c1;Lc1/w1;FLkotlin/coroutines/Continuation;)V

    .line 48
    .line 49
    .line 50
    iget-object p0, v4, Lc1/c1;->o:Lc1/r0;

    .line 51
    .line 52
    invoke-static {p0, v1, p3}, Lc1/r0;->a(Lc1/r0;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 57
    .line 58
    if-ne p0, p1, :cond_2

    .line 59
    .line 60
    return-object p0

    .line 61
    :cond_2
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 62
    .line 63
    return-object p0
.end method

.method public final j0()V
    .locals 5

    .line 1
    iget-object v0, p0, Lc1/c1;->i:Lc1/w1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object p0, p0, Lc1/c1;->l:Ll2/f1;

    .line 7
    .line 8
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    float-to-double v1, p0

    .line 13
    iget-object p0, v0, Lc1/w1;->l:Ll2/h0;

    .line 14
    .line 15
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Ljava/lang/Number;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 22
    .line 23
    .line 24
    move-result-wide v3

    .line 25
    long-to-double v3, v3

    .line 26
    mul-double/2addr v1, v3

    .line 27
    invoke-static {v1, v2}, Lcy0/a;->j(D)J

    .line 28
    .line 29
    .line 30
    move-result-wide v1

    .line 31
    invoke-virtual {v0, v1, v2}, Lc1/w1;->l(J)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public final k0(F)V
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/c1;->l:Ll2/f1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
