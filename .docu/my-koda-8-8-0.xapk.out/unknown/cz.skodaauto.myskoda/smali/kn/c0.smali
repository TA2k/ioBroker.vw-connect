.class public final Lkn/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lay0/k;

.field public final b:Ll2/j1;

.field public final c:Ll2/g1;

.field public d:F

.field public final e:Ll2/f1;

.field public final f:Lc1/c;

.field public final g:Lc1/k;

.field public final h:Ll2/f1;

.field public i:Lvy0/i1;

.field public j:Lc1/j;

.field public k:Lc1/j;

.field public l:Lkn/l0;

.field public m:Z

.field public n:Z

.field public o:Lvy0/x1;

.field public p:F

.field public final q:Lh6/j;

.field public final r:Ll2/j1;

.field public final s:Ll2/j1;


# direct methods
.method public synthetic constructor <init>(Lkn/f0;I)V
    .locals 0

    and-int/lit8 p2, p2, 0x1

    if-eqz p2, :cond_0

    .line 17
    sget-object p1, Lkn/f0;->f:Lkn/f0;

    .line 18
    :cond_0
    sget-object p2, Lkn/u;->g:Lkn/u;

    .line 19
    invoke-direct {p0, p1, p2}, Lkn/c0;-><init>(Lkn/f0;Lay0/k;)V

    return-void
.end method

.method public constructor <init>(Lkn/f0;Lay0/k;)V
    .locals 1

    const-string v0, "initialValue"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "confirmValueChange"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p2, p0, Lkn/c0;->a:Lay0/k;

    .line 3
    sget-object p2, Lkn/f0;->f:Lkn/f0;

    const/4 v0, 0x0

    if-eq p1, p2, :cond_0

    const/4 p2, 0x1

    goto :goto_0

    :cond_0
    move p2, v0

    :goto_0
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p2

    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object p2

    iput-object p2, p0, Lkn/c0;->b:Ll2/j1;

    .line 4
    new-instance p2, Ll2/g1;

    invoke-direct {p2, v0}, Ll2/g1;-><init>(I)V

    .line 5
    iput-object p2, p0, Lkn/c0;->c:Ll2/g1;

    const p2, 0x3ee66666    # 0.45f

    .line 6
    iput p2, p0, Lkn/c0;->d:F

    .line 7
    new-instance p2, Ll2/f1;

    const/4 v0, 0x0

    invoke-direct {p2, v0}, Ll2/f1;-><init>(F)V

    .line 8
    iput-object p2, p0, Lkn/c0;->e:Ll2/f1;

    .line 9
    invoke-static {v0}, Lc1/d;->a(F)Lc1/c;

    move-result-object p2

    iput-object p2, p0, Lkn/c0;->f:Lc1/c;

    .line 10
    iget-object p2, p2, Lc1/c;->c:Lc1/k;

    .line 11
    iput-object p2, p0, Lkn/c0;->g:Lc1/k;

    .line 12
    new-instance p2, Ll2/f1;

    invoke-direct {p2, v0}, Ll2/f1;-><init>(F)V

    .line 13
    iput-object p2, p0, Lkn/c0;->h:Ll2/f1;

    .line 14
    new-instance p2, Lh6/j;

    invoke-direct {p2}, Lh6/j;-><init>()V

    iput-object p2, p0, Lkn/c0;->q:Lh6/j;

    .line 15
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object p1

    iput-object p1, p0, Lkn/c0;->r:Ll2/j1;

    .line 16
    sget-object p1, Lkn/v;->d:Lkn/v;

    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    move-result-object p1

    iput-object p1, p0, Lkn/c0;->s:Ll2/j1;

    return-void
.end method

.method public static d(Lkn/c0;Lrx0/i;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lkn/c0;->p:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0x46c35000    # 25000.0f

    .line 8
    .line 9
    .line 10
    div-float/2addr v0, v1

    .line 11
    const/4 v1, 0x0

    .line 12
    const/high16 v2, 0x3f800000    # 1.0f

    .line 13
    .line 14
    invoke-static {v0, v1, v2}, Lkp/r9;->d(FFF)F

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    const/16 v1, 0x113

    .line 19
    .line 20
    int-to-float v1, v1

    .line 21
    const v2, 0x3f333333    # 0.7f

    .line 22
    .line 23
    .line 24
    mul-float/2addr v2, v1

    .line 25
    mul-float/2addr v2, v0

    .line 26
    sub-float/2addr v1, v2

    .line 27
    float-to-int v0, v1

    .line 28
    const/4 v1, 0x0

    .line 29
    const/4 v2, 0x6

    .line 30
    const/4 v3, 0x0

    .line 31
    invoke-static {v0, v3, v1, v2}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    const/4 v1, 0x1

    .line 36
    invoke-virtual {p0, v1, v0, p1}, Lkn/c0;->c(ZLc1/a2;Lrx0/c;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method

.method public static synthetic f(Lkn/c0;Lc1/j;Lrx0/i;I)Ljava/lang/Object;
    .locals 2

    .line 1
    and-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    const/high16 p1, 0x43b90000    # 370.0f

    .line 6
    .line 7
    const/4 p3, 0x4

    .line 8
    const v0, 0x3f59999a    # 0.85f

    .line 9
    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-static {v0, p1, v1, p3}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    :cond_0
    const/4 p3, 0x1

    .line 17
    invoke-virtual {p0, p3, p1, p2}, Lkn/c0;->e(ZLc1/j;Lrx0/c;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public static synthetic k(Lkn/c0;Lc1/j;Lrx0/i;I)Ljava/lang/Object;
    .locals 2

    .line 1
    and-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    const/high16 p1, 0x43b90000    # 370.0f

    .line 6
    .line 7
    const/4 p3, 0x4

    .line 8
    const v0, 0x3f59999a    # 0.85f

    .line 9
    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-static {v0, p1, v1, p3}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    :cond_0
    const/4 p3, 0x1

    .line 17
    invoke-virtual {p0, p3, p1, p2}, Lkn/c0;->j(ZLc1/j;Lrx0/c;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method


# virtual methods
.method public final a(FLrx0/i;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lkn/c0;->f:Lc1/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lc1/c;->d()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    add-float/2addr v0, p1

    .line 14
    const/4 p1, 0x1

    .line 15
    invoke-virtual {p0, v0, p1, p2}, Lkn/c0;->l(FZLrx0/c;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    if-ne p0, p1, :cond_0

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    return-object p0
.end method

.method public final b(Lkn/f0;)Lb1/x0;
    .locals 3

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p1, :cond_2

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    iget-object v2, p0, Lkn/c0;->c:Ll2/g1;

    .line 10
    .line 11
    if-eq p1, v1, :cond_1

    .line 12
    .line 13
    const/4 p0, 0x2

    .line 14
    if-ne p1, p0, :cond_0

    .line 15
    .line 16
    new-instance p0, Lb1/x0;

    .line 17
    .line 18
    invoke-virtual {v2}, Ll2/g1;->o()I

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    int-to-float p1, p1

    .line 23
    invoke-direct {p0, p1, v0}, Lb1/x0;-><init>(FF)V

    .line 24
    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_0
    new-instance p0, La8/r0;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-virtual {p0}, Lkn/c0;->h()F

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    invoke-virtual {v2}, Ll2/g1;->o()I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    int-to-float v0, v0

    .line 42
    sub-float/2addr v0, p1

    .line 43
    invoke-virtual {v2}, Ll2/g1;->o()I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    int-to-float v1, v1

    .line 48
    div-float/2addr p1, v1

    .line 49
    iget p0, p0, Lkn/c0;->d:F

    .line 50
    .line 51
    mul-float/2addr p1, p0

    .line 52
    new-instance p0, Lb1/x0;

    .line 53
    .line 54
    invoke-direct {p0, v0, p1}, Lb1/x0;-><init>(FF)V

    .line 55
    .line 56
    .line 57
    return-object p0

    .line 58
    :cond_2
    new-instance p1, Lb1/x0;

    .line 59
    .line 60
    iget p0, p0, Lkn/c0;->d:F

    .line 61
    .line 62
    invoke-direct {p1, v0, p0}, Lb1/x0;-><init>(FF)V

    .line 63
    .line 64
    .line 65
    return-object p1
.end method

.method public final c(ZLc1/a2;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Lkn/w;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lkn/w;

    .line 7
    .line 8
    iget v1, v0, Lkn/w;->k:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lkn/w;->k:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkn/w;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lkn/w;-><init>(Lkn/c0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lkn/w;->i:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkn/w;->k:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-object p0, v0, Lkn/w;->g:Lkn/c0;

    .line 40
    .line 41
    iget-object p1, v0, Lkn/w;->f:Lkn/f0;

    .line 42
    .line 43
    iget-object p2, v0, Lkn/w;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p2, Lkn/f0;

    .line 46
    .line 47
    iget-object v0, v0, Lkn/w;->d:Lkn/c0;

    .line 48
    .line 49
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto :goto_4

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_2
    iget-boolean p1, v0, Lkn/w;->h:Z

    .line 62
    .line 63
    iget-object p0, v0, Lkn/w;->e:Ljava/lang/Object;

    .line 64
    .line 65
    move-object p2, p0

    .line 66
    check-cast p2, Lc1/j;

    .line 67
    .line 68
    iget-object p0, v0, Lkn/w;->d:Lkn/c0;

    .line 69
    .line 70
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iput-object p0, v0, Lkn/w;->d:Lkn/c0;

    .line 78
    .line 79
    iput-object p2, v0, Lkn/w;->e:Ljava/lang/Object;

    .line 80
    .line 81
    iput-boolean p1, v0, Lkn/w;->h:Z

    .line 82
    .line 83
    iput v4, v0, Lkn/w;->k:I

    .line 84
    .line 85
    invoke-virtual {p0, v0}, Lkn/c0;->o(Lrx0/c;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p3

    .line 89
    if-ne p3, v1, :cond_4

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_4
    :goto_1
    sget-object p3, Lkn/f0;->f:Lkn/f0;

    .line 93
    .line 94
    iget-object v2, p0, Lkn/c0;->a:Lay0/k;

    .line 95
    .line 96
    invoke-interface {v2, p3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    check-cast v2, Ljava/lang/Boolean;

    .line 101
    .line 102
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 103
    .line 104
    .line 105
    move-result v2

    .line 106
    if-eqz v2, :cond_5

    .line 107
    .line 108
    move-object v2, p3

    .line 109
    goto :goto_2

    .line 110
    :cond_5
    invoke-virtual {p0}, Lkn/c0;->i()Lkn/f0;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    :goto_2
    iput-object p0, v0, Lkn/w;->d:Lkn/c0;

    .line 115
    .line 116
    iput-object p3, v0, Lkn/w;->e:Ljava/lang/Object;

    .line 117
    .line 118
    iput-object v2, v0, Lkn/w;->f:Lkn/f0;

    .line 119
    .line 120
    iput-object p0, v0, Lkn/w;->g:Lkn/c0;

    .line 121
    .line 122
    iput v3, v0, Lkn/w;->k:I

    .line 123
    .line 124
    invoke-virtual {p0, v2, p1, p2, v0}, Lkn/c0;->m(Lkn/f0;ZLc1/j;Lrx0/c;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    if-ne p1, v1, :cond_6

    .line 129
    .line 130
    :goto_3
    return-object v1

    .line 131
    :cond_6
    move-object v0, p0

    .line 132
    move-object p2, p3

    .line 133
    move-object p3, p1

    .line 134
    move-object p1, v2

    .line 135
    :goto_4
    check-cast p3, Lvy0/i1;

    .line 136
    .line 137
    new-instance v1, Lkn/x;

    .line 138
    .line 139
    const/4 v2, 0x0

    .line 140
    invoke-direct {v1, p1, p2, v0, v2}, Lkn/x;-><init>(Lkn/f0;Lkn/f0;Lkn/c0;I)V

    .line 141
    .line 142
    .line 143
    invoke-interface {p3, v1}, Lvy0/i1;->E(Lay0/k;)Lvy0/r0;

    .line 144
    .line 145
    .line 146
    iput-object p3, p0, Lkn/c0;->i:Lvy0/i1;

    .line 147
    .line 148
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 149
    .line 150
    return-object p0
.end method

.method public final e(ZLc1/j;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Lkn/y;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lkn/y;

    .line 7
    .line 8
    iget v1, v0, Lkn/y;->k:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lkn/y;->k:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkn/y;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lkn/y;-><init>(Lkn/c0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lkn/y;->i:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkn/y;->k:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-object p0, v0, Lkn/y;->g:Lkn/c0;

    .line 40
    .line 41
    iget-object p1, v0, Lkn/y;->f:Lkn/f0;

    .line 42
    .line 43
    iget-object p2, v0, Lkn/y;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p2, Lkn/f0;

    .line 46
    .line 47
    iget-object v0, v0, Lkn/y;->d:Lkn/c0;

    .line 48
    .line 49
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto :goto_4

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_2
    iget-boolean p1, v0, Lkn/y;->h:Z

    .line 62
    .line 63
    iget-object p0, v0, Lkn/y;->e:Ljava/lang/Object;

    .line 64
    .line 65
    move-object p2, p0

    .line 66
    check-cast p2, Lc1/j;

    .line 67
    .line 68
    iget-object p0, v0, Lkn/y;->d:Lkn/c0;

    .line 69
    .line 70
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iput-object p0, v0, Lkn/y;->d:Lkn/c0;

    .line 78
    .line 79
    iput-object p2, v0, Lkn/y;->e:Ljava/lang/Object;

    .line 80
    .line 81
    iput-boolean p1, v0, Lkn/y;->h:Z

    .line 82
    .line 83
    iput v4, v0, Lkn/y;->k:I

    .line 84
    .line 85
    invoke-virtual {p0, v0}, Lkn/c0;->o(Lrx0/c;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p3

    .line 89
    if-ne p3, v1, :cond_4

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_4
    :goto_1
    iput-object p2, p0, Lkn/c0;->j:Lc1/j;

    .line 93
    .line 94
    iget-object p3, p0, Lkn/c0;->b:Ll2/j1;

    .line 95
    .line 96
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 97
    .line 98
    invoke-virtual {p3, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    sget-object p3, Lkn/f0;->d:Lkn/f0;

    .line 102
    .line 103
    iget-object v2, p0, Lkn/c0;->a:Lay0/k;

    .line 104
    .line 105
    invoke-interface {v2, p3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    check-cast v2, Ljava/lang/Boolean;

    .line 110
    .line 111
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    if-eqz v2, :cond_5

    .line 116
    .line 117
    move-object v2, p3

    .line 118
    goto :goto_2

    .line 119
    :cond_5
    invoke-virtual {p0}, Lkn/c0;->i()Lkn/f0;

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    :goto_2
    iput-object p0, v0, Lkn/y;->d:Lkn/c0;

    .line 124
    .line 125
    iput-object p3, v0, Lkn/y;->e:Ljava/lang/Object;

    .line 126
    .line 127
    iput-object v2, v0, Lkn/y;->f:Lkn/f0;

    .line 128
    .line 129
    iput-object p0, v0, Lkn/y;->g:Lkn/c0;

    .line 130
    .line 131
    iput v3, v0, Lkn/y;->k:I

    .line 132
    .line 133
    invoke-virtual {p0, v2, p1, p2, v0}, Lkn/c0;->m(Lkn/f0;ZLc1/j;Lrx0/c;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    if-ne p1, v1, :cond_6

    .line 138
    .line 139
    :goto_3
    return-object v1

    .line 140
    :cond_6
    move-object v0, p0

    .line 141
    move-object p2, p3

    .line 142
    move-object p3, p1

    .line 143
    move-object p1, v2

    .line 144
    :goto_4
    check-cast p3, Lvy0/i1;

    .line 145
    .line 146
    new-instance v1, Lkn/x;

    .line 147
    .line 148
    const/4 v2, 0x1

    .line 149
    invoke-direct {v1, p1, p2, v0, v2}, Lkn/x;-><init>(Lkn/f0;Lkn/f0;Lkn/c0;I)V

    .line 150
    .line 151
    .line 152
    invoke-interface {p3, v1}, Lvy0/i1;->E(Lay0/k;)Lvy0/r0;

    .line 153
    .line 154
    .line 155
    iput-object p3, p0, Lkn/c0;->i:Lvy0/i1;

    .line 156
    .line 157
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 158
    .line 159
    return-object p0
.end method

.method public final g()F
    .locals 0

    .line 1
    iget-object p0, p0, Lkn/c0;->g:Lc1/k;

    .line 2
    .line 3
    iget-object p0, p0, Lc1/k;->e:Ll2/j1;

    .line 4
    .line 5
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public final h()F
    .locals 3

    .line 1
    iget-object v0, p0, Lkn/c0;->l:Lkn/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lkn/c0;->c:Ll2/g1;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    int-to-float p0, p0

    .line 12
    return p0

    .line 13
    :cond_0
    instance-of v0, v0, Lkn/l0;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    const/high16 v1, 0x3f800000    # 1.0f

    .line 19
    .line 20
    const/high16 v2, 0x3f000000    # 0.5f

    .line 21
    .line 22
    invoke-static {v2, v0, v1}, Lkp/r9;->d(FFF)F

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    int-to-float p0, p0

    .line 31
    mul-float/2addr v0, p0

    .line 32
    return v0

    .line 33
    :cond_1
    new-instance p0, La8/r0;

    .line 34
    .line 35
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 36
    .line 37
    .line 38
    throw p0
.end method

.method public final i()Lkn/f0;
    .locals 0

    .line 1
    iget-object p0, p0, Lkn/c0;->r:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lkn/f0;

    .line 8
    .line 9
    return-object p0
.end method

.method public final j(ZLc1/j;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Lkn/z;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lkn/z;

    .line 7
    .line 8
    iget v1, v0, Lkn/z;->k:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lkn/z;->k:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkn/z;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lkn/z;-><init>(Lkn/c0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lkn/z;->i:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkn/z;->k:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-object p0, v0, Lkn/z;->g:Lkn/c0;

    .line 40
    .line 41
    iget-object p1, v0, Lkn/z;->f:Lkn/f0;

    .line 42
    .line 43
    iget-object p2, v0, Lkn/z;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p2, Lkn/f0;

    .line 46
    .line 47
    iget-object v0, v0, Lkn/z;->d:Lkn/c0;

    .line 48
    .line 49
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto :goto_4

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_2
    iget-boolean p1, v0, Lkn/z;->h:Z

    .line 62
    .line 63
    iget-object p0, v0, Lkn/z;->e:Ljava/lang/Object;

    .line 64
    .line 65
    move-object p2, p0

    .line 66
    check-cast p2, Lc1/j;

    .line 67
    .line 68
    iget-object p0, v0, Lkn/z;->d:Lkn/c0;

    .line 69
    .line 70
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iput-object p0, v0, Lkn/z;->d:Lkn/c0;

    .line 78
    .line 79
    iput-object p2, v0, Lkn/z;->e:Ljava/lang/Object;

    .line 80
    .line 81
    iput-boolean p1, v0, Lkn/z;->h:Z

    .line 82
    .line 83
    iput v4, v0, Lkn/z;->k:I

    .line 84
    .line 85
    invoke-virtual {p0, v0}, Lkn/c0;->o(Lrx0/c;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p3

    .line 89
    if-ne p3, v1, :cond_4

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_4
    :goto_1
    iput-object p2, p0, Lkn/c0;->k:Lc1/j;

    .line 93
    .line 94
    iget-object p3, p0, Lkn/c0;->b:Ll2/j1;

    .line 95
    .line 96
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 97
    .line 98
    invoke-virtual {p3, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    sget-object p3, Lkn/f0;->e:Lkn/f0;

    .line 102
    .line 103
    iget-object v2, p0, Lkn/c0;->a:Lay0/k;

    .line 104
    .line 105
    invoke-interface {v2, p3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    check-cast v2, Ljava/lang/Boolean;

    .line 110
    .line 111
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    if-eqz v2, :cond_5

    .line 116
    .line 117
    move-object v2, p3

    .line 118
    goto :goto_2

    .line 119
    :cond_5
    invoke-virtual {p0}, Lkn/c0;->i()Lkn/f0;

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    :goto_2
    iput-object p0, v0, Lkn/z;->d:Lkn/c0;

    .line 124
    .line 125
    iput-object p3, v0, Lkn/z;->e:Ljava/lang/Object;

    .line 126
    .line 127
    iput-object v2, v0, Lkn/z;->f:Lkn/f0;

    .line 128
    .line 129
    iput-object p0, v0, Lkn/z;->g:Lkn/c0;

    .line 130
    .line 131
    iput v3, v0, Lkn/z;->k:I

    .line 132
    .line 133
    invoke-virtual {p0, v2, p1, p2, v0}, Lkn/c0;->m(Lkn/f0;ZLc1/j;Lrx0/c;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    if-ne p1, v1, :cond_6

    .line 138
    .line 139
    :goto_3
    return-object v1

    .line 140
    :cond_6
    move-object v0, p0

    .line 141
    move-object p2, p3

    .line 142
    move-object p3, p1

    .line 143
    move-object p1, v2

    .line 144
    :goto_4
    check-cast p3, Lvy0/i1;

    .line 145
    .line 146
    new-instance v1, Lkn/x;

    .line 147
    .line 148
    const/4 v2, 0x2

    .line 149
    invoke-direct {v1, p1, p2, v0, v2}, Lkn/x;-><init>(Lkn/f0;Lkn/f0;Lkn/c0;I)V

    .line 150
    .line 151
    .line 152
    invoke-interface {p3, v1}, Lvy0/i1;->E(Lay0/k;)Lvy0/r0;

    .line 153
    .line 154
    .line 155
    iput-object p3, p0, Lkn/c0;->i:Lvy0/i1;

    .line 156
    .line 157
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 158
    .line 159
    return-object p0
.end method

.method public final l(FZLrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lkn/a0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lkn/a0;

    .line 7
    .line 8
    iget v1, v0, Lkn/a0;->i:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lkn/a0;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkn/a0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lkn/a0;-><init>(Lkn/c0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lkn/a0;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkn/a0;->i:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v5, :cond_2

    .line 37
    .line 38
    if-ne v2, v4, :cond_1

    .line 39
    .line 40
    iget-boolean p0, v0, Lkn/a0;->f:Z

    .line 41
    .line 42
    iget-object p1, v0, Lkn/a0;->d:Lkn/c0;

    .line 43
    .line 44
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_3

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    iget-boolean p2, v0, Lkn/a0;->f:Z

    .line 57
    .line 58
    iget p1, v0, Lkn/a0;->e:F

    .line 59
    .line 60
    iget-object p0, v0, Lkn/a0;->d:Lkn/c0;

    .line 61
    .line 62
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iput-object p0, v0, Lkn/a0;->d:Lkn/c0;

    .line 70
    .line 71
    iput p1, v0, Lkn/a0;->e:F

    .line 72
    .line 73
    iput-boolean p2, v0, Lkn/a0;->f:Z

    .line 74
    .line 75
    iput v5, v0, Lkn/a0;->i:I

    .line 76
    .line 77
    iget-object p3, p0, Lkn/c0;->f:Lc1/c;

    .line 78
    .line 79
    invoke-virtual {p3, v0}, Lc1/c;->g(Lrx0/c;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p3

    .line 83
    if-ne p3, v1, :cond_4

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_4
    :goto_1
    iget-object p3, p0, Lkn/c0;->f:Lc1/c;

    .line 87
    .line 88
    invoke-static {v3, p1}, Ljava/lang/Math;->max(FF)F

    .line 89
    .line 90
    .line 91
    move-result p1

    .line 92
    new-instance v2, Ljava/lang/Float;

    .line 93
    .line 94
    invoke-direct {v2, p1}, Ljava/lang/Float;-><init>(F)V

    .line 95
    .line 96
    .line 97
    iput-object p0, v0, Lkn/a0;->d:Lkn/c0;

    .line 98
    .line 99
    iput-boolean p2, v0, Lkn/a0;->f:Z

    .line 100
    .line 101
    iput v4, v0, Lkn/a0;->i:I

    .line 102
    .line 103
    invoke-virtual {p3, v2, v0}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    if-ne p1, v1, :cond_5

    .line 108
    .line 109
    :goto_2
    return-object v1

    .line 110
    :cond_5
    move-object p1, p0

    .line 111
    move p0, p2

    .line 112
    :goto_3
    if-eqz p0, :cond_7

    .line 113
    .line 114
    iget-object p0, p1, Lkn/c0;->c:Ll2/g1;

    .line 115
    .line 116
    iget-object p2, p1, Lkn/c0;->c:Ll2/g1;

    .line 117
    .line 118
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    if-eqz p0, :cond_6

    .line 123
    .line 124
    invoke-virtual {p2}, Ll2/g1;->o()I

    .line 125
    .line 126
    .line 127
    move-result p0

    .line 128
    int-to-float p0, p0

    .line 129
    invoke-virtual {p1}, Lkn/c0;->g()F

    .line 130
    .line 131
    .line 132
    move-result p3

    .line 133
    sub-float/2addr p0, p3

    .line 134
    invoke-virtual {p2}, Ll2/g1;->o()I

    .line 135
    .line 136
    .line 137
    move-result p2

    .line 138
    int-to-float p2, p2

    .line 139
    div-float/2addr p0, p2

    .line 140
    goto :goto_4

    .line 141
    :cond_6
    move p0, v3

    .line 142
    :goto_4
    iget p2, p1, Lkn/c0;->d:F

    .line 143
    .line 144
    const/high16 p3, 0x3f800000    # 1.0f

    .line 145
    .line 146
    invoke-static {p0, v3, p3}, Lkp/r9;->d(FFF)F

    .line 147
    .line 148
    .line 149
    move-result p0

    .line 150
    mul-float/2addr p0, p2

    .line 151
    iget-object p1, p1, Lkn/c0;->e:Ll2/f1;

    .line 152
    .line 153
    invoke-virtual {p1, p0}, Ll2/f1;->p(F)V

    .line 154
    .line 155
    .line 156
    :cond_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 157
    .line 158
    return-object p0
.end method

.method public final m(Lkn/f0;ZLc1/j;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    if-eq v0, v1, :cond_1

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    sget-object v0, Lkn/v;->g:Lkn/v;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    new-instance p0, La8/r0;

    .line 17
    .line 18
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :cond_1
    sget-object v0, Lkn/v;->e:Lkn/v;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_2
    sget-object v0, Lkn/v;->f:Lkn/v;

    .line 26
    .line 27
    :goto_0
    iget-object v1, p0, Lkn/c0;->s:Ll2/j1;

    .line 28
    .line 29
    invoke-virtual {v1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    new-instance v2, Lkn/b0;

    .line 33
    .line 34
    const/4 v7, 0x0

    .line 35
    move-object v4, p0

    .line 36
    move-object v5, p1

    .line 37
    move v3, p2

    .line 38
    move-object v6, p3

    .line 39
    invoke-direct/range {v2 .. v7}, Lkn/b0;-><init>(ZLkn/c0;Lkn/f0;Lc1/j;Lkotlin/coroutines/Continuation;)V

    .line 40
    .line 41
    .line 42
    invoke-static {v2, p4}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method

.method public final n()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lkn/c0;->c:Ll2/g1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_2

    .line 8
    .line 9
    iget-object v1, p0, Lkn/c0;->l:Lkn/l0;

    .line 10
    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-boolean v1, p0, Lkn/c0;->m:Z

    .line 15
    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0}, Lkn/c0;->h()F

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    int-to-float v0, v0

    .line 27
    cmpl-float p0, p0, v0

    .line 28
    .line 29
    if-ltz p0, :cond_2

    .line 30
    .line 31
    :cond_1
    const/4 p0, 0x1

    .line 32
    return p0

    .line 33
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 34
    return p0
.end method

.method public final o(Lrx0/c;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lkn/c0;->i:Lvy0/i1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-interface {v0, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 7
    .line 8
    .line 9
    :cond_0
    iget-object p0, p0, Lkn/c0;->f:Lc1/c;

    .line 10
    .line 11
    invoke-virtual {p0}, Lc1/c;->e()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lc1/c;->g(Lrx0/c;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 22
    .line 23
    if-ne p0, p1, :cond_1

    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0
.end method
