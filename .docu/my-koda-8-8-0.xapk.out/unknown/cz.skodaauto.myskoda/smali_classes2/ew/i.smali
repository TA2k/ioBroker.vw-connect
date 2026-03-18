.class public final Lew/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lkw/j;

.field public final b:Lkw/l;

.field public final c:Lj9/d;

.field public final d:Lc1/j;

.field public final e:Ll2/f1;

.field public final f:Ll2/f1;

.field public g:Z

.field public h:Lkw/g;

.field public i:Lkw/i;

.field public j:Landroid/graphics/RectF;

.field public final k:Z

.field public final l:Lyy0/q1;

.field public final m:Lg1/f0;


# direct methods
.method public constructor <init>(ZLkw/j;Lkw/l;Lj9/d;Lc1/j;FZ)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ll2/f1;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Ll2/f1;-><init>(F)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lew/i;->f:Ll2/f1;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    const/4 v1, 0x5

    .line 14
    const/4 v2, 0x1

    .line 15
    invoke-static {v2, v1, v0}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iput-object v0, p0, Lew/i;->l:Lyy0/q1;

    .line 20
    .line 21
    new-instance v0, Lew/b;

    .line 22
    .line 23
    const/4 v1, 0x1

    .line 24
    invoke-direct {v0, p0, v1}, Lew/b;-><init>(Lew/i;I)V

    .line 25
    .line 26
    .line 27
    new-instance v1, Lg1/f0;

    .line 28
    .line 29
    invoke-direct {v1, v0}, Lg1/f0;-><init>(Lay0/k;)V

    .line 30
    .line 31
    .line 32
    iput-object v1, p0, Lew/i;->m:Lg1/f0;

    .line 33
    .line 34
    iput-boolean p1, p0, Lew/i;->k:Z

    .line 35
    .line 36
    iput-object p2, p0, Lew/i;->a:Lkw/j;

    .line 37
    .line 38
    iput-object p3, p0, Lew/i;->b:Lkw/l;

    .line 39
    .line 40
    iput-object p4, p0, Lew/i;->c:Lj9/d;

    .line 41
    .line 42
    iput-object p5, p0, Lew/i;->d:Lc1/j;

    .line 43
    .line 44
    new-instance p1, Ll2/f1;

    .line 45
    .line 46
    invoke-direct {p1, p6}, Ll2/f1;-><init>(F)V

    .line 47
    .line 48
    .line 49
    iput-object p1, p0, Lew/i;->e:Ll2/f1;

    .line 50
    .line 51
    iput-boolean p7, p0, Lew/i;->g:Z

    .line 52
    .line 53
    return-void
.end method


# virtual methods
.method public final a(Lmw/a;Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p2, Lew/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lew/h;

    .line 7
    .line 8
    iget v1, v0, Lew/h;->g:I

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
    iput v1, v0, Lew/h;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lew/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lew/h;-><init>(Lew/i;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lew/h;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lew/h;->g:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    if-eq v2, v5, :cond_2

    .line 39
    .line 40
    if-ne v2, v4, :cond_1

    .line 41
    .line 42
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-object v6

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
    iget-object p0, v0, Lew/h;->d:Lew/i;

    .line 55
    .line 56
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object v7, p0, Lew/i;->b:Lkw/l;

    .line 60
    .line 61
    iget-object p1, p0, Lew/i;->d:Lc1/j;

    .line 62
    .line 63
    iput-object v3, v0, Lew/h;->d:Lew/i;

    .line 64
    .line 65
    iput v4, v0, Lew/h;->g:I

    .line 66
    .line 67
    iget-object v8, p0, Lew/i;->h:Lkw/g;

    .line 68
    .line 69
    iget-object v9, p0, Lew/i;->i:Lkw/i;

    .line 70
    .line 71
    iget-object v10, p0, Lew/i;->j:Landroid/graphics/RectF;

    .line 72
    .line 73
    if-eqz v8, :cond_3

    .line 74
    .line 75
    if-eqz v9, :cond_3

    .line 76
    .line 77
    if-eqz v10, :cond_3

    .line 78
    .line 79
    iget-object p2, p0, Lew/i;->m:Lg1/f0;

    .line 80
    .line 81
    iget-object v2, p0, Lew/i;->f:Ll2/f1;

    .line 82
    .line 83
    invoke-virtual {v2}, Ll2/f1;->o()F

    .line 84
    .line 85
    .line 86
    move-result v11

    .line 87
    iget-object p0, p0, Lew/i;->e:Ll2/f1;

    .line 88
    .line 89
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 90
    .line 91
    .line 92
    move-result v12

    .line 93
    invoke-static/range {v7 .. v12}, Llp/ie;->a(Lkw/l;Lkw/g;Lkw/i;Landroid/graphics/RectF;FF)F

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    invoke-static {p2, p0, p1, v0}, Lg1/h3;->a(Lg1/q2;FLc1/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    if-ne p0, v1, :cond_3

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_3
    move-object p0, v6

    .line 105
    :goto_1
    if-ne p0, v1, :cond_5

    .line 106
    .line 107
    return-object v1

    .line 108
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    iget-object p0, p0, Lew/i;->c:Lj9/d;

    .line 112
    .line 113
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 114
    .line 115
    .line 116
    const-string p0, "<unused var>"

    .line 117
    .line 118
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    :cond_5
    return-object v6
.end method

.method public final b(F)V
    .locals 5

    .line 1
    iget-object v0, p0, Lew/i;->e:Ll2/f1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iget-object v2, p0, Lew/i;->f:Ll2/f1;

    .line 12
    .line 13
    invoke-virtual {v2}, Ll2/f1;->o()F

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v3, 0x0

    .line 18
    cmpl-float v4, v2, v3

    .line 19
    .line 20
    if-lez v4, :cond_0

    .line 21
    .line 22
    new-instance v4, Lgy0/e;

    .line 23
    .line 24
    invoke-direct {v4, v3, v2}, Lgy0/e;-><init>(FF)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v4, Lgy0/e;

    .line 29
    .line 30
    invoke-direct {v4, v2, v3}, Lgy0/e;-><init>(FF)V

    .line 31
    .line 32
    .line 33
    :goto_0
    invoke-static {p1, v4}, Lkp/r9;->i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    check-cast p1, Ljava/lang/Number;

    .line 38
    .line 39
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    invoke-virtual {v0, p1}, Ll2/f1;->p(F)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    cmpg-float p1, p1, v1

    .line 51
    .line 52
    if-nez p1, :cond_1

    .line 53
    .line 54
    return-void

    .line 55
    :cond_1
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    sub-float/2addr v1, p1

    .line 60
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    iget-object p0, p0, Lew/i;->l:Lyy0/q1;

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    return-void
.end method
