.class public abstract Lg1/d1;
.super Lv3/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/t1;


# instance fields
.field public A:J

.field public B:Lp3/j0;

.field public t:Lg1/w1;

.field public u:Lay0/k;

.field public v:Z

.field public w:Li1/l;

.field public x:Lxy0/j;

.field public y:Li1/b;

.field public z:Z


# direct methods
.method public constructor <init>(Lay0/k;ZLi1/l;Lg1/w1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lv3/n;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lg1/d1;->t:Lg1/w1;

    .line 5
    .line 6
    iput-object p1, p0, Lg1/d1;->u:Lay0/k;

    .line 7
    .line 8
    iput-boolean p2, p0, Lg1/d1;->v:Z

    .line 9
    .line 10
    iput-object p3, p0, Lg1/d1;->w:Li1/l;

    .line 11
    .line 12
    const-wide/16 p1, 0x0

    .line 13
    .line 14
    iput-wide p1, p0, Lg1/d1;->A:J

    .line 15
    .line 16
    return-void
.end method

.method public static final a1(Lg1/d1;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lg1/z0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lg1/z0;

    .line 7
    .line 8
    iget v1, v0, Lg1/z0;->f:I

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
    iput v1, v0, Lg1/z0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/z0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lg1/z0;-><init>(Lg1/d1;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lg1/z0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/z0;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iget-object p1, p0, Lg1/d1;->y:Li1/b;

    .line 52
    .line 53
    if-eqz p1, :cond_4

    .line 54
    .line 55
    iget-object v2, p0, Lg1/d1;->w:Li1/l;

    .line 56
    .line 57
    if-eqz v2, :cond_3

    .line 58
    .line 59
    new-instance v4, Li1/a;

    .line 60
    .line 61
    invoke-direct {v4, p1}, Li1/a;-><init>(Li1/b;)V

    .line 62
    .line 63
    .line 64
    iput v3, v0, Lg1/z0;->f:I

    .line 65
    .line 66
    invoke-virtual {v2, v4, v0}, Li1/l;->a(Li1/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-ne p1, v1, :cond_3

    .line 71
    .line 72
    return-object v1

    .line 73
    :cond_3
    :goto_1
    const/4 p1, 0x0

    .line 74
    iput-object p1, p0, Lg1/d1;->y:Li1/b;

    .line 75
    .line 76
    :cond_4
    const-wide/16 v0, 0x0

    .line 77
    .line 78
    invoke-virtual {p0, v0, v1}, Lg1/d1;->g1(J)V

    .line 79
    .line 80
    .line 81
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    return-object p0
.end method

.method public static final b1(Lg1/d1;Lg1/i0;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lg1/a1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lg1/a1;

    .line 7
    .line 8
    iget v1, v0, Lg1/a1;->h:I

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
    iput v1, v0, Lg1/a1;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/a1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lg1/a1;-><init>(Lg1/d1;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lg1/a1;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/a1;->h:I

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
    iget-object p1, v0, Lg1/a1;->e:Li1/b;

    .line 40
    .line 41
    iget-object v0, v0, Lg1/a1;->d:Lg1/i0;

    .line 42
    .line 43
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    iget-object p1, v0, Lg1/a1;->d:Lg1/i0;

    .line 56
    .line 57
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iget-object p2, p0, Lg1/d1;->y:Li1/b;

    .line 65
    .line 66
    if-eqz p2, :cond_4

    .line 67
    .line 68
    iget-object v2, p0, Lg1/d1;->w:Li1/l;

    .line 69
    .line 70
    if-eqz v2, :cond_4

    .line 71
    .line 72
    new-instance v5, Li1/a;

    .line 73
    .line 74
    invoke-direct {v5, p2}, Li1/a;-><init>(Li1/b;)V

    .line 75
    .line 76
    .line 77
    iput-object p1, v0, Lg1/a1;->d:Lg1/i0;

    .line 78
    .line 79
    iput v4, v0, Lg1/a1;->h:I

    .line 80
    .line 81
    invoke-virtual {v2, v5, v0}, Li1/l;->a(Li1/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    if-ne p2, v1, :cond_4

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    :goto_1
    new-instance p2, Li1/b;

    .line 89
    .line 90
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 91
    .line 92
    .line 93
    iget-object v2, p0, Lg1/d1;->w:Li1/l;

    .line 94
    .line 95
    if-eqz v2, :cond_6

    .line 96
    .line 97
    iput-object p1, v0, Lg1/a1;->d:Lg1/i0;

    .line 98
    .line 99
    iput-object p2, v0, Lg1/a1;->e:Li1/b;

    .line 100
    .line 101
    iput v3, v0, Lg1/a1;->h:I

    .line 102
    .line 103
    invoke-virtual {v2, p2, v0}, Li1/l;->a(Li1/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    if-ne v0, v1, :cond_5

    .line 108
    .line 109
    :goto_2
    return-object v1

    .line 110
    :cond_5
    move-object v0, p1

    .line 111
    move-object p1, p2

    .line 112
    :goto_3
    move-object p2, p1

    .line 113
    move-object p1, v0

    .line 114
    :cond_6
    iput-object p2, p0, Lg1/d1;->y:Li1/b;

    .line 115
    .line 116
    iget-wide p1, p1, Lg1/i0;->a:J

    .line 117
    .line 118
    invoke-virtual {p0, p1, p2}, Lg1/d1;->f1(J)V

    .line 119
    .line 120
    .line 121
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 122
    .line 123
    return-object p0
.end method

.method public static final c1(Lg1/d1;Lg1/j0;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lg1/b1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lg1/b1;

    .line 7
    .line 8
    iget v1, v0, Lg1/b1;->g:I

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
    iput v1, v0, Lg1/b1;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/b1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lg1/b1;-><init>(Lg1/d1;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lg1/b1;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/b1;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lg1/b1;->d:Lg1/j0;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p2, p0, Lg1/d1;->y:Li1/b;

    .line 54
    .line 55
    if-eqz p2, :cond_4

    .line 56
    .line 57
    iget-object v2, p0, Lg1/d1;->w:Li1/l;

    .line 58
    .line 59
    if-eqz v2, :cond_3

    .line 60
    .line 61
    new-instance v4, Li1/c;

    .line 62
    .line 63
    invoke-direct {v4, p2}, Li1/c;-><init>(Li1/b;)V

    .line 64
    .line 65
    .line 66
    iput-object p1, v0, Lg1/b1;->d:Lg1/j0;

    .line 67
    .line 68
    iput v3, v0, Lg1/b1;->g:I

    .line 69
    .line 70
    invoke-virtual {v2, v4, v0}, Li1/l;->a(Li1/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    if-ne p2, v1, :cond_3

    .line 75
    .line 76
    return-object v1

    .line 77
    :cond_3
    :goto_1
    const/4 p2, 0x0

    .line 78
    iput-object p2, p0, Lg1/d1;->y:Li1/b;

    .line 79
    .line 80
    :cond_4
    iget-wide p1, p1, Lg1/j0;->a:J

    .line 81
    .line 82
    invoke-virtual {p0, p1, p2}, Lg1/d1;->g1(J)V

    .line 83
    .line 84
    .line 85
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    return-object p0
.end method


# virtual methods
.method public final Q0()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lg1/d1;->z:Z

    .line 3
    .line 4
    invoke-virtual {p0}, Lg1/d1;->d1()V

    .line 5
    .line 6
    .line 7
    const-wide/16 v0, 0x0

    .line 8
    .line 9
    iput-wide v0, p0, Lg1/d1;->A:J

    .line 10
    .line 11
    return-void
.end method

.method public final d1()V
    .locals 3

    .line 1
    iget-object v0, p0, Lg1/d1;->y:Li1/b;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v1, p0, Lg1/d1;->w:Li1/l;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    new-instance v2, Li1/a;

    .line 10
    .line 11
    invoke-direct {v2, v0}, Li1/a;-><init>(Li1/b;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1, v2}, Li1/l;->b(Li1/k;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    const/4 v0, 0x0

    .line 18
    iput-object v0, p0, Lg1/d1;->y:Li1/b;

    .line 19
    .line 20
    :cond_1
    return-void
.end method

.method public abstract e1(Lg1/c1;Lg1/c1;)Ljava/lang/Object;
.end method

.method public abstract f1(J)V
.end method

.method public abstract g1(J)V
.end method

.method public abstract h1()Z
.end method

.method public final i1(Lay0/k;ZLi1/l;Lg1/w1;Z)V
    .locals 1

    .line 1
    iput-object p1, p0, Lg1/d1;->u:Lay0/k;

    .line 2
    .line 3
    iget-boolean p1, p0, Lg1/d1;->v:Z

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    if-eq p1, p2, :cond_2

    .line 7
    .line 8
    iput-boolean p2, p0, Lg1/d1;->v:Z

    .line 9
    .line 10
    if-nez p2, :cond_1

    .line 11
    .line 12
    invoke-virtual {p0}, Lg1/d1;->d1()V

    .line 13
    .line 14
    .line 15
    iget-object p1, p0, Lg1/d1;->B:Lp3/j0;

    .line 16
    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Lv3/n;->Y0(Lv3/m;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    const/4 p1, 0x0

    .line 23
    iput-object p1, p0, Lg1/d1;->B:Lp3/j0;

    .line 24
    .line 25
    :cond_1
    move p5, v0

    .line 26
    :cond_2
    iget-object p1, p0, Lg1/d1;->w:Li1/l;

    .line 27
    .line 28
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-nez p1, :cond_3

    .line 33
    .line 34
    invoke-virtual {p0}, Lg1/d1;->d1()V

    .line 35
    .line 36
    .line 37
    iput-object p3, p0, Lg1/d1;->w:Li1/l;

    .line 38
    .line 39
    :cond_3
    iget-object p1, p0, Lg1/d1;->t:Lg1/w1;

    .line 40
    .line 41
    if-eq p1, p4, :cond_4

    .line 42
    .line 43
    iput-object p4, p0, Lg1/d1;->t:Lg1/w1;

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_4
    move v0, p5

    .line 47
    :goto_0
    if-eqz v0, :cond_5

    .line 48
    .line 49
    iget-object p0, p0, Lg1/d1;->B:Lp3/j0;

    .line 50
    .line 51
    if-eqz p0, :cond_5

    .line 52
    .line 53
    invoke-virtual {p0}, Lp3/j0;->Z0()V

    .line 54
    .line 55
    .line 56
    :cond_5
    return-void
.end method

.method public final l0()V
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/d1;->B:Lp3/j0;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lp3/j0;->l0()V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public v0(Lp3/k;Lp3/l;J)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lg1/d1;->v:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lg1/d1;->B:Lp3/j0;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    new-instance v0, Lb2/b;

    .line 10
    .line 11
    const/4 v1, 0x5

    .line 12
    invoke-direct {v0, p0, v1}, Lb2/b;-><init>(Ljava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    invoke-static {v0}, Lp3/f0;->a(Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lp3/j0;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {p0, v0}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Lg1/d1;->B:Lp3/j0;

    .line 23
    .line 24
    :cond_0
    iget-object p0, p0, Lg1/d1;->B:Lp3/j0;

    .line 25
    .line 26
    if-eqz p0, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0, p1, p2, p3, p4}, Lp3/j0;->v0(Lp3/k;Lp3/l;J)V

    .line 29
    .line 30
    .line 31
    :cond_1
    return-void
.end method
