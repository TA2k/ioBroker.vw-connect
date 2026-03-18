.class public abstract Lw3/y1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lw3/v1;->g:Lw3/v1;

    .line 2
    .line 3
    new-instance v1, Ll2/u2;

    .line 4
    .line 5
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 6
    .line 7
    .line 8
    sput-object v1, Lw3/y1;->a:Ll2/u2;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lc2/l;La7/k;Lrx0/c;)V
    .locals 4

    .line 1
    instance-of v0, p2, Lw3/w1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lw3/w1;

    .line 7
    .line 8
    iget v1, v0, Lw3/w1;->e:I

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
    iput v1, v0, Lw3/w1;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lw3/w1;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lw3/w1;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lw3/w1;->e:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-eq v1, v2, :cond_1

    .line 35
    .line 36
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    invoke-static {p2}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    move-object p2, p0

    .line 53
    check-cast p2, Lx2/r;

    .line 54
    .line 55
    iget-object p2, p2, Lx2/r;->d:Lx2/r;

    .line 56
    .line 57
    iget-boolean p2, p2, Lx2/r;->q:Z

    .line 58
    .line 59
    if-eqz p2, :cond_4

    .line 60
    .line 61
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    iget-object p0, p0, Lv3/h0;->D:Ll2/c0;

    .line 70
    .line 71
    check-cast p0, Lt2/g;

    .line 72
    .line 73
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    sget-object v1, Lw3/y1;->a:Ll2/u2;

    .line 77
    .line 78
    invoke-static {p0, v1}, Ll2/b;->q(Ll2/p1;Ll2/s1;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    if-nez p0, :cond_3

    .line 83
    .line 84
    iput v2, v0, Lw3/w1;->e:I

    .line 85
    .line 86
    invoke-static {p2, p1, v0}, Lw3/y1;->b(Lv3/o1;Lay0/n;Lrx0/c;)V

    .line 87
    .line 88
    .line 89
    return-void

    .line 90
    :cond_3
    new-instance p0, Ljava/lang/ClassCastException;

    .line 91
    .line 92
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 93
    .line 94
    .line 95
    throw p0

    .line 96
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 97
    .line 98
    const-string p1, "establishTextInputSession called from an unattached node"

    .line 99
    .line 100
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    throw p0
.end method

.method public static final b(Lv3/o1;Lay0/n;Lrx0/c;)V
    .locals 4

    .line 1
    instance-of v0, p2, Lw3/x1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lw3/x1;

    .line 7
    .line 8
    iget v1, v0, Lw3/x1;->e:I

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
    iput v1, v0, Lw3/x1;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lw3/x1;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lw3/x1;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lw3/x1;->e:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_3

    .line 33
    .line 34
    if-eq v1, v2, :cond_2

    .line 35
    .line 36
    const/4 p0, 0x2

    .line 37
    if-eq v1, p0, :cond_1

    .line 38
    .line 39
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 40
    .line 41
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 42
    .line 43
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_1
    invoke-static {p2}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p2}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    throw p0

    .line 57
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput v2, v0, Lw3/x1;->e:I

    .line 61
    .line 62
    check-cast p0, Lw3/t;

    .line 63
    .line 64
    invoke-virtual {p0, p1, v0}, Lw3/t;->G(Lay0/n;Lrx0/c;)V

    .line 65
    .line 66
    .line 67
    return-void
.end method
