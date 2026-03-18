.class public final Lo3/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Lo3/g;

.field public b:Lo3/g;

.field public c:Lkotlin/jvm/internal/n;

.field public d:Lvy0/b0;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, La7/j;

    .line 5
    .line 6
    const/16 v1, 0x10

    .line 7
    .line 8
    invoke-direct {v0, p0, v1}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lo3/d;->c:Lkotlin/jvm/internal/n;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(JJLrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p5, Lo3/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p5

    .line 6
    check-cast v0, Lo3/b;

    .line 7
    .line 8
    iget v1, v0, Lo3/b;->f:I

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
    iput v1, v0, Lo3/b;->f:I

    .line 18
    .line 19
    :goto_0
    move-object p5, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v0, Lo3/b;

    .line 22
    .line 23
    invoke-direct {v0, p0, p5}, Lo3/b;-><init>(Lo3/d;Lrx0/c;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object v0, p5, Lo3/b;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, p5, Lo3/b;->f:I

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v4, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_5

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_3

    .line 57
    :cond_3
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object v0, p0, Lo3/d;->a:Lo3/g;

    .line 61
    .line 62
    const/4 v2, 0x0

    .line 63
    if-eqz v0, :cond_4

    .line 64
    .line 65
    iget-boolean v5, v0, Lx2/r;->q:Z

    .line 66
    .line 67
    if-eqz v5, :cond_4

    .line 68
    .line 69
    invoke-static {v0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    check-cast v0, Lo3/g;

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_4
    move-object v0, v2

    .line 77
    :goto_2
    const-wide/16 v5, 0x0

    .line 78
    .line 79
    if-nez v0, :cond_6

    .line 80
    .line 81
    iget-object p0, p0, Lo3/d;->b:Lo3/g;

    .line 82
    .line 83
    if-eqz p0, :cond_9

    .line 84
    .line 85
    iput v4, p5, Lo3/b;->f:I

    .line 86
    .line 87
    invoke-virtual/range {p0 .. p5}, Lo3/g;->i(JJLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    if-ne v0, v1, :cond_5

    .line 92
    .line 93
    goto :goto_4

    .line 94
    :cond_5
    :goto_3
    check-cast v0, Lt4/q;

    .line 95
    .line 96
    iget-wide v5, v0, Lt4/q;->a:J

    .line 97
    .line 98
    goto :goto_6

    .line 99
    :cond_6
    iget-object p0, p0, Lo3/d;->a:Lo3/g;

    .line 100
    .line 101
    if-eqz p0, :cond_7

    .line 102
    .line 103
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 104
    .line 105
    if-eqz v0, :cond_7

    .line 106
    .line 107
    invoke-static {p0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    move-object v2, p0

    .line 112
    check-cast v2, Lo3/g;

    .line 113
    .line 114
    :cond_7
    move-object p0, v2

    .line 115
    if-eqz p0, :cond_9

    .line 116
    .line 117
    iput v3, p5, Lo3/b;->f:I

    .line 118
    .line 119
    invoke-virtual/range {p0 .. p5}, Lo3/g;->i(JJLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    if-ne v0, v1, :cond_8

    .line 124
    .line 125
    :goto_4
    return-object v1

    .line 126
    :cond_8
    :goto_5
    check-cast v0, Lt4/q;

    .line 127
    .line 128
    iget-wide v5, v0, Lt4/q;->a:J

    .line 129
    .line 130
    :cond_9
    :goto_6
    new-instance p0, Lt4/q;

    .line 131
    .line 132
    invoke-direct {p0, v5, v6}, Lt4/q;-><init>(J)V

    .line 133
    .line 134
    .line 135
    return-object p0
.end method

.method public final b(JLrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p3, Lo3/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lo3/c;

    .line 7
    .line 8
    iget v1, v0, Lo3/c;->f:I

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
    iput v1, v0, Lo3/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lo3/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lo3/c;-><init>(Lo3/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lo3/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lo3/c;->f:I

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
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lo3/d;->a:Lo3/g;

    .line 52
    .line 53
    const/4 p3, 0x0

    .line 54
    if-eqz p0, :cond_3

    .line 55
    .line 56
    iget-boolean v2, p0, Lx2/r;->q:Z

    .line 57
    .line 58
    if-eqz v2, :cond_3

    .line 59
    .line 60
    invoke-static {p0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    move-object p3, p0

    .line 65
    check-cast p3, Lo3/g;

    .line 66
    .line 67
    :cond_3
    if-eqz p3, :cond_5

    .line 68
    .line 69
    iput v3, v0, Lo3/c;->f:I

    .line 70
    .line 71
    invoke-virtual {p3, p1, p2, v0}, Lo3/g;->y0(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p3

    .line 75
    if-ne p3, v1, :cond_4

    .line 76
    .line 77
    return-object v1

    .line 78
    :cond_4
    :goto_1
    check-cast p3, Lt4/q;

    .line 79
    .line 80
    iget-wide p0, p3, Lt4/q;->a:J

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_5
    const-wide/16 p0, 0x0

    .line 84
    .line 85
    :goto_2
    new-instance p2, Lt4/q;

    .line 86
    .line 87
    invoke-direct {p2, p0, p1}, Lt4/q;-><init>(J)V

    .line 88
    .line 89
    .line 90
    return-object p2
.end method

.method public final c()Lvy0/b0;
    .locals 1

    .line 1
    iget-object p0, p0, Lo3/d;->c:Lkotlin/jvm/internal/n;

    .line 2
    .line 3
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lvy0/b0;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 13
    .line 14
    const-string v0, "in order to access nested coroutine scope you need to attach dispatcher to the `Modifier.nestedScroll` first."

    .line 15
    .line 16
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method
