.class public final Lmc0/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lzd0/a;

.field public final i:Lkc0/m0;

.field public final j:Lkc0/q0;

.field public final k:Lwr0/e;

.field public final l:Lij0/a;


# direct methods
.method public constructor <init>(Lzd0/a;Lkc0/m0;Lkc0/q0;Lwr0/e;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lmc0/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x7

    .line 5
    invoke-direct {v0, v1, v2}, Lmc0/b;-><init>(Lmc0/a;I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lmc0/d;->h:Lzd0/a;

    .line 12
    .line 13
    iput-object p2, p0, Lmc0/d;->i:Lkc0/m0;

    .line 14
    .line 15
    iput-object p3, p0, Lmc0/d;->j:Lkc0/q0;

    .line 16
    .line 17
    iput-object p4, p0, Lmc0/d;->k:Lwr0/e;

    .line 18
    .line 19
    iput-object p5, p0, Lmc0/d;->l:Lij0/a;

    .line 20
    .line 21
    return-void
.end method

.method public static final h(Lmc0/d;Lne0/c;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lmc0/d;->l:Lij0/a;

    .line 2
    .line 3
    instance-of v1, p2, Lmc0/c;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p2

    .line 8
    check-cast v1, Lmc0/c;

    .line 9
    .line 10
    iget v2, v1, Lmc0/c;->g:I

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
    iput v2, v1, Lmc0/c;->g:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lmc0/c;

    .line 23
    .line 24
    invoke-direct {v1, p0, p2}, Lmc0/c;-><init>(Lmc0/d;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p2, v1, Lmc0/c;->e:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lmc0/c;->g:I

    .line 32
    .line 33
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    if-eqz v3, :cond_2

    .line 37
    .line 38
    if-ne v3, v5, :cond_1

    .line 39
    .line 40
    iget-object p1, v1, Lmc0/c;->d:Lne0/c;

    .line 41
    .line 42
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-object p2, p0, Lmc0/d;->k:Lwr0/e;

    .line 58
    .line 59
    iput-object p1, v1, Lmc0/c;->d:Lne0/c;

    .line 60
    .line 61
    iput v5, v1, Lmc0/c;->g:I

    .line 62
    .line 63
    invoke-virtual {p2, v4, v1}, Lwr0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    if-ne p2, v2, :cond_3

    .line 68
    .line 69
    return-object v2

    .line 70
    :cond_3
    :goto_1
    check-cast p2, Lyr0/e;

    .line 71
    .line 72
    const/4 v1, 0x0

    .line 73
    if-eqz p2, :cond_4

    .line 74
    .line 75
    iget-object p2, p2, Lyr0/e;->b:Ljava/lang/String;

    .line 76
    .line 77
    if-nez p2, :cond_5

    .line 78
    .line 79
    :cond_4
    new-array p2, v1, [Ljava/lang/Object;

    .line 80
    .line 81
    move-object v2, v0

    .line 82
    check-cast v2, Ljj0/f;

    .line 83
    .line 84
    const v3, 0x7f120503

    .line 85
    .line 86
    .line 87
    invoke-virtual {v2, v3, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p2

    .line 91
    :cond_5
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    check-cast v2, Lmc0/b;

    .line 96
    .line 97
    new-instance v3, Lmc0/a;

    .line 98
    .line 99
    new-array v1, v1, [Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v0, Ljj0/f;

    .line 102
    .line 103
    const v6, 0x7f120504

    .line 104
    .line 105
    .line 106
    invoke-virtual {v0, v6, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    const v6, 0x7f120502

    .line 111
    .line 112
    .line 113
    filled-new-array {p2}, [Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    invoke-virtual {v0, v6, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object p2

    .line 121
    invoke-direct {v3, v1, p2}, Lmc0/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    const/4 p2, 0x0

    .line 125
    invoke-static {v2, p2, p1, v3, v5}, Lmc0/b;->a(Lmc0/b;[Llc0/l;Lne0/c;Lmc0/a;I)Lmc0/b;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 130
    .line 131
    .line 132
    return-object v4
.end method


# virtual methods
.method public final j()V
    .locals 7

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lmc0/b;

    .line 6
    .line 7
    iget-object v0, v0, Lmc0/b;->b:Lne0/c;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    new-instance v1, Lne0/c;

    .line 12
    .line 13
    new-instance v2, Ljava/lang/IllegalStateException;

    .line 14
    .line 15
    const-string v0, "Sign in result is null"

    .line 16
    .line 17
    invoke-direct {v2, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const/4 v5, 0x0

    .line 21
    const/16 v6, 0x1e

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 26
    .line 27
    .line 28
    move-object v0, v1

    .line 29
    :cond_0
    iget-object v1, p0, Lmc0/d;->h:Lzd0/a;

    .line 30
    .line 31
    invoke-virtual {v1, v0}, Lzd0/a;->a(Lne0/t;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    check-cast v0, Lmc0/b;

    .line 39
    .line 40
    const/4 v1, 0x1

    .line 41
    const/4 v2, 0x0

    .line 42
    invoke-static {v0, v2, v2, v2, v1}, Lmc0/b;->a(Lmc0/b;[Llc0/l;Lne0/c;Lmc0/a;I)Lmc0/b;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 47
    .line 48
    .line 49
    return-void
.end method
