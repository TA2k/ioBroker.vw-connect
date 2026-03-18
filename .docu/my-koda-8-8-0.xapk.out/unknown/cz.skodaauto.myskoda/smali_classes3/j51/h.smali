.class public final Lj51/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lxo/g;


# direct methods
.method public constructor <init>(Lxo/g;Ly41/g;)V
    .locals 9

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj51/h;->a:Lxo/g;

    .line 5
    .line 6
    new-instance v0, Lio/ktor/utils/io/g0;

    .line 7
    .line 8
    const/4 v6, 0x0

    .line 9
    const/4 v7, 0x3

    .line 10
    const/4 v1, 0x1

    .line 11
    const-class v3, Lj51/h;

    .line 12
    .line 13
    const-string v4, "getAllDigitalKeyIdsFromWallet"

    .line 14
    .line 15
    const-string v5, "getAllDigitalKeyIdsFromWallet$carkeykit_world_release(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 16
    .line 17
    move-object v2, p0

    .line 18
    invoke-direct/range {v0 .. v7}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 19
    .line 20
    .line 21
    new-instance v1, Laa/i0;

    .line 22
    .line 23
    const/16 v3, 0xd

    .line 24
    .line 25
    const/4 v8, 0x0

    .line 26
    invoke-direct {v1, v3, p1, v0, v8}, Laa/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    invoke-static {v1}, Lyy0/u;->h(Lay0/n;)Lyy0/c;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    new-instance v1, Lac/l;

    .line 34
    .line 35
    const/16 v3, 0x11

    .line 36
    .line 37
    invoke-direct {v1, v3, v0, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    new-instance v0, Lio/ktor/utils/io/g0;

    .line 41
    .line 42
    const/4 v7, 0x4

    .line 43
    const/4 v1, 0x1

    .line 44
    const-class v3, Lj51/h;

    .line 45
    .line 46
    const-string v4, "getAllDigitalKeyIdsFromWallet"

    .line 47
    .line 48
    const-string v5, "getAllDigitalKeyIdsFromWallet$carkeykit_world_release(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 49
    .line 50
    invoke-direct/range {v0 .. v7}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 51
    .line 52
    .line 53
    new-instance v1, Laa/i0;

    .line 54
    .line 55
    const/16 v2, 0xe

    .line 56
    .line 57
    invoke-direct {v1, v2, p1, v0, v8}, Laa/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 58
    .line 59
    .line 60
    invoke-static {v1}, Lyy0/u;->h(Lay0/n;)Lyy0/c;

    .line 61
    .line 62
    .line 63
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/io/Serializable;
    .locals 4

    .line 1
    instance-of v0, p1, Lj51/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lj51/d;

    .line 7
    .line 8
    iget v1, v0, Lj51/d;->f:I

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
    iput v1, v0, Lj51/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj51/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lj51/d;-><init>(Lj51/h;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lj51/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj51/d;->f:I

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
    check-cast p1, Llx0/o;

    .line 40
    .line 41
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iput v3, v0, Lj51/d;->f:I

    .line 56
    .line 57
    invoke-virtual {p0, v0}, Lj51/h;->b(Lrx0/c;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    if-ne p0, v1, :cond_3

    .line 62
    .line 63
    return-object v1

    .line 64
    :cond_3
    :goto_1
    instance-of p1, p0, Llx0/n;

    .line 65
    .line 66
    if-eqz p1, :cond_4

    .line 67
    .line 68
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 69
    .line 70
    :cond_4
    check-cast p0, Ljava/lang/Iterable;

    .line 71
    .line 72
    new-instance p1, Ljava/util/ArrayList;

    .line 73
    .line 74
    const/16 v0, 0xa

    .line 75
    .line 76
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 81
    .line 82
    .line 83
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-eqz v0, :cond_5

    .line 92
    .line 93
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    check-cast v0, Lcom/google/android/gms/dck/DigitalKeyData;

    .line 98
    .line 99
    iget-object v0, v0, Lcom/google/android/gms/dck/DigitalKeyData;->e:Ljava/lang/String;

    .line 100
    .line 101
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    goto :goto_2

    .line 105
    :cond_5
    return-object p1
.end method

.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lj51/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lj51/e;

    .line 7
    .line 8
    iget v1, v0, Lj51/e;->f:I

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
    iput v1, v0, Lj51/e;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj51/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lj51/e;-><init>(Lj51/h;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lj51/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj51/e;->f:I

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
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :catch_0
    move-exception p1

    .line 41
    goto :goto_2

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :try_start_1
    iget-object p1, p0, Lj51/h;->a:Lxo/g;

    .line 54
    .line 55
    invoke-static {}, Lhr/b0;->e()Lh6/i;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    sget-object v4, Lwo/g;->b:Ljo/d;

    .line 60
    .line 61
    filled-new-array {v4}, [Ljo/d;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    iput-object v4, v2, Lh6/i;->e:Ljava/lang/Object;

    .line 66
    .line 67
    sget-object v4, Lmb/e;->o:Lmb/e;

    .line 68
    .line 69
    iput-object v4, v2, Lh6/i;->d:Ljava/lang/Object;

    .line 70
    .line 71
    const v4, 0x8860

    .line 72
    .line 73
    .line 74
    iput v4, v2, Lh6/i;->b:I

    .line 75
    .line 76
    invoke-virtual {v2}, Lh6/i;->a()Lbp/s;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    const/4 v4, 0x0

    .line 81
    invoke-virtual {p1, v4, v2}, Lko/i;->e(ILhr/b0;)Laq/t;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    const-string v2, "getAllDigitalKeys(...)"

    .line 86
    .line 87
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    iput v3, v0, Lj51/e;->f:I

    .line 91
    .line 92
    invoke-static {p1, v0}, Lkp/j8;->a(Laq/t;Lrx0/c;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    if-ne p1, v1, :cond_3

    .line 97
    .line 98
    return-object v1

    .line 99
    :cond_3
    :goto_1
    check-cast p1, Ljava/util/List;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 100
    .line 101
    return-object p1

    .line 102
    :goto_2
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 103
    .line 104
    invoke-static {p0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    iget-object p0, v0, Lx51/b;->d:La61/a;

    .line 108
    .line 109
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 110
    .line 111
    .line 112
    new-instance p0, Lz41/a;

    .line 113
    .line 114
    const-string v0, "Getting list of installed digital keys from wallet failed due to an exception."

    .line 115
    .line 116
    invoke-direct {p0, v0, p1}, Lz41/e;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 117
    .line 118
    .line 119
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    return-object p0
.end method

.method public final c(Lrx0/c;)Ljava/io/Serializable;
    .locals 5

    .line 1
    instance-of v0, p1, Lj51/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lj51/f;

    .line 7
    .line 8
    iget v1, v0, Lj51/f;->f:I

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
    iput v1, v0, Lj51/f;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj51/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lj51/f;-><init>(Lj51/h;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lj51/f;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj51/f;->f:I

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
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :catch_0
    move-exception p1

    .line 41
    goto :goto_2

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :try_start_1
    iget-object p1, p0, Lj51/h;->a:Lxo/g;

    .line 54
    .line 55
    invoke-static {}, Lhr/b0;->e()Lh6/i;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    sget-object v4, Lwo/g;->b:Ljo/d;

    .line 60
    .line 61
    filled-new-array {v4}, [Ljo/d;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    iput-object v4, v2, Lh6/i;->e:Ljava/lang/Object;

    .line 66
    .line 67
    sget-object v4, Lnm0/b;->n:Lnm0/b;

    .line 68
    .line 69
    iput-object v4, v2, Lh6/i;->d:Ljava/lang/Object;

    .line 70
    .line 71
    const v4, 0x8855

    .line 72
    .line 73
    .line 74
    iput v4, v2, Lh6/i;->b:I

    .line 75
    .line 76
    invoke-virtual {v2}, Lh6/i;->a()Lbp/s;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    const/4 v4, 0x0

    .line 81
    invoke-virtual {p1, v4, v2}, Lko/i;->e(ILhr/b0;)Laq/t;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    const-string v2, "isSupportedByDevice(...)"

    .line 86
    .line 87
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    iput v3, v0, Lj51/f;->f:I

    .line 91
    .line 92
    invoke-static {p1, v0}, Lkp/j8;->a(Laq/t;Lrx0/c;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    if-ne p1, v1, :cond_3

    .line 97
    .line 98
    return-object v1

    .line 99
    :cond_3
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 100
    .line 101
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 102
    .line 103
    invoke-static {p0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    new-instance v2, Lh50/q0;

    .line 108
    .line 109
    const/16 v3, 0xf

    .line 110
    .line 111
    invoke-direct {v2, p1, v3}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 112
    .line 113
    .line 114
    const/4 v3, 0x6

    .line 115
    invoke-static {v0, v1, v2, v3}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 116
    .line 117
    .line 118
    return-object p1

    .line 119
    :goto_2
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 120
    .line 121
    invoke-static {p0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    iget-object p0, v0, Lx51/b;->d:La61/a;

    .line 125
    .line 126
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 127
    .line 128
    .line 129
    new-instance p0, Lz41/a;

    .line 130
    .line 131
    const-string v0, "An exception occurred while checking if device supports Digital Key Creation feature."

    .line 132
    .line 133
    invoke-direct {p0, v0, p1}, Lz41/e;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 134
    .line 135
    .line 136
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    return-object p0
.end method
