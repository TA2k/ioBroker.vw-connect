.class public final Lyk0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lal0/e0;
.implements Lme0/a;


# instance fields
.field public final a:Lyy0/c2;

.field public final b:Lyy0/l1;

.field public final c:Lyy0/c2;

.field public final d:Lyy0/l1;

.field public final e:Lez0/c;

.field public final f:Ljava/util/LinkedHashMap;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/c2;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iput-object v1, p0, Lyk0/j;->a:Lyy0/c2;

    .line 10
    .line 11
    new-instance v2, Lyy0/l1;

    .line 12
    .line 13
    invoke-direct {v2, v1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 14
    .line 15
    .line 16
    iput-object v2, p0, Lyk0/j;->b:Lyy0/l1;

    .line 17
    .line 18
    new-instance v1, Lne0/e;

    .line 19
    .line 20
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    invoke-direct {v1, v2}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    iput-object v1, p0, Lyk0/j;->c:Lyy0/c2;

    .line 30
    .line 31
    new-instance v2, Lyy0/l1;

    .line 32
    .line 33
    invoke-direct {v2, v1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 34
    .line 35
    .line 36
    iput-object v2, p0, Lyk0/j;->d:Lyy0/l1;

    .line 37
    .line 38
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    iput-object v1, p0, Lyk0/j;->e:Lez0/c;

    .line 43
    .line 44
    new-instance v1, Ljava/util/LinkedHashMap;

    .line 45
    .line 46
    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 47
    .line 48
    .line 49
    iput-object v1, p0, Lyk0/j;->f:Ljava/util/LinkedHashMap;

    .line 50
    .line 51
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    iput-object v0, p0, Lyk0/j;->g:Lyy0/c2;

    .line 56
    .line 57
    iput-object v0, p0, Lyk0/j;->h:Lyy0/c2;

    .line 58
    .line 59
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p1, p0, Lyk0/j;->a:Lyy0/c2;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p1, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lyk0/j;->g:Lyy0/c2;

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method public final b(Ljava/util/List;Lxj0/f;Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p3, Lyk0/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lyk0/g;

    .line 7
    .line 8
    iget v1, v0, Lyk0/g;->j:I

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
    iput v1, v0, Lyk0/g;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyk0/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lyk0/g;-><init>(Lyk0/j;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lyk0/g;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyk0/g;->j:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v10, 0x0

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v4, :cond_2

    .line 37
    .line 38
    if-ne v2, v3, :cond_1

    .line 39
    .line 40
    iget-object p0, v0, Lyk0/g;->f:Lez0/a;

    .line 41
    .line 42
    iget-object p1, v0, Lyk0/g;->d:Ljava/util/List;

    .line 43
    .line 44
    check-cast p1, Ljava/util/List;

    .line 45
    .line 46
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 47
    .line 48
    .line 49
    goto :goto_3

    .line 50
    :catchall_0
    move-exception v0

    .line 51
    move-object p1, v0

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
    iget p1, v0, Lyk0/g;->g:I

    .line 62
    .line 63
    iget-object p2, v0, Lyk0/g;->f:Lez0/a;

    .line 64
    .line 65
    iget-object v2, v0, Lyk0/g;->e:Lxj0/f;

    .line 66
    .line 67
    iget-object v4, v0, Lyk0/g;->d:Ljava/util/List;

    .line 68
    .line 69
    check-cast v4, Ljava/util/List;

    .line 70
    .line 71
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    move-object v9, v2

    .line 75
    move-object v8, v4

    .line 76
    goto :goto_1

    .line 77
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    move-object p3, p1

    .line 81
    check-cast p3, Ljava/util/List;

    .line 82
    .line 83
    iput-object p3, v0, Lyk0/g;->d:Ljava/util/List;

    .line 84
    .line 85
    iput-object p2, v0, Lyk0/g;->e:Lxj0/f;

    .line 86
    .line 87
    iget-object p3, p0, Lyk0/j;->e:Lez0/c;

    .line 88
    .line 89
    iput-object p3, v0, Lyk0/g;->f:Lez0/a;

    .line 90
    .line 91
    const/4 v2, 0x0

    .line 92
    iput v2, v0, Lyk0/g;->g:I

    .line 93
    .line 94
    iput v4, v0, Lyk0/g;->j:I

    .line 95
    .line 96
    invoke-virtual {p3, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    if-ne v4, v1, :cond_4

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_4
    move-object v8, p1

    .line 104
    move-object v9, p2

    .line 105
    move-object p2, p3

    .line 106
    move p1, v2

    .line 107
    :goto_1
    :try_start_1
    sget-object p3, Lge0/b;->a:Lcz0/e;

    .line 108
    .line 109
    new-instance v5, Lqh/a;

    .line 110
    .line 111
    const/16 v6, 0x12

    .line 112
    .line 113
    move-object v7, p0

    .line 114
    invoke-direct/range {v5 .. v10}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 115
    .line 116
    .line 117
    iput-object v10, v0, Lyk0/g;->d:Ljava/util/List;

    .line 118
    .line 119
    iput-object v10, v0, Lyk0/g;->e:Lxj0/f;

    .line 120
    .line 121
    iput-object p2, v0, Lyk0/g;->f:Lez0/a;

    .line 122
    .line 123
    iput p1, v0, Lyk0/g;->g:I

    .line 124
    .line 125
    iput v3, v0, Lyk0/g;->j:I

    .line 126
    .line 127
    invoke-static {p3, v5, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object p3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 131
    if-ne p3, v1, :cond_5

    .line 132
    .line 133
    :goto_2
    return-object v1

    .line 134
    :cond_5
    move-object p0, p2

    .line 135
    :goto_3
    :try_start_2
    check-cast p3, Lkj0/f;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 136
    .line 137
    invoke-interface {p0, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 141
    .line 142
    return-object p0

    .line 143
    :catchall_1
    move-exception v0

    .line 144
    move-object p1, v0

    .line 145
    move-object p0, p2

    .line 146
    :goto_4
    invoke-interface {p0, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    throw p1
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lyk0/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lyk0/h;

    .line 7
    .line 8
    iget v1, v0, Lyk0/h;->g:I

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
    iput v1, v0, Lyk0/h;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyk0/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lyk0/h;-><init>(Lyk0/j;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lyk0/h;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyk0/h;->g:I

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
    iget-object v0, v0, Lyk0/h;->d:Lez0/c;

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, Lyk0/j;->e:Lez0/c;

    .line 54
    .line 55
    iput-object p1, v0, Lyk0/h;->d:Lez0/c;

    .line 56
    .line 57
    iput v3, v0, Lyk0/h;->g:I

    .line 58
    .line 59
    invoke-virtual {p1, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    if-ne v0, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    move-object v0, p1

    .line 67
    :goto_1
    const/4 p1, 0x0

    .line 68
    :try_start_0
    iget-object v1, p0, Lyk0/j;->f:Ljava/util/LinkedHashMap;

    .line 69
    .line 70
    invoke-virtual {v1}, Ljava/util/LinkedHashMap;->clear()V

    .line 71
    .line 72
    .line 73
    iget-object p0, p0, Lyk0/j;->a:Lyy0/c2;

    .line 74
    .line 75
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 76
    .line 77
    .line 78
    invoke-interface {v0, p1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    return-object p0

    .line 84
    :catchall_0
    move-exception p0

    .line 85
    invoke-interface {v0, p1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    throw p0
.end method

.method public final d(Lbl0/h0;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lyk0/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lyk0/i;

    .line 7
    .line 8
    iget v1, v0, Lyk0/i;->g:I

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
    iput v1, v0, Lyk0/i;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyk0/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lyk0/i;-><init>(Lyk0/j;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lyk0/i;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyk0/i;->g:I

    .line 30
    .line 31
    iget-object v3, p0, Lyk0/j;->g:Lyy0/c2;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    iget-object p1, v0, Lyk0/i;->d:Lbl0/h0;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    if-eq p1, p2, :cond_3

    .line 60
    .line 61
    iput-object p1, v0, Lyk0/i;->d:Lbl0/h0;

    .line 62
    .line 63
    iput v4, v0, Lyk0/i;->g:I

    .line 64
    .line 65
    invoke-virtual {p0, v0}, Lyk0/j;->c(Lrx0/c;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    if-ne p0, v1, :cond_3

    .line 70
    .line 71
    return-object v1

    .line 72
    :cond_3
    :goto_1
    invoke-virtual {v3, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    return-object p0
.end method
