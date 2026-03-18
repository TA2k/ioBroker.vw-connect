.class public final Lv51/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu51/g;


# instance fields
.field public final a:Lca/d;


# direct methods
.method public constructor <init>(Lca/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv51/f;->a:Lca/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lv51/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lv51/a;

    .line 7
    .line 8
    iget v1, v0, Lv51/a;->f:I

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
    iput v1, v0, Lv51/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lv51/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lv51/a;-><init>(Lv51/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lv51/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lv51/a;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object p2, Lvy0/p0;->a:Lcz0/e;

    .line 52
    .line 53
    sget-object p2, Lcz0/d;->e:Lcz0/d;

    .line 54
    .line 55
    new-instance v2, Lv51/b;

    .line 56
    .line 57
    const/4 v4, 0x0

    .line 58
    const/4 v5, 0x0

    .line 59
    invoke-direct {v2, p0, p1, v4, v5}, Lv51/b;-><init>(Lv51/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 60
    .line 61
    .line 62
    iput v3, v0, Lv51/a;->f:I

    .line 63
    .line 64
    invoke-static {p2, v2, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    if-ne p2, v1, :cond_3

    .line 69
    .line 70
    return-object v1

    .line 71
    :cond_3
    :goto_1
    check-cast p2, Llx0/o;

    .line 72
    .line 73
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 74
    .line 75
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lv51/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lv51/c;

    .line 7
    .line 8
    iget v1, v0, Lv51/c;->f:I

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
    iput v1, v0, Lv51/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lv51/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lv51/c;-><init>(Lv51/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lv51/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lv51/c;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object p2, Lvy0/p0;->a:Lcz0/e;

    .line 52
    .line 53
    sget-object p2, Lcz0/d;->e:Lcz0/d;

    .line 54
    .line 55
    new-instance v2, Lv51/b;

    .line 56
    .line 57
    const/4 v4, 0x0

    .line 58
    invoke-direct {v2, p0, p1, v4, v3}, Lv51/b;-><init>(Lv51/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 59
    .line 60
    .line 61
    iput v3, v0, Lv51/c;->f:I

    .line 62
    .line 63
    invoke-static {p2, v2, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    if-ne p2, v1, :cond_3

    .line 68
    .line 69
    return-object v1

    .line 70
    :cond_3
    :goto_1
    check-cast p2, Llx0/o;

    .line 71
    .line 72
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 73
    .line 74
    return-object p0
.end method

.method public final c(Ljava/lang/String;Lhy0/a0;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p3, Lv51/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lv51/d;

    .line 7
    .line 8
    iget v1, v0, Lv51/d;->f:I

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
    iput v1, v0, Lv51/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lv51/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lv51/d;-><init>(Lv51/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lv51/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lv51/d;->f:I

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
    goto :goto_2

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
    :try_start_0
    const-string p3, "type"

    .line 52
    .line 53
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    sget-object p3, Lxz0/a;->a:Lwq/f;

    .line 57
    .line 58
    invoke-static {p3, p2}, Ljp/mg;->d(Lwq/f;Lhy0/a0;)Lqz0/a;

    .line 59
    .line 60
    .line 61
    move-result-object p3

    .line 62
    instance-of v2, p3, Lqz0/a;
    :try_end_0
    .catch Lqz0/h; {:try_start_0 .. :try_end_0} :catch_0

    .line 63
    .line 64
    const/4 v9, 0x0

    .line 65
    if-eqz v2, :cond_3

    .line 66
    .line 67
    move-object v8, p3

    .line 68
    goto :goto_1

    .line 69
    :cond_3
    move-object v8, v9

    .line 70
    :goto_1
    if-nez v8, :cond_4

    .line 71
    .line 72
    new-instance p0, Lu51/b;

    .line 73
    .line 74
    new-instance p3, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    const-string v0, "Cannot create serializer for "

    .line 77
    .line 78
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p2

    .line 88
    invoke-direct {p0, p1, p2, v9}, Lu51/b;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 89
    .line 90
    .line 91
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0

    .line 96
    :cond_4
    sget-object p2, Lvy0/p0;->a:Lcz0/e;

    .line 97
    .line 98
    sget-object p2, Lcz0/d;->e:Lcz0/d;

    .line 99
    .line 100
    new-instance v4, Lqh/a;

    .line 101
    .line 102
    const/16 v5, 0xd

    .line 103
    .line 104
    move-object v6, p0

    .line 105
    move-object v7, p1

    .line 106
    invoke-direct/range {v4 .. v9}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 107
    .line 108
    .line 109
    iput v3, v0, Lv51/d;->f:I

    .line 110
    .line 111
    invoke-static {p2, v4, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p3

    .line 115
    if-ne p3, v1, :cond_5

    .line 116
    .line 117
    return-object v1

    .line 118
    :cond_5
    :goto_2
    check-cast p3, Llx0/o;

    .line 119
    .line 120
    iget-object p0, p3, Llx0/o;->d:Ljava/lang/Object;

    .line 121
    .line 122
    return-object p0

    .line 123
    :catch_0
    move-exception v0

    .line 124
    move-object v7, p1

    .line 125
    move-object p0, v0

    .line 126
    new-instance p1, Lu51/b;

    .line 127
    .line 128
    new-instance p3, Ljava/lang/StringBuilder;

    .line 129
    .line 130
    invoke-direct {p3}, Ljava/lang/StringBuilder;-><init>()V

    .line 131
    .line 132
    .line 133
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    const-string p2, " is not serializable / has no Serializer"

    .line 137
    .line 138
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object p2

    .line 145
    invoke-direct {p1, v7, p2, p0}, Lu51/b;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 146
    .line 147
    .line 148
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    return-object p0
.end method

.method public final d(Ljava/lang/String;Ljava/lang/Object;Lhy0/a0;Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v3, p4, Lv51/e;

    .line 2
    .line 3
    if-eqz v3, :cond_0

    .line 4
    .line 5
    move-object v3, p4

    .line 6
    check-cast v3, Lv51/e;

    .line 7
    .line 8
    iget v4, v3, Lv51/e;->f:I

    .line 9
    .line 10
    const/high16 v5, -0x80000000

    .line 11
    .line 12
    and-int v6, v4, v5

    .line 13
    .line 14
    if-eqz v6, :cond_0

    .line 15
    .line 16
    sub-int/2addr v4, v5

    .line 17
    iput v4, v3, Lv51/e;->f:I

    .line 18
    .line 19
    :goto_0
    move-object v7, v3

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v3, Lv51/e;

    .line 22
    .line 23
    invoke-direct {v3, p0, p4}, Lv51/e;-><init>(Lv51/f;Lrx0/c;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object v0, v7, Lv51/e;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v7, Lv51/e;->f:I

    .line 32
    .line 33
    const/4 v9, 0x1

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    if-ne v3, v9, :cond_1

    .line 37
    .line 38
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_3

    .line 42
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw v0

    .line 50
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :try_start_0
    const-string v0, "type"

    .line 54
    .line 55
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    sget-object v0, Lxz0/a;->a:Lwq/f;

    .line 59
    .line 60
    invoke-static {v0, p3}, Ljp/mg;->d(Lwq/f;Lhy0/a0;)Lqz0/a;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    instance-of v3, v0, Lqz0/a;
    :try_end_0
    .catch Lqz0/h; {:try_start_0 .. :try_end_0} :catch_0

    .line 65
    .line 66
    const/4 v5, 0x0

    .line 67
    if-eqz v3, :cond_3

    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_3
    move-object v0, v5

    .line 71
    :goto_2
    if-nez v0, :cond_4

    .line 72
    .line 73
    new-instance v0, Lu51/f;

    .line 74
    .line 75
    new-instance v3, Ljava/lang/StringBuilder;

    .line 76
    .line 77
    const-string v4, "Cannot create serializer for "

    .line 78
    .line 79
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v3, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    invoke-direct {v0, p1, v1, v5}, Lu51/f;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 90
    .line 91
    .line 92
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    return-object v0

    .line 97
    :cond_4
    sget-object v1, Lvy0/p0;->a:Lcz0/e;

    .line 98
    .line 99
    sget-object v10, Lcz0/d;->e:Lcz0/d;

    .line 100
    .line 101
    move-object v4, v0

    .line 102
    new-instance v0, Lff/a;

    .line 103
    .line 104
    const/4 v5, 0x0

    .line 105
    const/16 v6, 0xc

    .line 106
    .line 107
    move-object v1, p0

    .line 108
    move-object v2, p1

    .line 109
    move-object v3, p2

    .line 110
    invoke-direct/range {v0 .. v6}, Lff/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 111
    .line 112
    .line 113
    iput v9, v7, Lv51/e;->f:I

    .line 114
    .line 115
    invoke-static {v10, v0, v7}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    if-ne v0, v8, :cond_5

    .line 120
    .line 121
    return-object v8

    .line 122
    :cond_5
    :goto_3
    check-cast v0, Llx0/o;

    .line 123
    .line 124
    iget-object v0, v0, Llx0/o;->d:Ljava/lang/Object;

    .line 125
    .line 126
    return-object v0

    .line 127
    :catch_0
    move-exception v0

    .line 128
    new-instance v3, Lu51/f;

    .line 129
    .line 130
    new-instance v4, Ljava/lang/StringBuilder;

    .line 131
    .line 132
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v4, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    const-string v1, " is not serializable / has no Serializer"

    .line 139
    .line 140
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    invoke-direct {v3, p1, v1, v0}, Lu51/f;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 148
    .line 149
    .line 150
    invoke-static {v3}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    return-object v0
.end method
