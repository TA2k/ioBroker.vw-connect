.class public final Li7/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Li7/a;


# static fields
.field public static final a:Li7/f;

.field public static final b:Lez0/c;

.field public static final c:Ljava/util/LinkedHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Li7/f;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Li7/f;->a:Li7/f;

    .line 7
    .line 8
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sput-object v0, Li7/f;->b:Lez0/c;

    .line 13
    .line 14
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 15
    .line 16
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 17
    .line 18
    .line 19
    sput-object v0, Li7/f;->c:Ljava/util/LinkedHashMap;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;Li7/g;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p4, Li7/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Li7/b;

    .line 7
    .line 8
    iget v1, v0, Li7/b;->j:I

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
    iput v1, v0, Li7/b;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li7/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Li7/b;-><init>(Li7/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Li7/b;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p4, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Li7/b;->j:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-ne v1, v2, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Li7/b;->g:Lez0/c;

    .line 37
    .line 38
    iget-object p3, v0, Li7/b;->f:Ljava/lang/String;

    .line 39
    .line 40
    iget-object p2, v0, Li7/b;->e:Li7/g;

    .line 41
    .line 42
    iget-object p4, v0, Li7/b;->d:Landroid/content/Context;

    .line 43
    .line 44
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    move-object p0, p1

    .line 48
    move-object p1, p4

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iput-object p1, v0, Li7/b;->d:Landroid/content/Context;

    .line 62
    .line 63
    iput-object p2, v0, Li7/b;->e:Li7/g;

    .line 64
    .line 65
    iput-object p3, v0, Li7/b;->f:Ljava/lang/String;

    .line 66
    .line 67
    sget-object p0, Li7/f;->b:Lez0/c;

    .line 68
    .line 69
    iput-object p0, v0, Li7/b;->g:Lez0/c;

    .line 70
    .line 71
    iput v2, v0, Li7/b;->j:I

    .line 72
    .line 73
    invoke-virtual {p0, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    if-ne v0, p4, :cond_3

    .line 78
    .line 79
    return-object p4

    .line 80
    :cond_3
    :goto_1
    const/4 p4, 0x0

    .line 81
    :try_start_0
    sget-object v0, Li7/f;->c:Ljava/util/LinkedHashMap;

    .line 82
    .line 83
    invoke-interface {v0, p3}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    invoke-interface {p2, p1, p3}, Li7/g;->a(Landroid/content/Context;Ljava/lang/String;)Ljava/io/File;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    invoke-virtual {p1}, Ljava/io/File;->delete()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 91
    .line 92
    .line 93
    invoke-interface {p0, p4}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    return-object p0

    .line 99
    :catchall_0
    move-exception p1

    .line 100
    invoke-interface {p0, p4}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    throw p1
.end method

.method public final b(Landroid/content/Context;Li7/g;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p4, Li7/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Li7/c;

    .line 7
    .line 8
    iget v1, v0, Li7/c;->j:I

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
    iput v1, v0, Li7/c;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li7/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Li7/c;-><init>(Li7/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Li7/c;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p4, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Li7/c;->j:I

    .line 30
    .line 31
    const/4 v2, 0x2

    .line 32
    const/4 v3, 0x1

    .line 33
    const/4 v4, 0x0

    .line 34
    if-eqz v1, :cond_3

    .line 35
    .line 36
    if-eq v1, v3, :cond_2

    .line 37
    .line 38
    if-ne v1, v2, :cond_1

    .line 39
    .line 40
    iget-object p1, v0, Li7/c;->f:Ljava/io/Serializable;

    .line 41
    .line 42
    check-cast p1, Ljava/util/Map;

    .line 43
    .line 44
    iget-object p2, v0, Li7/c;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p2, Lez0/a;

    .line 47
    .line 48
    iget-object p3, v0, Li7/c;->d:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p3, Ljava/lang/String;

    .line 51
    .line 52
    :try_start_0
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 53
    .line 54
    .line 55
    goto :goto_3

    .line 56
    :catchall_0
    move-exception p0

    .line 57
    goto/16 :goto_5

    .line 58
    .line 59
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 62
    .line 63
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw p0

    .line 67
    :cond_2
    iget-object p1, v0, Li7/c;->g:Lez0/c;

    .line 68
    .line 69
    iget-object p2, v0, Li7/c;->f:Ljava/io/Serializable;

    .line 70
    .line 71
    move-object p3, p2

    .line 72
    check-cast p3, Ljava/lang/String;

    .line 73
    .line 74
    iget-object p2, v0, Li7/c;->e:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p2, Li7/g;

    .line 77
    .line 78
    iget-object v1, v0, Li7/c;->d:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v1, Landroid/content/Context;

    .line 81
    .line 82
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    move-object p0, p1

    .line 86
    move-object p1, v1

    .line 87
    goto :goto_1

    .line 88
    :cond_3
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    iput-object p1, v0, Li7/c;->d:Ljava/lang/Object;

    .line 92
    .line 93
    iput-object p2, v0, Li7/c;->e:Ljava/lang/Object;

    .line 94
    .line 95
    iput-object p3, v0, Li7/c;->f:Ljava/io/Serializable;

    .line 96
    .line 97
    sget-object p0, Li7/f;->b:Lez0/c;

    .line 98
    .line 99
    iput-object p0, v0, Li7/c;->g:Lez0/c;

    .line 100
    .line 101
    iput v3, v0, Li7/c;->j:I

    .line 102
    .line 103
    invoke-virtual {p0, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    if-ne v1, p4, :cond_4

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_4
    :goto_1
    :try_start_1
    sget-object v1, Li7/f;->c:Ljava/util/LinkedHashMap;

    .line 111
    .line 112
    invoke-virtual {v1, p3}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v3

    .line 116
    if-nez v3, :cond_6

    .line 117
    .line 118
    iput-object p3, v0, Li7/c;->d:Ljava/lang/Object;

    .line 119
    .line 120
    iput-object p0, v0, Li7/c;->e:Ljava/lang/Object;

    .line 121
    .line 122
    iput-object v1, v0, Li7/c;->f:Ljava/io/Serializable;

    .line 123
    .line 124
    iput-object v4, v0, Li7/c;->g:Lez0/c;

    .line 125
    .line 126
    iput v2, v0, Li7/c;->j:I

    .line 127
    .line 128
    invoke-interface {p2, p1, p3}, Li7/g;->b(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 132
    if-ne p1, p4, :cond_5

    .line 133
    .line 134
    :goto_2
    return-object p4

    .line 135
    :cond_5
    move-object p2, p0

    .line 136
    move-object p0, p1

    .line 137
    move-object p1, v1

    .line 138
    :goto_3
    :try_start_2
    move-object v3, p0

    .line 139
    check-cast v3, Lm6/g;

    .line 140
    .line 141
    invoke-interface {p1, p3, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    goto :goto_4

    .line 145
    :catchall_1
    move-exception p1

    .line 146
    move-object p2, p0

    .line 147
    move-object p0, p1

    .line 148
    goto :goto_5

    .line 149
    :cond_6
    move-object p2, p0

    .line 150
    :goto_4
    const-string p0, "null cannot be cast to non-null type androidx.datastore.core.DataStore<T of androidx.glance.state.GlanceState.getDataStore$lambda$2>"

    .line 151
    .line 152
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    check-cast v3, Lm6/g;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 156
    .line 157
    invoke-interface {p2, v4}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    return-object v3

    .line 161
    :goto_5
    invoke-interface {p2, v4}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    throw p0
.end method

.method public final c(Landroid/content/Context;Li7/g;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p4, Li7/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Li7/d;

    .line 7
    .line 8
    iget v1, v0, Li7/d;->f:I

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
    iput v1, v0, Li7/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li7/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Li7/d;-><init>(Li7/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Li7/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Li7/d;->f:I

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
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-object p4

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iput v4, v0, Li7/d;->f:I

    .line 59
    .line 60
    invoke-virtual {p0, p1, p2, p3, v0}, Li7/f;->b(Landroid/content/Context;Li7/g;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p4

    .line 64
    if-ne p4, v1, :cond_4

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_4
    :goto_1
    check-cast p4, Lm6/g;

    .line 68
    .line 69
    invoke-interface {p4}, Lm6/g;->getData()Lyy0/i;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    iput v3, v0, Li7/d;->f:I

    .line 74
    .line 75
    invoke-static {p0, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    if-ne p0, v1, :cond_5

    .line 80
    .line 81
    :goto_2
    return-object v1

    .line 82
    :cond_5
    return-object p0
.end method

.method public final d(Landroid/content/Context;La7/l1;Ljava/lang/String;La60/f;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p5, Li7/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p5

    .line 6
    check-cast v0, Li7/e;

    .line 7
    .line 8
    iget v1, v0, Li7/e;->g:I

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
    iput v1, v0, Li7/e;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li7/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p5}, Li7/e;-><init>(Li7/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p5, v0, Li7/e;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Li7/e;->g:I

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
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-object p5

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    iget-object p4, v0, Li7/e;->d:La60/f;

    .line 52
    .line 53
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput-object p4, v0, Li7/e;->d:La60/f;

    .line 61
    .line 62
    iput v4, v0, Li7/e;->g:I

    .line 63
    .line 64
    invoke-virtual {p0, p1, p2, p3, v0}, Li7/f;->b(Landroid/content/Context;Li7/g;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p5

    .line 68
    if-ne p5, v1, :cond_4

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_4
    :goto_1
    check-cast p5, Lm6/g;

    .line 72
    .line 73
    const/4 p0, 0x0

    .line 74
    iput-object p0, v0, Li7/e;->d:La60/f;

    .line 75
    .line 76
    iput v3, v0, Li7/e;->g:I

    .line 77
    .line 78
    invoke-interface {p5, p4, v0}, Lm6/g;->a(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    if-ne p0, v1, :cond_5

    .line 83
    .line 84
    :goto_2
    return-object v1

    .line 85
    :cond_5
    return-object p0
.end method
