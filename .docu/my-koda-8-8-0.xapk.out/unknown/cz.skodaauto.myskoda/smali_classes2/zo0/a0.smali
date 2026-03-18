.class public final Lzo0/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lzo0/o;

.field public final b:Lwo0/f;

.field public final c:Lzo0/m;


# direct methods
.method public constructor <init>(Lzo0/o;Lwo0/f;Lzo0/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzo0/a0;->a:Lzo0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lzo0/a0;->b:Lwo0/f;

    .line 7
    .line 8
    iput-object p3, p0, Lzo0/a0;->c:Lzo0/m;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lzo0/a0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Lzo0/u;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lzo0/u;

    .line 7
    .line 8
    iget v1, v0, Lzo0/u;->j:I

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
    iput v1, v0, Lzo0/u;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzo0/u;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lzo0/u;-><init>(Lzo0/a0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lzo0/u;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lzo0/u;->j:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v5, 0x0

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
    iget-object p0, v0, Lzo0/u;->e:Lez0/a;

    .line 41
    .line 42
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    .line 45
    goto :goto_3

    .line 46
    :catchall_0
    move-exception v0

    .line 47
    move-object p1, v0

    .line 48
    goto :goto_4

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget p0, v0, Lzo0/u;->g:I

    .line 58
    .line 59
    iget v2, v0, Lzo0/u;->f:I

    .line 60
    .line 61
    iget-object v4, v0, Lzo0/u;->e:Lez0/a;

    .line 62
    .line 63
    iget-object v6, v0, Lzo0/u;->d:Lzo0/a0;

    .line 64
    .line 65
    :try_start_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 66
    .line 67
    .line 68
    move-object p1, v4

    .line 69
    move v4, v2

    .line 70
    move v2, p0

    .line 71
    move-object p0, v6

    .line 72
    goto :goto_1

    .line 73
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    :try_start_2
    iget-object p1, p0, Lzo0/a0;->c:Lzo0/m;

    .line 77
    .line 78
    check-cast p1, Lwo0/d;

    .line 79
    .line 80
    iget-object p1, p1, Lwo0/d;->b:Lez0/c;

    .line 81
    .line 82
    iput-object p0, v0, Lzo0/u;->d:Lzo0/a0;

    .line 83
    .line 84
    iput-object p1, v0, Lzo0/u;->e:Lez0/a;

    .line 85
    .line 86
    const/4 v2, 0x0

    .line 87
    iput v2, v0, Lzo0/u;->f:I

    .line 88
    .line 89
    iput v2, v0, Lzo0/u;->g:I

    .line 90
    .line 91
    iput v4, v0, Lzo0/u;->j:I

    .line 92
    .line 93
    invoke-virtual {p1, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 97
    if-ne v4, v1, :cond_4

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_4
    move v4, v2

    .line 101
    :goto_1
    :try_start_3
    iput-object v5, v0, Lzo0/u;->d:Lzo0/a0;

    .line 102
    .line 103
    iput-object p1, v0, Lzo0/u;->e:Lez0/a;

    .line 104
    .line 105
    iput v4, v0, Lzo0/u;->f:I

    .line 106
    .line 107
    iput v2, v0, Lzo0/u;->g:I

    .line 108
    .line 109
    iput v3, v0, Lzo0/u;->j:I

    .line 110
    .line 111
    invoke-virtual {p0, v0}, Lzo0/a0;->g(Lrx0/c;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 115
    if-ne p0, v1, :cond_5

    .line 116
    .line 117
    :goto_2
    return-object v1

    .line 118
    :cond_5
    move-object v7, p1

    .line 119
    move-object p1, p0

    .line 120
    move-object p0, v7

    .line 121
    :goto_3
    :try_start_4
    check-cast p1, Lne0/t;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 122
    .line 123
    :try_start_5
    invoke-interface {p0, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    goto :goto_5

    .line 127
    :catchall_1
    move-exception v0

    .line 128
    move-object p0, v0

    .line 129
    move-object v7, p1

    .line 130
    move-object p1, p0

    .line 131
    move-object p0, v7

    .line 132
    :goto_4
    invoke-interface {p0, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    throw p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 136
    :catchall_2
    move-exception v0

    .line 137
    move-object p0, v0

    .line 138
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    :goto_5
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    if-nez p0, :cond_6

    .line 147
    .line 148
    goto :goto_6

    .line 149
    :cond_6
    new-instance v0, Lne0/c;

    .line 150
    .line 151
    new-instance v1, Ljava/lang/Exception;

    .line 152
    .line 153
    const-string p0, "Notification token is not available"

    .line 154
    .line 155
    invoke-direct {v1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    const/4 v4, 0x0

    .line 159
    const/16 v5, 0x1e

    .line 160
    .line 161
    const/4 v2, 0x0

    .line 162
    const/4 v3, 0x0

    .line 163
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 164
    .line 165
    .line 166
    move-object p1, v0

    .line 167
    :goto_6
    return-object p1
.end method

.method public final c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lzo0/v;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lzo0/v;

    .line 7
    .line 8
    iget v1, v0, Lzo0/v;->g:I

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
    iput v1, v0, Lzo0/v;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzo0/v;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lzo0/v;-><init>(Lzo0/a0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lzo0/v;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lzo0/v;->g:I

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
    iget-object p1, v0, Lzo0/v;->d:Ljava/lang/String;

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
    iput-object p1, v0, Lzo0/v;->d:Ljava/lang/String;

    .line 54
    .line 55
    iput v3, v0, Lzo0/v;->g:I

    .line 56
    .line 57
    iget-object p0, p0, Lzo0/a0;->c:Lzo0/m;

    .line 58
    .line 59
    check-cast p0, Lwo0/d;

    .line 60
    .line 61
    iget-object p0, p0, Lwo0/d;->a:Lve0/u;

    .line 62
    .line 63
    const-string p2, "last_uploaded_notification_language"

    .line 64
    .line 65
    invoke-virtual {p0, p2, v0}, Lve0/u;->f(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    if-ne p2, v1, :cond_3

    .line 70
    .line 71
    return-object v1

    .line 72
    :cond_3
    :goto_1
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    xor-int/2addr p0, v3

    .line 77
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0
.end method

.method public final d(Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Lzo0/w;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lzo0/w;

    .line 7
    .line 8
    iget v1, v0, Lzo0/w;->g:I

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
    iput v1, v0, Lzo0/w;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzo0/w;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lzo0/w;-><init>(Lzo0/a0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lzo0/w;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lzo0/w;->g:I

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
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-object p3

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
    iget-object p1, v0, Lzo0/w;->d:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput-object p1, v0, Lzo0/w;->d:Ljava/lang/String;

    .line 61
    .line 62
    iput v4, v0, Lzo0/w;->g:I

    .line 63
    .line 64
    invoke-virtual {p0, p2, v0}, Lzo0/a0;->c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p3

    .line 68
    if-ne p3, v1, :cond_4

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_4
    :goto_1
    check-cast p3, Ljava/lang/Boolean;

    .line 72
    .line 73
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 74
    .line 75
    .line 76
    move-result p2

    .line 77
    if-nez p2, :cond_6

    .line 78
    .line 79
    const/4 p2, 0x0

    .line 80
    iput-object p2, v0, Lzo0/w;->d:Ljava/lang/String;

    .line 81
    .line 82
    iput v3, v0, Lzo0/w;->g:I

    .line 83
    .line 84
    invoke-virtual {p0, p1, v0}, Lzo0/a0;->e(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    if-ne p0, v1, :cond_5

    .line 89
    .line 90
    :goto_2
    return-object v1

    .line 91
    :cond_5
    return-object p0

    .line 92
    :cond_6
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 93
    .line 94
    return-object p0
.end method

.method public final e(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lzo0/x;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lzo0/x;

    .line 7
    .line 8
    iget v1, v0, Lzo0/x;->g:I

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
    iput v1, v0, Lzo0/x;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzo0/x;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lzo0/x;-><init>(Lzo0/a0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lzo0/x;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lzo0/x;->g:I

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
    iget-object p1, v0, Lzo0/x;->d:Ljava/lang/String;

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
    iput-object p1, v0, Lzo0/x;->d:Ljava/lang/String;

    .line 54
    .line 55
    iput v3, v0, Lzo0/x;->g:I

    .line 56
    .line 57
    iget-object p0, p0, Lzo0/a0;->c:Lzo0/m;

    .line 58
    .line 59
    check-cast p0, Lwo0/d;

    .line 60
    .line 61
    iget-object p0, p0, Lwo0/d;->a:Lve0/u;

    .line 62
    .line 63
    const-string p2, "last_uploaded_notification_token"

    .line 64
    .line 65
    invoke-virtual {p0, p2, v0}, Lve0/u;->f(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    if-ne p2, v1, :cond_3

    .line 70
    .line 71
    return-object v1

    .line 72
    :cond_3
    :goto_1
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    xor-int/2addr p0, v3

    .line 77
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0
.end method

.method public final f(Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    instance-of v2, v1, Lzo0/y;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lzo0/y;

    .line 11
    .line 12
    iget v3, v2, Lzo0/y;->i:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lzo0/y;->i:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lzo0/y;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lzo0/y;-><init>(Lzo0/a0;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lzo0/y;->g:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lzo0/y;->i:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    iget-object v6, v0, Lzo0/a0;->c:Lzo0/m;

    .line 38
    .line 39
    const/4 v7, 0x3

    .line 40
    const/4 v8, 0x2

    .line 41
    const/4 v9, 0x1

    .line 42
    const/4 v14, 0x0

    .line 43
    if-eqz v4, :cond_4

    .line 44
    .line 45
    if-eq v4, v9, :cond_3

    .line 46
    .line 47
    if-eq v4, v8, :cond_2

    .line 48
    .line 49
    if-ne v4, v7, :cond_1

    .line 50
    .line 51
    iget-object v0, v2, Lzo0/y;->f:Lne0/t;

    .line 52
    .line 53
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    return-object v0

    .line 57
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_2
    iget-object v0, v2, Lzo0/y;->f:Lne0/t;

    .line 66
    .line 67
    iget-object v4, v2, Lzo0/y;->e:Ljava/lang/String;

    .line 68
    .line 69
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto/16 :goto_3

    .line 73
    .line 74
    :cond_3
    iget-object v0, v2, Lzo0/y;->e:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v4, v2, Lzo0/y;->d:Ljava/lang/String;

    .line 77
    .line 78
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    move-object/from16 v12, p1

    .line 86
    .line 87
    iput-object v12, v2, Lzo0/y;->d:Ljava/lang/String;

    .line 88
    .line 89
    move-object/from16 v1, p2

    .line 90
    .line 91
    iput-object v1, v2, Lzo0/y;->e:Ljava/lang/String;

    .line 92
    .line 93
    iput v9, v2, Lzo0/y;->i:I

    .line 94
    .line 95
    iget-object v11, v0, Lzo0/a0;->b:Lwo0/f;

    .line 96
    .line 97
    new-instance v13, Lcz/myskoda/api/bff/v1/NotificationSubscriptionDto;

    .line 98
    .line 99
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    invoke-virtual {v0}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    const-string v4, "getLanguage(...)"

    .line 108
    .line 109
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const/16 v24, 0xf8

    .line 113
    .line 114
    const/16 v25, 0x0

    .line 115
    .line 116
    const-string v16, "ANDROID"

    .line 117
    .line 118
    const-string v17, "8.8.0"

    .line 119
    .line 120
    const/16 v19, 0x0

    .line 121
    .line 122
    const/16 v20, 0x0

    .line 123
    .line 124
    const/16 v21, 0x0

    .line 125
    .line 126
    const/16 v22, 0x0

    .line 127
    .line 128
    const/16 v23, 0x0

    .line 129
    .line 130
    move-object/from16 v18, v0

    .line 131
    .line 132
    move-object v15, v13

    .line 133
    invoke-direct/range {v15 .. v25}, Lcz/myskoda/api/bff/v1/NotificationSubscriptionDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;ILkotlin/jvm/internal/g;)V

    .line 134
    .line 135
    .line 136
    iget-object v0, v11, Lwo0/f;->a:Lxl0/f;

    .line 137
    .line 138
    new-instance v10, Lo10/l;

    .line 139
    .line 140
    const/16 v15, 0x10

    .line 141
    .line 142
    invoke-direct/range {v10 .. v15}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v0, v10, v2}, Lxl0/f;->i(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    if-ne v0, v3, :cond_5

    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_5
    move-object v4, v1

    .line 153
    move-object v1, v0

    .line 154
    move-object v0, v4

    .line 155
    move-object/from16 v4, p1

    .line 156
    .line 157
    :goto_1
    check-cast v1, Lne0/t;

    .line 158
    .line 159
    instance-of v9, v1, Lne0/e;

    .line 160
    .line 161
    if-eqz v9, :cond_a

    .line 162
    .line 163
    iput-object v14, v2, Lzo0/y;->d:Ljava/lang/String;

    .line 164
    .line 165
    iput-object v0, v2, Lzo0/y;->e:Ljava/lang/String;

    .line 166
    .line 167
    iput-object v1, v2, Lzo0/y;->f:Lne0/t;

    .line 168
    .line 169
    iput v8, v2, Lzo0/y;->i:I

    .line 170
    .line 171
    move-object v8, v6

    .line 172
    check-cast v8, Lwo0/d;

    .line 173
    .line 174
    iget-object v8, v8, Lwo0/d;->a:Lve0/u;

    .line 175
    .line 176
    const-string v9, "last_uploaded_notification_token"

    .line 177
    .line 178
    invoke-virtual {v8, v9, v4, v2}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v4

    .line 182
    if-ne v4, v3, :cond_6

    .line 183
    .line 184
    goto :goto_2

    .line 185
    :cond_6
    move-object v4, v5

    .line 186
    :goto_2
    if-ne v4, v3, :cond_7

    .line 187
    .line 188
    goto :goto_4

    .line 189
    :cond_7
    move-object v4, v0

    .line 190
    move-object v0, v1

    .line 191
    :goto_3
    iput-object v14, v2, Lzo0/y;->d:Ljava/lang/String;

    .line 192
    .line 193
    iput-object v14, v2, Lzo0/y;->e:Ljava/lang/String;

    .line 194
    .line 195
    iput-object v0, v2, Lzo0/y;->f:Lne0/t;

    .line 196
    .line 197
    iput v7, v2, Lzo0/y;->i:I

    .line 198
    .line 199
    check-cast v6, Lwo0/d;

    .line 200
    .line 201
    iget-object v1, v6, Lwo0/d;->a:Lve0/u;

    .line 202
    .line 203
    const-string v6, "last_uploaded_notification_language"

    .line 204
    .line 205
    invoke-virtual {v1, v6, v4, v2}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v1

    .line 209
    if-ne v1, v3, :cond_8

    .line 210
    .line 211
    move-object v5, v1

    .line 212
    :cond_8
    if-ne v5, v3, :cond_9

    .line 213
    .line 214
    :goto_4
    return-object v3

    .line 215
    :cond_9
    return-object v0

    .line 216
    :cond_a
    return-object v1
.end method

.method public final g(Lrx0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p1, Lzo0/z;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lzo0/z;

    .line 7
    .line 8
    iget v1, v0, Lzo0/z;->h:I

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
    iput v1, v0, Lzo0/z;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzo0/z;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lzo0/z;-><init>(Lzo0/a0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lzo0/z;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lzo0/z;->h:I

    .line 30
    .line 31
    const/4 v3, 0x4

    .line 32
    const/4 v4, 0x3

    .line 33
    const/4 v5, 0x2

    .line 34
    const/4 v6, 0x1

    .line 35
    if-eqz v2, :cond_5

    .line 36
    .line 37
    if-eq v2, v6, :cond_4

    .line 38
    .line 39
    if-eq v2, v5, :cond_3

    .line 40
    .line 41
    if-eq v2, v4, :cond_2

    .line 42
    .line 43
    if-ne v2, v3, :cond_1

    .line 44
    .line 45
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-object p1

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget-object v2, v0, Lzo0/z;->e:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v4, v0, Lzo0/z;->d:Ljava/lang/String;

    .line 60
    .line 61
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_3
    iget-object v2, v0, Lzo0/z;->d:Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_4
    iget-object v2, v0, Lzo0/z;->d:Ljava/lang/String;

    .line 72
    .line 73
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    invoke-virtual {p1}, Ljava/util/Locale;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    const-string p1, "toString(...)"

    .line 89
    .line 90
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    iput-object v2, v0, Lzo0/z;->d:Ljava/lang/String;

    .line 94
    .line 95
    iput v6, v0, Lzo0/z;->h:I

    .line 96
    .line 97
    iget-object p1, p0, Lzo0/a0;->a:Lzo0/o;

    .line 98
    .line 99
    check-cast p1, Lxo0/a;

    .line 100
    .line 101
    invoke-virtual {p1}, Lxo0/a;->a()Lyy0/h2;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    if-ne p1, v1, :cond_6

    .line 106
    .line 107
    goto :goto_4

    .line 108
    :cond_6
    :goto_1
    check-cast p1, Lyy0/i;

    .line 109
    .line 110
    iput-object v2, v0, Lzo0/z;->d:Ljava/lang/String;

    .line 111
    .line 112
    iput v5, v0, Lzo0/z;->h:I

    .line 113
    .line 114
    invoke-static {p1, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    if-ne p1, v1, :cond_7

    .line 119
    .line 120
    goto :goto_4

    .line 121
    :cond_7
    :goto_2
    check-cast p1, Ljava/lang/String;

    .line 122
    .line 123
    if-nez p1, :cond_8

    .line 124
    .line 125
    new-instance v5, Lne0/c;

    .line 126
    .line 127
    new-instance v6, Ljava/lang/Exception;

    .line 128
    .line 129
    const-string p0, "Notification token is not available"

    .line 130
    .line 131
    invoke-direct {v6, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    const/4 v9, 0x0

    .line 135
    const/16 v10, 0x1e

    .line 136
    .line 137
    const/4 v7, 0x0

    .line 138
    const/4 v8, 0x0

    .line 139
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 140
    .line 141
    .line 142
    return-object v5

    .line 143
    :cond_8
    iput-object v2, v0, Lzo0/z;->d:Ljava/lang/String;

    .line 144
    .line 145
    iput-object p1, v0, Lzo0/z;->e:Ljava/lang/String;

    .line 146
    .line 147
    iput v4, v0, Lzo0/z;->h:I

    .line 148
    .line 149
    invoke-virtual {p0, p1, v2, v0}, Lzo0/a0;->d(Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v4

    .line 153
    if-ne v4, v1, :cond_9

    .line 154
    .line 155
    goto :goto_4

    .line 156
    :cond_9
    move-object v11, v2

    .line 157
    move-object v2, p1

    .line 158
    move-object p1, v4

    .line 159
    move-object v4, v11

    .line 160
    :goto_3
    check-cast p1, Ljava/lang/Boolean;

    .line 161
    .line 162
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 163
    .line 164
    .line 165
    move-result p1

    .line 166
    if-nez p1, :cond_a

    .line 167
    .line 168
    new-instance p0, Lne0/e;

    .line 169
    .line 170
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 171
    .line 172
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    return-object p0

    .line 176
    :cond_a
    const/4 p1, 0x0

    .line 177
    iput-object p1, v0, Lzo0/z;->d:Ljava/lang/String;

    .line 178
    .line 179
    iput-object p1, v0, Lzo0/z;->e:Ljava/lang/String;

    .line 180
    .line 181
    iput v3, v0, Lzo0/z;->h:I

    .line 182
    .line 183
    invoke-virtual {p0, v2, v4, v0}, Lzo0/a0;->f(Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    if-ne p0, v1, :cond_b

    .line 188
    .line 189
    :goto_4
    return-object v1

    .line 190
    :cond_b
    return-object p0
.end method
