.class public final Lp50/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/b0;


# instance fields
.field public final d:Lti0/a;

.field public final e:Lpx0/g;


# direct methods
.method public constructor <init>(Lti0/a;)V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    const-string v1, "MDK Cariad Thread Pool"

    .line 3
    .line 4
    invoke-static {v0, v1}, Lvy0/e0;->G(ILjava/lang/String;)Lvy0/b1;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v0, v1}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const-string v1, "coroutineContext"

    .line 17
    .line 18
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lp50/d;->d:Lti0/a;

    .line 25
    .line 26
    iput-object v0, p0, Lp50/d;->e:Lpx0/g;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lp50/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lp50/a;

    .line 7
    .line 8
    iget v1, v0, Lp50/a;->f:I

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
    iput v1, v0, Lp50/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lp50/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lp50/a;-><init>(Lp50/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lp50/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lp50/a;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    check-cast p1, Llx0/o;

    .line 43
    .line 44
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput v4, v0, Lp50/a;->f:I

    .line 63
    .line 64
    iget-object p1, p0, Lp50/d;->d:Lti0/a;

    .line 65
    .line 66
    invoke-interface {p1, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-ne p1, v1, :cond_4

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    :goto_1
    check-cast p1, Li51/a;

    .line 74
    .line 75
    iput v3, v0, Lp50/a;->f:I

    .line 76
    .line 77
    invoke-virtual {p1, v0}, Li51/a;->a(Lrx0/c;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    if-ne p1, v1, :cond_5

    .line 82
    .line 83
    :goto_2
    return-object v1

    .line 84
    :cond_5
    :goto_3
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    if-nez v0, :cond_6

    .line 89
    .line 90
    check-cast p1, Ly41/f;

    .line 91
    .line 92
    new-instance p0, Lt50/c;

    .line 93
    .line 94
    invoke-direct {p0, p1}, Lt50/c;-><init>(Ly41/f;)V

    .line 95
    .line 96
    .line 97
    return-object p0

    .line 98
    :cond_6
    new-instance p1, Lbp0/e;

    .line 99
    .line 100
    const/4 v1, 0x7

    .line 101
    invoke-direct {p1, v0, v1}, Lbp0/e;-><init>(Ljava/lang/Throwable;I)V

    .line 102
    .line 103
    .line 104
    const/4 v0, 0x0

    .line 105
    invoke-static {v0, p0, p1}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 106
    .line 107
    .line 108
    sget-object p0, Lt50/a;->a:Lt50/a;

    .line 109
    .line 110
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Lp50/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lp50/b;

    .line 7
    .line 8
    iget v1, v0, Lp50/b;->g:I

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
    iput v1, v0, Lp50/b;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lp50/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lp50/b;-><init>(Lp50/d;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lp50/b;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lp50/b;->g:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

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
    iget-object p1, v0, Lp50/b;->d:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput-object p1, v0, Lp50/b;->d:Ljava/lang/String;

    .line 61
    .line 62
    iput v4, v0, Lp50/b;->g:I

    .line 63
    .line 64
    invoke-virtual {p0, v0}, Lp50/d;->a(Lrx0/c;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    if-ne p2, v1, :cond_4

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_4
    :goto_1
    check-cast p2, Lt50/b;

    .line 72
    .line 73
    sget-object p0, Lt50/a;->a:Lt50/a;

    .line 74
    .line 75
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    if-eqz p0, :cond_5

    .line 80
    .line 81
    new-instance v4, Lne0/c;

    .line 82
    .line 83
    new-instance v5, Lt50/d;

    .line 84
    .line 85
    invoke-direct {v5}, Lt50/d;-><init>()V

    .line 86
    .line 87
    .line 88
    const/4 v8, 0x0

    .line 89
    const/16 v9, 0x1e

    .line 90
    .line 91
    const/4 v6, 0x0

    .line 92
    const/4 v7, 0x0

    .line 93
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 94
    .line 95
    .line 96
    new-instance p0, Lyy0/m;

    .line 97
    .line 98
    const/4 p1, 0x0

    .line 99
    invoke-direct {p0, v4, p1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 100
    .line 101
    .line 102
    return-object p0

    .line 103
    :cond_5
    instance-of p0, p2, Lt50/c;

    .line 104
    .line 105
    if-eqz p0, :cond_8

    .line 106
    .line 107
    check-cast p2, Lt50/c;

    .line 108
    .line 109
    iget-object p0, p2, Lt50/c;->a:Ly41/f;

    .line 110
    .line 111
    const/4 p2, 0x0

    .line 112
    iput-object p2, v0, Lp50/b;->d:Ljava/lang/String;

    .line 113
    .line 114
    iput v3, v0, Lp50/b;->g:I

    .line 115
    .line 116
    iget-object p0, p0, Ly41/f;->c:Lb81/b;

    .line 117
    .line 118
    invoke-virtual {p0, p1, v0}, Lb81/b;->l(Ljava/lang/String;Lrx0/c;)Ljava/io/Serializable;

    .line 119
    .line 120
    .line 121
    move-result-object p2

    .line 122
    if-ne p2, v1, :cond_6

    .line 123
    .line 124
    :goto_2
    return-object v1

    .line 125
    :cond_6
    :goto_3
    check-cast p2, Lz41/e;

    .line 126
    .line 127
    if-nez p2, :cond_7

    .line 128
    .line 129
    new-instance p0, Lne0/e;

    .line 130
    .line 131
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    new-instance p1, Lyy0/m;

    .line 137
    .line 138
    const/4 p2, 0x0

    .line 139
    invoke-direct {p1, p0, p2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 140
    .line 141
    .line 142
    return-object p1

    .line 143
    :cond_7
    new-instance v0, Lne0/c;

    .line 144
    .line 145
    new-instance v1, Lt11/a;

    .line 146
    .line 147
    iget-object p0, p2, Lz41/e;->d:Ljava/lang/String;

    .line 148
    .line 149
    const-string p1, "reason"

    .line 150
    .line 151
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    const/4 p1, 0x1

    .line 155
    invoke-direct {v1, p0, p1}, Lt11/a;-><init>(Ljava/lang/String;I)V

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
    new-instance p0, Lyy0/m;

    .line 167
    .line 168
    const/4 p1, 0x0

    .line 169
    invoke-direct {p0, v0, p1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 170
    .line 171
    .line 172
    return-object p0

    .line 173
    :cond_8
    new-instance p0, La8/r0;

    .line 174
    .line 175
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 176
    .line 177
    .line 178
    throw p0
.end method

.method public final c(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Lp50/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lp50/c;

    .line 7
    .line 8
    iget v1, v0, Lp50/c;->g:I

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
    iput v1, v0, Lp50/c;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lp50/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lp50/c;-><init>(Lp50/d;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lp50/c;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lp50/c;->g:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

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
    iget-object p1, v0, Lp50/c;->d:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput-object p1, v0, Lp50/c;->d:Ljava/lang/String;

    .line 61
    .line 62
    iput v4, v0, Lp50/c;->g:I

    .line 63
    .line 64
    invoke-virtual {p0, v0}, Lp50/d;->a(Lrx0/c;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    if-ne p2, v1, :cond_4

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_4
    :goto_1
    check-cast p2, Lt50/b;

    .line 72
    .line 73
    sget-object p0, Lt50/a;->a:Lt50/a;

    .line 74
    .line 75
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    if-eqz p0, :cond_5

    .line 80
    .line 81
    new-instance v4, Lne0/c;

    .line 82
    .line 83
    new-instance v5, Lt50/d;

    .line 84
    .line 85
    invoke-direct {v5}, Lt50/d;-><init>()V

    .line 86
    .line 87
    .line 88
    const/4 v8, 0x0

    .line 89
    const/16 v9, 0x1e

    .line 90
    .line 91
    const/4 v6, 0x0

    .line 92
    const/4 v7, 0x0

    .line 93
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 94
    .line 95
    .line 96
    new-instance p0, Lyy0/m;

    .line 97
    .line 98
    const/4 p1, 0x0

    .line 99
    invoke-direct {p0, v4, p1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 100
    .line 101
    .line 102
    return-object p0

    .line 103
    :cond_5
    instance-of p0, p2, Lt50/c;

    .line 104
    .line 105
    if-eqz p0, :cond_8

    .line 106
    .line 107
    check-cast p2, Lt50/c;

    .line 108
    .line 109
    iget-object p0, p2, Lt50/c;->a:Ly41/f;

    .line 110
    .line 111
    const/4 p2, 0x0

    .line 112
    iput-object p2, v0, Lp50/c;->d:Ljava/lang/String;

    .line 113
    .line 114
    iput v3, v0, Lp50/c;->g:I

    .line 115
    .line 116
    iget-object p0, p0, Ly41/f;->b:Lb81/a;

    .line 117
    .line 118
    invoke-virtual {p0, p1, v0}, Lb81/a;->t(Ljava/lang/String;Lrx0/c;)Ljava/io/Serializable;

    .line 119
    .line 120
    .line 121
    move-result-object p2

    .line 122
    if-ne p2, v1, :cond_6

    .line 123
    .line 124
    :goto_2
    return-object v1

    .line 125
    :cond_6
    :goto_3
    check-cast p2, Lz41/e;

    .line 126
    .line 127
    if-nez p2, :cond_7

    .line 128
    .line 129
    new-instance p0, Lne0/e;

    .line 130
    .line 131
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    new-instance p1, Lyy0/m;

    .line 137
    .line 138
    const/4 p2, 0x0

    .line 139
    invoke-direct {p1, p0, p2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 140
    .line 141
    .line 142
    return-object p1

    .line 143
    :cond_7
    new-instance v0, Lne0/c;

    .line 144
    .line 145
    new-instance v1, Lt11/a;

    .line 146
    .line 147
    iget-object p0, p2, Lz41/e;->d:Ljava/lang/String;

    .line 148
    .line 149
    const-string p1, "reason"

    .line 150
    .line 151
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    const/4 p1, 0x2

    .line 155
    invoke-direct {v1, p0, p1}, Lt11/a;-><init>(Ljava/lang/String;I)V

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
    new-instance p0, Lyy0/m;

    .line 167
    .line 168
    const/4 p1, 0x0

    .line 169
    invoke-direct {p0, v0, p1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 170
    .line 171
    .line 172
    return-object p0

    .line 173
    :cond_8
    new-instance p0, La8/r0;

    .line 174
    .line 175
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 176
    .line 177
    .line 178
    throw p0
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lp50/d;->e:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method
