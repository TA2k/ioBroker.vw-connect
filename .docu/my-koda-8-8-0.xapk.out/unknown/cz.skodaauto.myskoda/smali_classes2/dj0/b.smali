.class public final Ldj0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lfj0/e;


# instance fields
.field public final a:Lez0/c;

.field public final b:Lyy0/q1;

.field public final c:Lyy0/q1;

.field public final d:Lyy0/q1;

.field public final e:Lyy0/q1;

.field public final f:Lyy0/k1;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/l1;


# direct methods
.method public constructor <init>(Ljava/util/Locale;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Ldj0/b;->a:Lez0/c;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    const/4 v1, 0x6

    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    iput-object v3, p0, Ldj0/b;->b:Lyy0/q1;

    .line 18
    .line 19
    iput-object v3, p0, Ldj0/b;->c:Lyy0/q1;

    .line 20
    .line 21
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iput-object v0, p0, Ldj0/b;->d:Lyy0/q1;

    .line 26
    .line 27
    const/4 v0, 0x5

    .line 28
    const/4 v1, 0x1

    .line 29
    invoke-static {v1, v0, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iput-object v0, p0, Ldj0/b;->e:Lyy0/q1;

    .line 34
    .line 35
    new-instance v1, Lyy0/k1;

    .line 36
    .line 37
    invoke-direct {v1, v0}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 38
    .line 39
    .line 40
    iput-object v1, p0, Ldj0/b;->f:Lyy0/k1;

    .line 41
    .line 42
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    iput-object p1, p0, Ldj0/b;->g:Lyy0/c2;

    .line 47
    .line 48
    new-instance v0, Lyy0/l1;

    .line 49
    .line 50
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 51
    .line 52
    .line 53
    iput-object v0, p0, Ldj0/b;->h:Lyy0/l1;

    .line 54
    .line 55
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p1, Ldj0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ldj0/a;

    .line 7
    .line 8
    iget v1, v0, Ldj0/a;->i:I

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
    iput v1, v0, Ldj0/a;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ldj0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ldj0/a;-><init>(Ldj0/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ldj0/a;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ldj0/a;->i:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x3

    .line 33
    const/4 v5, 0x2

    .line 34
    const/4 v6, 0x1

    .line 35
    const/4 v7, 0x0

    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    if-eq v2, v6, :cond_3

    .line 39
    .line 40
    if-eq v2, v5, :cond_2

    .line 41
    .line 42
    if-ne v2, v4, :cond_1

    .line 43
    .line 44
    iget-object p0, v0, Ldj0/a;->d:Lez0/a;

    .line 45
    .line 46
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 47
    .line 48
    .line 49
    goto :goto_4

    .line 50
    :catchall_0
    move-exception p1

    .line 51
    goto/16 :goto_5

    .line 52
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
    iget v3, v0, Ldj0/a;->f:I

    .line 62
    .line 63
    iget v2, v0, Ldj0/a;->e:I

    .line 64
    .line 65
    iget-object v5, v0, Ldj0/a;->d:Lez0/a;

    .line 66
    .line 67
    :try_start_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 68
    .line 69
    .line 70
    move-object p1, v5

    .line 71
    goto :goto_2

    .line 72
    :catchall_1
    move-exception p1

    .line 73
    move-object p0, v5

    .line 74
    goto :goto_5

    .line 75
    :cond_3
    iget v2, v0, Ldj0/a;->e:I

    .line 76
    .line 77
    iget-object v6, v0, Ldj0/a;->d:Lez0/a;

    .line 78
    .line 79
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    move-object p1, v6

    .line 83
    goto :goto_1

    .line 84
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    iget-object p1, p0, Ldj0/b;->a:Lez0/c;

    .line 88
    .line 89
    iput-object p1, v0, Ldj0/a;->d:Lez0/a;

    .line 90
    .line 91
    iput v3, v0, Ldj0/a;->e:I

    .line 92
    .line 93
    iput v6, v0, Ldj0/a;->i:I

    .line 94
    .line 95
    invoke-virtual {p1, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    if-ne v2, v1, :cond_5

    .line 100
    .line 101
    goto :goto_3

    .line 102
    :cond_5
    move v2, v3

    .line 103
    :goto_1
    :try_start_2
    iget-object v6, p0, Ldj0/b;->b:Lyy0/q1;

    .line 104
    .line 105
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    iput-object p1, v0, Ldj0/a;->d:Lez0/a;

    .line 108
    .line 109
    iput v2, v0, Ldj0/a;->e:I

    .line 110
    .line 111
    iput v3, v0, Ldj0/a;->f:I

    .line 112
    .line 113
    iput v5, v0, Ldj0/a;->i:I

    .line 114
    .line 115
    invoke-virtual {v6, v8, v0}, Lyy0/q1;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v5

    .line 119
    if-ne v5, v1, :cond_6

    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_6
    :goto_2
    iget-object p0, p0, Ldj0/b;->d:Lyy0/q1;

    .line 123
    .line 124
    iput-object p1, v0, Ldj0/a;->d:Lez0/a;

    .line 125
    .line 126
    iput v2, v0, Ldj0/a;->e:I

    .line 127
    .line 128
    iput v3, v0, Ldj0/a;->f:I

    .line 129
    .line 130
    iput v4, v0, Ldj0/a;->i:I

    .line 131
    .line 132
    invoke-static {p0, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 136
    if-ne p0, v1, :cond_7

    .line 137
    .line 138
    :goto_3
    return-object v1

    .line 139
    :cond_7
    move-object v9, p1

    .line 140
    move-object p1, p0

    .line 141
    move-object p0, v9

    .line 142
    :goto_4
    :try_start_3
    check-cast p1, Lne0/t;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 143
    .line 144
    invoke-interface {p0, v7}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    return-object p1

    .line 148
    :catchall_2
    move-exception p0

    .line 149
    move-object v9, p1

    .line 150
    move-object p1, p0

    .line 151
    move-object p0, v9

    .line 152
    :goto_5
    invoke-interface {p0, v7}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    throw p1
.end method
