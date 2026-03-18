.class public final Lwq0/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/e;

.field public final b:Lwq0/g0;

.field public final c:Ltq0/k;

.field public final d:Lwq0/r;

.field public final e:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lkf0/e;Lwq0/g0;Ltq0/k;Lwq0/r;Ljava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwq0/i0;->a:Lkf0/e;

    .line 5
    .line 6
    iput-object p2, p0, Lwq0/i0;->b:Lwq0/g0;

    .line 7
    .line 8
    iput-object p3, p0, Lwq0/i0;->c:Ltq0/k;

    .line 9
    .line 10
    iput-object p4, p0, Lwq0/i0;->d:Lwq0/r;

    .line 11
    .line 12
    iput-object p5, p0, Lwq0/i0;->e:Ljava/util/ArrayList;

    .line 13
    .line 14
    return-void
.end method

.method public static final a(Lwq0/i0;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lwq0/h0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lwq0/h0;

    .line 7
    .line 8
    iget v1, v0, Lwq0/h0;->i:I

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
    iput v1, v0, Lwq0/h0;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwq0/h0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lwq0/h0;-><init>(Lwq0/i0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lwq0/h0;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwq0/h0;->i:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    iget v2, v0, Lwq0/h0;->f:I

    .line 42
    .line 43
    iget v5, v0, Lwq0/h0;->e:I

    .line 44
    .line 45
    iget-object v6, v0, Lwq0/h0;->d:Ljava/util/Iterator;

    .line 46
    .line 47
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    .line 50
    goto :goto_2

    .line 51
    :catchall_0
    move-exception p1

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iget-object p1, p0, Lwq0/i0;->a:Lkf0/e;

    .line 69
    .line 70
    invoke-virtual {p1}, Lkf0/e;->invoke()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    check-cast p1, Lyy0/i;

    .line 75
    .line 76
    new-instance v2, Ls90/a;

    .line 77
    .line 78
    const/16 v6, 0x19

    .line 79
    .line 80
    invoke-direct {v2, p0, v6}, Ls90/a;-><init>(Ljava/lang/Object;I)V

    .line 81
    .line 82
    .line 83
    iput v5, v0, Lwq0/h0;->i:I

    .line 84
    .line 85
    invoke-interface {p1, v2, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    if-ne p1, v1, :cond_4

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_4
    :goto_1
    :try_start_1
    iget-object p1, p0, Lwq0/i0;->e:Ljava/util/ArrayList;

    .line 93
    .line 94
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    const/4 v2, 0x0

    .line 99
    move-object v6, p1

    .line 100
    move v5, v2

    .line 101
    :cond_5
    :goto_2
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 102
    .line 103
    .line 104
    move-result p1

    .line 105
    if-eqz p1, :cond_6

    .line 106
    .line 107
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    check-cast p1, Lme0/b;

    .line 112
    .line 113
    iput-object v6, v0, Lwq0/h0;->d:Ljava/util/Iterator;

    .line 114
    .line 115
    iput v5, v0, Lwq0/h0;->e:I

    .line 116
    .line 117
    iput v2, v0, Lwq0/h0;->f:I

    .line 118
    .line 119
    iput v4, v0, Lwq0/h0;->i:I

    .line 120
    .line 121
    invoke-interface {p1, v0}, Lme0/b;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 125
    if-ne p1, v1, :cond_5

    .line 126
    .line 127
    :goto_3
    return-object v1

    .line 128
    :cond_6
    move-object p1, v3

    .line 129
    goto :goto_5

    .line 130
    :goto_4
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    :goto_5
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    if-eqz p1, :cond_7

    .line 139
    .line 140
    new-instance v0, Lbp0/e;

    .line 141
    .line 142
    const/16 v1, 0xb

    .line 143
    .line 144
    invoke-direct {v0, p1, v1}, Lbp0/e;-><init>(Ljava/lang/Throwable;I)V

    .line 145
    .line 146
    .line 147
    invoke-static {p0, v0}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 148
    .line 149
    .line 150
    :cond_7
    return-object v3
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lwq0/i0;->d:Lwq0/r;

    .line 2
    .line 3
    check-cast v0, Ltq0/a;

    .line 4
    .line 5
    iget-object v0, v0, Ltq0/a;->c:Ljava/lang/String;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object v1, p0, Lwq0/i0;->c:Ltq0/k;

    .line 10
    .line 11
    iget-object v2, v1, Ltq0/k;->a:Lxl0/f;

    .line 12
    .line 13
    new-instance v3, Ltq0/j;

    .line 14
    .line 15
    const/4 v4, 0x0

    .line 16
    const/4 v5, 0x0

    .line 17
    invoke-direct {v3, v1, v0, v5, v4}, Ltq0/j;-><init>(Ltq0/k;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v2, v3}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    new-instance v1, Lvo0/e;

    .line 25
    .line 26
    const/16 v2, 0x10

    .line 27
    .line 28
    invoke-direct {v1, p0, v5, v2}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v1, v0}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :cond_0
    new-instance v0, Lne0/c;

    .line 37
    .line 38
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 39
    .line 40
    const-string p0, "Spin cannot be null during reset spin update"

    .line 41
    .line 42
    invoke-direct {v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    const/4 v4, 0x0

    .line 46
    const/16 v5, 0x1e

    .line 47
    .line 48
    const/4 v2, 0x0

    .line 49
    const/4 v3, 0x0

    .line 50
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 51
    .line 52
    .line 53
    new-instance p0, Lyy0/m;

    .line 54
    .line 55
    const/4 v1, 0x0

    .line 56
    invoke-direct {p0, v0, v1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 57
    .line 58
    .line 59
    return-object p0
.end method
