.class public final Lh7/s;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:La7/n;

.field public final synthetic g:Ll2/y1;

.field public final synthetic h:Lkotlin/jvm/internal/e0;

.field public final synthetic i:Lyy0/c2;

.field public final synthetic j:Landroid/content/Context;

.field public final synthetic k:La7/q1;

.field public final synthetic l:Lh7/a0;

.field public final synthetic m:Lh7/x;

.field public final synthetic n:Lvy0/b0;


# direct methods
.method public constructor <init>(La7/n;Ll2/y1;Lkotlin/jvm/internal/e0;Lyy0/c2;Landroid/content/Context;La7/q1;Lh7/a0;Lh7/x;Lvy0/b0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh7/s;->f:La7/n;

    .line 2
    .line 3
    iput-object p2, p0, Lh7/s;->g:Ll2/y1;

    .line 4
    .line 5
    iput-object p3, p0, Lh7/s;->h:Lkotlin/jvm/internal/e0;

    .line 6
    .line 7
    iput-object p4, p0, Lh7/s;->i:Lyy0/c2;

    .line 8
    .line 9
    iput-object p5, p0, Lh7/s;->j:Landroid/content/Context;

    .line 10
    .line 11
    iput-object p6, p0, Lh7/s;->k:La7/q1;

    .line 12
    .line 13
    iput-object p7, p0, Lh7/s;->l:Lh7/a0;

    .line 14
    .line 15
    iput-object p8, p0, Lh7/s;->m:Lh7/x;

    .line 16
    .line 17
    iput-object p9, p0, Lh7/s;->n:Lvy0/b0;

    .line 18
    .line 19
    const/4 p1, 0x2

    .line 20
    invoke-direct {p0, p1, p10}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 11

    .line 1
    new-instance v0, Lh7/s;

    .line 2
    .line 3
    iget-object v8, p0, Lh7/s;->m:Lh7/x;

    .line 4
    .line 5
    iget-object v9, p0, Lh7/s;->n:Lvy0/b0;

    .line 6
    .line 7
    iget-object v1, p0, Lh7/s;->f:La7/n;

    .line 8
    .line 9
    iget-object v2, p0, Lh7/s;->g:Ll2/y1;

    .line 10
    .line 11
    iget-object v3, p0, Lh7/s;->h:Lkotlin/jvm/internal/e0;

    .line 12
    .line 13
    iget-object v4, p0, Lh7/s;->i:Lyy0/c2;

    .line 14
    .line 15
    iget-object v5, p0, Lh7/s;->j:Landroid/content/Context;

    .line 16
    .line 17
    iget-object v6, p0, Lh7/s;->k:La7/q1;

    .line 18
    .line 19
    iget-object v7, p0, Lh7/s;->l:Lh7/a0;

    .line 20
    .line 21
    move-object v10, p2

    .line 22
    invoke-direct/range {v0 .. v10}, Lh7/s;-><init>(La7/n;Ll2/y1;Lkotlin/jvm/internal/e0;Lyy0/c2;Landroid/content/Context;La7/q1;Lh7/a0;Lh7/x;Lvy0/b0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lh7/s;->e:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ll2/w1;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lh7/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lh7/s;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lh7/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lh7/s;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, p0, Lh7/s;->h:Lkotlin/jvm/internal/e0;

    .line 8
    .line 9
    iget-object v4, p0, Lh7/s;->g:Ll2/y1;

    .line 10
    .line 11
    const/4 v5, 0x2

    .line 12
    iget-object v6, p0, Lh7/s;->i:Lyy0/c2;

    .line 13
    .line 14
    const/4 v7, 0x1

    .line 15
    if-eqz v1, :cond_2

    .line 16
    .line 17
    if-eq v1, v7, :cond_1

    .line 18
    .line 19
    if-ne v1, v5, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto :goto_2

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    iget-object p1, p0, Lh7/s;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p1, Ll2/w1;

    .line 43
    .line 44
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    if-eqz p1, :cond_8

    .line 49
    .line 50
    const/4 v1, 0x4

    .line 51
    if-eq p1, v1, :cond_3

    .line 52
    .line 53
    return-object v2

    .line 54
    :cond_3
    iget-wide v8, v4, Ll2/y1;->a:J

    .line 55
    .line 56
    iget-wide v10, v3, Lkotlin/jvm/internal/e0;->d:J

    .line 57
    .line 58
    cmp-long p1, v8, v10

    .line 59
    .line 60
    if-gtz p1, :cond_4

    .line 61
    .line 62
    invoke-virtual {v6}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    check-cast p1, Ljava/lang/Boolean;

    .line 67
    .line 68
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    if-nez p1, :cond_7

    .line 73
    .line 74
    :cond_4
    iget-object p1, p0, Lh7/s;->k:La7/q1;

    .line 75
    .line 76
    invoke-virtual {p1}, La7/q1;->copy()Ly6/l;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    check-cast p1, Ly6/n;

    .line 81
    .line 82
    iput v7, p0, Lh7/s;->d:I

    .line 83
    .line 84
    iget-object v1, p0, Lh7/s;->f:La7/n;

    .line 85
    .line 86
    iget-object v7, p0, Lh7/s;->j:Landroid/content/Context;

    .line 87
    .line 88
    invoke-virtual {v1, v7, p1, p0}, La7/n;->b(Landroid/content/Context;Ly6/n;Lrx0/c;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    if-ne p1, v0, :cond_5

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :cond_5
    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    .line 96
    .line 97
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 98
    .line 99
    .line 100
    move-result p1

    .line 101
    invoke-virtual {v6}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    check-cast v1, Ljava/lang/Boolean;

    .line 106
    .line 107
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-nez v1, :cond_7

    .line 112
    .line 113
    if-eqz p1, :cond_7

    .line 114
    .line 115
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 116
    .line 117
    iput v5, p0, Lh7/s;->d:I

    .line 118
    .line 119
    invoke-virtual {v6, p1, p0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    if-ne v2, v0, :cond_6

    .line 123
    .line 124
    :goto_1
    return-object v0

    .line 125
    :cond_6
    :goto_2
    iget-object p1, p0, Lh7/s;->m:Lh7/x;

    .line 126
    .line 127
    iget-wide v0, p1, Lh7/x;->a:J

    .line 128
    .line 129
    iget-object p0, p0, Lh7/s;->l:Lh7/a0;

    .line 130
    .line 131
    invoke-virtual {p0, v0, v1}, Lh7/a0;->b(J)V

    .line 132
    .line 133
    .line 134
    :cond_7
    iget-wide p0, v4, Ll2/y1;->a:J

    .line 135
    .line 136
    iput-wide p0, v3, Lkotlin/jvm/internal/e0;->d:J

    .line 137
    .line 138
    return-object v2

    .line 139
    :cond_8
    iget-object p0, p0, Lh7/s;->n:Lvy0/b0;

    .line 140
    .line 141
    const/4 p1, 0x0

    .line 142
    invoke-static {p0, p1}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 143
    .line 144
    .line 145
    return-object v2
.end method
