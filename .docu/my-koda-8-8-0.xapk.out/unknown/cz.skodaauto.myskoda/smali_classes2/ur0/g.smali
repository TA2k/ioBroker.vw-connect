.class public final Lur0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lwr0/g;
.implements Lme0/a;


# instance fields
.field public final a:Lti0/a;

.field public final b:Lwe0/a;

.field public final c:Lez0/c;

.field public final d:Lal0/i;

.field public final e:Lyy0/m1;


# direct methods
.method public constructor <init>(Lti0/a;Lwe0/a;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lur0/g;->a:Lti0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lur0/g;->b:Lwe0/a;

    .line 7
    .line 8
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lur0/g;->c:Lez0/c;

    .line 13
    .line 14
    new-instance p1, Lur0/f;

    .line 15
    .line 16
    const/4 p2, 0x1

    .line 17
    const/4 v0, 0x0

    .line 18
    invoke-direct {p1, p0, v0, p2}, Lur0/f;-><init>(Lur0/g;Lkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    new-instance p2, Lyy0/m1;

    .line 22
    .line 23
    invoke-direct {p2, p1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 24
    .line 25
    .line 26
    new-instance p1, Lal0/i;

    .line 27
    .line 28
    const/16 v1, 0xc

    .line 29
    .line 30
    invoke-direct {p1, p2, v1}, Lal0/i;-><init>(Lyy0/m1;I)V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lur0/g;->d:Lal0/i;

    .line 34
    .line 35
    new-instance p1, Lur0/f;

    .line 36
    .line 37
    const/4 p2, 0x0

    .line 38
    invoke-direct {p1, p0, v0, p2}, Lur0/f;-><init>(Lur0/g;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    new-instance p2, Lyy0/m1;

    .line 42
    .line 43
    invoke-direct {p2, p1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 44
    .line 45
    .line 46
    iput-object p2, p0, Lur0/g;->e:Lyy0/m1;

    .line 47
    .line 48
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Lge0/b;->a:Lcz0/e;

    .line 2
    .line 3
    new-instance v1, Ltz/o2;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/16 v3, 0x11

    .line 7
    .line 8
    invoke-direct {v1, p0, v2, v3}, Ltz/o2;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 9
    .line 10
    .line 11
    invoke-static {v0, v1, p1}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    if-ne p0, p1, :cond_0

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Lge0/b;->a:Lcz0/e;

    .line 2
    .line 3
    new-instance v1, Lur0/c;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v1, p0, v2, v3}, Lur0/c;-><init>(Lur0/g;Lkotlin/coroutines/Continuation;I)V

    .line 8
    .line 9
    .line 10
    invoke-static {v0, v1, p1}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public final c(Lyr0/e;ZLrx0/c;)Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, Lge0/b;->a:Lcz0/e;

    .line 2
    .line 3
    new-instance v1, Lau0/b;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p0, p1, p2, v2}, Lau0/b;-><init>(Lur0/g;Lyr0/e;ZLkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    invoke-static {v0, v1, p3}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    if-ne p0, p1, :cond_0

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    return-object p0
.end method

.method public final d(Lyr0/c;Lrx0/c;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Lur0/e;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lur0/e;

    .line 11
    .line 12
    iget v3, v2, Lur0/e;->g:I

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
    iput v3, v2, Lur0/e;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lur0/e;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lur0/e;-><init>(Lur0/g;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lur0/e;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lur0/e;->g:I

    .line 34
    .line 35
    const/4 v5, 0x2

    .line 36
    const/4 v6, 0x1

    .line 37
    if-eqz v4, :cond_3

    .line 38
    .line 39
    if-eq v4, v6, :cond_2

    .line 40
    .line 41
    if-ne v4, v5, :cond_1

    .line 42
    .line 43
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_3

    .line 47
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw v0

    .line 55
    :cond_2
    iget-object v4, v2, Lur0/e;->d:Lyr0/c;

    .line 56
    .line 57
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    move-object/from16 v18, v4

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    move-object/from16 v1, p1

    .line 67
    .line 68
    iput-object v1, v2, Lur0/e;->d:Lyr0/c;

    .line 69
    .line 70
    iput v6, v2, Lur0/e;->g:I

    .line 71
    .line 72
    invoke-virtual {v0, v2}, Lur0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    if-ne v4, v3, :cond_4

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_4
    move-object/from16 v18, v1

    .line 80
    .line 81
    move-object v1, v4

    .line 82
    :goto_1
    check-cast v1, Lyr0/e;

    .line 83
    .line 84
    if-eqz v1, :cond_5

    .line 85
    .line 86
    iget-object v7, v1, Lyr0/e;->a:Ljava/lang/String;

    .line 87
    .line 88
    iget-object v8, v1, Lyr0/e;->b:Ljava/lang/String;

    .line 89
    .line 90
    iget-object v9, v1, Lyr0/e;->c:Ljava/lang/String;

    .line 91
    .line 92
    iget-object v10, v1, Lyr0/e;->d:Ljava/lang/String;

    .line 93
    .line 94
    iget-object v11, v1, Lyr0/e;->e:Ljava/lang/String;

    .line 95
    .line 96
    iget-object v12, v1, Lyr0/e;->f:Ljava/lang/String;

    .line 97
    .line 98
    iget-object v13, v1, Lyr0/e;->g:Ljava/lang/String;

    .line 99
    .line 100
    iget-object v14, v1, Lyr0/e;->h:Ljava/lang/String;

    .line 101
    .line 102
    iget-object v15, v1, Lyr0/e;->i:Ljava/time/LocalDate;

    .line 103
    .line 104
    iget-object v4, v1, Lyr0/e;->j:Ljava/lang/String;

    .line 105
    .line 106
    iget-object v6, v1, Lyr0/e;->k:Lyr0/a;

    .line 107
    .line 108
    iget-object v5, v1, Lyr0/e;->m:Ljava/lang/String;

    .line 109
    .line 110
    iget-object v1, v1, Lyr0/e;->n:Ljava/util/List;

    .line 111
    .line 112
    move-object/from16 v16, v4

    .line 113
    .line 114
    const-string v4, "id"

    .line 115
    .line 116
    invoke-static {v7, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    const-string v4, "email"

    .line 120
    .line 121
    invoke-static {v8, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    const-string v4, "capabilities"

    .line 125
    .line 126
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    move-object/from16 v17, v6

    .line 130
    .line 131
    new-instance v6, Lyr0/e;

    .line 132
    .line 133
    move-object/from16 v20, v1

    .line 134
    .line 135
    move-object/from16 v19, v5

    .line 136
    .line 137
    invoke-direct/range {v6 .. v20}, Lyr0/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Ljava/lang/String;Lyr0/a;Lyr0/c;Ljava/lang/String;Ljava/util/List;)V

    .line 138
    .line 139
    .line 140
    const/4 v1, 0x0

    .line 141
    iput-object v1, v2, Lur0/e;->d:Lyr0/c;

    .line 142
    .line 143
    const/4 v1, 0x2

    .line 144
    iput v1, v2, Lur0/e;->g:I

    .line 145
    .line 146
    const/4 v1, 0x0

    .line 147
    invoke-virtual {v0, v6, v1, v2}, Lur0/g;->c(Lyr0/e;ZLrx0/c;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    if-ne v0, v3, :cond_5

    .line 152
    .line 153
    :goto_2
    return-object v3

    .line 154
    :cond_5
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 155
    .line 156
    return-object v0
.end method
