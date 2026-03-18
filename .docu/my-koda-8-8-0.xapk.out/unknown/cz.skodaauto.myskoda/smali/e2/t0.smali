.class public final Le2/t0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public final synthetic e:Le2/o;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:J

.field public final synthetic h:Lg4/o0;

.field public final synthetic i:Le2/w0;

.field public final synthetic j:Ll4/p;


# direct methods
.method public constructor <init>(Le2/o;Ljava/lang/String;JLg4/o0;Le2/w0;Ll4/p;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Le2/t0;->e:Le2/o;

    .line 2
    .line 3
    iput-object p2, p0, Le2/t0;->f:Ljava/lang/String;

    .line 4
    .line 5
    iput-wide p3, p0, Le2/t0;->g:J

    .line 6
    .line 7
    iput-object p5, p0, Le2/t0;->h:Lg4/o0;

    .line 8
    .line 9
    iput-object p6, p0, Le2/t0;->i:Le2/w0;

    .line 10
    .line 11
    iput-object p7, p0, Le2/t0;->j:Ll4/p;

    .line 12
    .line 13
    const/4 p1, 0x2

    .line 14
    invoke-direct {p0, p1, p8}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 9

    .line 1
    new-instance v0, Le2/t0;

    .line 2
    .line 3
    iget-object v6, p0, Le2/t0;->i:Le2/w0;

    .line 4
    .line 5
    iget-object v7, p0, Le2/t0;->j:Ll4/p;

    .line 6
    .line 7
    iget-object v1, p0, Le2/t0;->e:Le2/o;

    .line 8
    .line 9
    iget-object v2, p0, Le2/t0;->f:Ljava/lang/String;

    .line 10
    .line 11
    iget-wide v3, p0, Le2/t0;->g:J

    .line 12
    .line 13
    iget-object v5, p0, Le2/t0;->h:Lg4/o0;

    .line 14
    .line 15
    move-object v8, p2

    .line 16
    invoke-direct/range {v0 .. v8}, Le2/t0;-><init>(Le2/o;Ljava/lang/String;JLg4/o0;Le2/w0;Ll4/p;Lkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Le2/t0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Le2/t0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Le2/t0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Le2/t0;->d:I

    .line 4
    .line 5
    iget-object v3, p0, Le2/t0;->f:Ljava/lang/String;

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    if-ne v1, v2, :cond_0

    .line 11
    .line 12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    goto :goto_2

    .line 16
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 17
    .line 18
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    iput v2, p0, Le2/t0;->d:I

    .line 28
    .line 29
    iget-object v6, p0, Le2/t0;->e:Le2/o;

    .line 30
    .line 31
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    const/4 v1, 0x0

    .line 39
    if-nez p1, :cond_2

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    iget-wide v4, p0, Le2/t0;->g:J

    .line 43
    .line 44
    invoke-static {v4, v5}, Lg4/o0;->c(J)Z

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    if-eqz p1, :cond_3

    .line 49
    .line 50
    :goto_0
    move-object p1, v1

    .line 51
    goto :goto_1

    .line 52
    :cond_3
    new-instance v2, Le2/n;

    .line 53
    .line 54
    const/4 v7, 0x0

    .line 55
    invoke-direct/range {v2 .. v7}, Le2/n;-><init>(Ljava/lang/CharSequence;JLe2/o;Lkotlin/coroutines/Continuation;)V

    .line 56
    .line 57
    .line 58
    iget-object p1, v6, Le2/o;->a:Lpx0/g;

    .line 59
    .line 60
    new-instance v4, La7/k;

    .line 61
    .line 62
    invoke-direct {v4, v6, v2, v1}, La7/k;-><init>(Le2/o;Lay0/n;Lkotlin/coroutines/Continuation;)V

    .line 63
    .line 64
    .line 65
    invoke-static {p1, v4, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    :goto_1
    if-ne p1, v0, :cond_4

    .line 70
    .line 71
    return-object v0

    .line 72
    :cond_4
    :goto_2
    check-cast p1, Lg4/o0;

    .line 73
    .line 74
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 75
    .line 76
    if-eqz p1, :cond_5

    .line 77
    .line 78
    iget-wide v1, p1, Lg4/o0;->a:J

    .line 79
    .line 80
    const/16 p1, 0x20

    .line 81
    .line 82
    shr-long v4, v1, p1

    .line 83
    .line 84
    long-to-int p1, v4

    .line 85
    iget-object v4, p0, Le2/t0;->j:Ll4/p;

    .line 86
    .line 87
    invoke-interface {v4, p1}, Ll4/p;->E(I)I

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    const-wide v5, 0xffffffffL

    .line 92
    .line 93
    .line 94
    .line 95
    .line 96
    and-long/2addr v1, v5

    .line 97
    long-to-int v1, v1

    .line 98
    invoke-interface {v4, v1}, Ll4/p;->E(I)I

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    invoke-static {p1, v1}, Lg4/f0;->b(II)J

    .line 103
    .line 104
    .line 105
    move-result-wide v1

    .line 106
    iget-object p1, p0, Le2/t0;->h:Lg4/o0;

    .line 107
    .line 108
    invoke-static {v1, v2, p1}, Lg4/o0;->a(JLjava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result p1

    .line 112
    if-nez p1, :cond_5

    .line 113
    .line 114
    iget-object p0, p0, Le2/t0;->i:Le2/w0;

    .line 115
    .line 116
    invoke-virtual {p0}, Le2/w0;->m()Ll4/v;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    iget-object p1, p1, Ll4/v;->a:Lg4/g;

    .line 121
    .line 122
    iget-object p1, p1, Lg4/g;->e:Ljava/lang/String;

    .line 123
    .line 124
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result p1

    .line 128
    if-eqz p1, :cond_5

    .line 129
    .line 130
    iget-object p1, p0, Le2/w0;->b:Ll4/p;

    .line 131
    .line 132
    if-ne v4, p1, :cond_5

    .line 133
    .line 134
    iget-object p1, p0, Le2/w0;->c:Lay0/k;

    .line 135
    .line 136
    invoke-virtual {p0}, Le2/w0;->m()Ll4/v;

    .line 137
    .line 138
    .line 139
    move-result-object v3

    .line 140
    iget-object v3, v3, Ll4/v;->a:Lg4/g;

    .line 141
    .line 142
    invoke-static {v3, v1, v2}, Le2/w0;->e(Lg4/g;J)Ll4/v;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    invoke-interface {p1, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    new-instance p1, Lg4/o0;

    .line 150
    .line 151
    invoke-direct {p1, v1, v2}, Lg4/o0;-><init>(J)V

    .line 152
    .line 153
    .line 154
    iput-object p1, p0, Le2/w0;->v:Lg4/o0;

    .line 155
    .line 156
    :cond_5
    return-object v0
.end method
