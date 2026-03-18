.class public final Li20/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lsg0/a;

.field public final b:Li20/s;

.field public final c:Ltr0/b;

.field public final d:Lug0/c;


# direct methods
.method public constructor <init>(Lsg0/a;Li20/s;Ltr0/b;Lug0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li20/r;->a:Lsg0/a;

    .line 5
    .line 6
    iput-object p2, p0, Li20/r;->b:Li20/s;

    .line 7
    .line 8
    iput-object p3, p0, Li20/r;->c:Ltr0/b;

    .line 9
    .line 10
    iput-object p4, p0, Li20/r;->d:Lug0/c;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Li20/r;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Li20/p;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Li20/p;

    .line 7
    .line 8
    iget v1, v0, Li20/p;->f:I

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
    iput v1, v0, Li20/p;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li20/p;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Li20/p;-><init>(Li20/r;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Li20/p;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Li20/p;->f:I

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
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :catch_0
    move-exception v0

    .line 41
    move-object p1, v0

    .line 42
    move-object v1, p1

    .line 43
    goto :goto_2

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    :try_start_1
    iput v3, v0, Li20/p;->f:I

    .line 56
    .line 57
    invoke-virtual {p0, v0}, Li20/r;->c(Lrx0/c;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-ne p1, v1, :cond_3

    .line 62
    .line 63
    return-object v1

    .line 64
    :cond_3
    :goto_1
    check-cast p1, Lne0/t;
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0

    .line 65
    .line 66
    iget-object p0, p0, Li20/r;->d:Lug0/c;

    .line 67
    .line 68
    invoke-virtual {p0, p1}, Lug0/c;->a(Lne0/t;)V

    .line 69
    .line 70
    .line 71
    return-object p1

    .line 72
    :goto_2
    new-instance v0, Lne0/c;

    .line 73
    .line 74
    const/4 v4, 0x0

    .line 75
    const/16 v5, 0x1e

    .line 76
    .line 77
    const/4 v2, 0x0

    .line 78
    const/4 v3, 0x0

    .line 79
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 80
    .line 81
    .line 82
    new-instance p1, La60/a;

    .line 83
    .line 84
    const/4 v1, 0x1

    .line 85
    invoke-direct {p1, v0, v1}, La60/a;-><init>(Lne0/c;I)V

    .line 86
    .line 87
    .line 88
    invoke-static {p0, p1}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 89
    .line 90
    .line 91
    return-object v0
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Li20/q;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Li20/q;

    .line 7
    .line 8
    iget v1, v0, Li20/q;->f:I

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
    iput v1, v0, Li20/q;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li20/q;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Li20/q;-><init>(Li20/r;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Li20/q;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Li20/q;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_2

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
    iget-object p1, p0, Li20/r;->a:Lsg0/a;

    .line 54
    .line 55
    iget-object p1, p1, Lsg0/a;->b:Lss0/n;

    .line 56
    .line 57
    const/4 v2, -0x1

    .line 58
    if-nez p1, :cond_3

    .line 59
    .line 60
    move v5, v2

    .line 61
    goto :goto_1

    .line 62
    :cond_3
    sget-object v5, Lj20/b;->a:[I

    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 65
    .line 66
    .line 67
    move-result v6

    .line 68
    aget v5, v5, v6

    .line 69
    .line 70
    :goto_1
    if-eq v5, v2, :cond_8

    .line 71
    .line 72
    if-eq v5, v4, :cond_4

    .line 73
    .line 74
    const/4 v2, 0x2

    .line 75
    if-eq v5, v2, :cond_4

    .line 76
    .line 77
    const/4 v2, 0x3

    .line 78
    if-eq v5, v2, :cond_4

    .line 79
    .line 80
    const/4 v2, 0x4

    .line 81
    if-eq v5, v2, :cond_4

    .line 82
    .line 83
    const/4 p0, 0x5

    .line 84
    if-eq v5, p0, :cond_8

    .line 85
    .line 86
    new-instance p0, La8/r0;

    .line 87
    .line 88
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 89
    .line 90
    .line 91
    throw p0

    .line 92
    :cond_4
    sget-object p1, Lj20/a;->d:[Lj20/a;

    .line 93
    .line 94
    sget-object p1, Li20/o;->a:[I

    .line 95
    .line 96
    const/4 v2, 0x0

    .line 97
    aget p1, p1, v2

    .line 98
    .line 99
    if-ne p1, v4, :cond_7

    .line 100
    .line 101
    iput v4, v0, Li20/q;->f:I

    .line 102
    .line 103
    iget-object p1, p0, Li20/r;->b:Li20/s;

    .line 104
    .line 105
    invoke-virtual {p1, v3, v0}, Li20/s;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    if-ne p1, v1, :cond_5

    .line 110
    .line 111
    return-object v1

    .line 112
    :cond_5
    :goto_2
    check-cast p1, Lne0/t;

    .line 113
    .line 114
    instance-of v0, p1, Lne0/c;

    .line 115
    .line 116
    if-eqz v0, :cond_6

    .line 117
    .line 118
    check-cast p1, Lne0/c;

    .line 119
    .line 120
    return-object p1

    .line 121
    :cond_6
    iget-object p0, p0, Li20/r;->c:Ltr0/b;

    .line 122
    .line 123
    invoke-virtual {p0}, Ltr0/b;->invoke()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    new-instance p0, Lne0/e;

    .line 127
    .line 128
    invoke-direct {p0, v3}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    return-object p0

    .line 132
    :cond_7
    new-instance p0, La8/r0;

    .line 133
    .line 134
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 135
    .line 136
    .line 137
    throw p0

    .line 138
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 139
    .line 140
    new-instance v0, Ljava/lang/StringBuilder;

    .line 141
    .line 142
    const-string v1, "DevicePlatform is "

    .line 143
    .line 144
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 148
    .line 149
    .line 150
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    throw p0
.end method
