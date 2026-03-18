.class public final Lrq0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lrq0/f;

.field public final b:Ljn0/c;


# direct methods
.method public constructor <init>(Lrq0/f;Ljn0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrq0/d;->a:Lrq0/f;

    .line 5
    .line 6
    iput-object p2, p0, Lrq0/d;->b:Ljn0/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lsq0/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lrq0/d;->b(Lsq0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lsq0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p2, Lrq0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lrq0/b;

    .line 7
    .line 8
    iget v1, v0, Lrq0/b;->h:I

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
    iput v1, v0, Lrq0/b;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lrq0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lrq0/b;-><init>(Lrq0/d;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lrq0/b;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lrq0/b;->h:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v5, :cond_2

    .line 37
    .line 38
    if-ne v2, v4, :cond_1

    .line 39
    .line 40
    iget-object p0, v0, Lrq0/b;->e:Ljava/lang/Object;

    .line 41
    .line 42
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-object p0

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    iget-object p1, v0, Lrq0/b;->d:Lsq0/b;

    .line 55
    .line 56
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_3

    .line 60
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    new-instance v6, Lsq0/c;

    .line 64
    .line 65
    iget-object v7, p1, Lsq0/b;->b:Ljava/lang/String;

    .line 66
    .line 67
    if-nez v7, :cond_7

    .line 68
    .line 69
    iget-object p2, p1, Lsq0/b;->a:Lne0/c;

    .line 70
    .line 71
    iget-object p2, p2, Lne0/c;->e:Lne0/b;

    .line 72
    .line 73
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 74
    .line 75
    .line 76
    move-result p2

    .line 77
    if-eqz p2, :cond_6

    .line 78
    .line 79
    if-eq p2, v5, :cond_5

    .line 80
    .line 81
    if-ne p2, v4, :cond_4

    .line 82
    .line 83
    const p2, 0x7f1202c4

    .line 84
    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_4
    new-instance p0, La8/r0;

    .line 88
    .line 89
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_5
    const p2, 0x7f1202ca

    .line 94
    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_6
    const p2, 0x7f1202bf

    .line 98
    .line 99
    .line 100
    :goto_1
    new-instance v2, Ljava/lang/Integer;

    .line 101
    .line 102
    invoke-direct {v2, p2}, Ljava/lang/Integer;-><init>(I)V

    .line 103
    .line 104
    .line 105
    move-object v8, v2

    .line 106
    goto :goto_2

    .line 107
    :cond_7
    move-object v8, v3

    .line 108
    :goto_2
    new-instance v10, Ljava/lang/Integer;

    .line 109
    .line 110
    const p2, 0x7f1202c7

    .line 111
    .line 112
    .line 113
    invoke-direct {v10, p2}, Ljava/lang/Integer;-><init>(I)V

    .line 114
    .line 115
    .line 116
    const/4 v9, 0x0

    .line 117
    const/4 v11, 0x0

    .line 118
    invoke-direct/range {v6 .. v11}, Lsq0/c;-><init>(Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    iput-object p1, v0, Lrq0/b;->d:Lsq0/b;

    .line 122
    .line 123
    iput v5, v0, Lrq0/b;->h:I

    .line 124
    .line 125
    iget-object p2, p0, Lrq0/d;->a:Lrq0/f;

    .line 126
    .line 127
    const/4 v2, 0x0

    .line 128
    invoke-virtual {p2, v6, v2, v0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 129
    .line 130
    .line 131
    move-result-object p2

    .line 132
    if-ne p2, v1, :cond_8

    .line 133
    .line 134
    goto :goto_4

    .line 135
    :cond_8
    :goto_3
    move-object v2, p2

    .line 136
    check-cast v2, Lsq0/d;

    .line 137
    .line 138
    sget-object v5, Lsq0/d;->d:Lsq0/d;

    .line 139
    .line 140
    if-ne v2, v5, :cond_9

    .line 141
    .line 142
    iput-object v3, v0, Lrq0/b;->d:Lsq0/b;

    .line 143
    .line 144
    iput-object p2, v0, Lrq0/b;->e:Ljava/lang/Object;

    .line 145
    .line 146
    iput v4, v0, Lrq0/b;->h:I

    .line 147
    .line 148
    invoke-virtual {p0, p1, v0}, Lrq0/d;->c(Lsq0/b;Lrx0/c;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    if-ne p0, v1, :cond_9

    .line 153
    .line 154
    :goto_4
    return-object v1

    .line 155
    :cond_9
    return-object p2
.end method

.method public final c(Lsq0/b;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lrq0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lrq0/c;

    .line 7
    .line 8
    iget v1, v0, Lrq0/c;->f:I

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
    iput v1, v0, Lrq0/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lrq0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lrq0/c;-><init>(Lrq0/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lrq0/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lrq0/c;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v3

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    return-object v3

    .line 57
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p2, p1, Lsq0/b;->c:Lsq0/a;

    .line 61
    .line 62
    iget-object p1, p1, Lsq0/b;->a:Lne0/c;

    .line 63
    .line 64
    iget-object p0, p0, Lrq0/d;->b:Ljn0/c;

    .line 65
    .line 66
    if-eqz p2, :cond_4

    .line 67
    .line 68
    iget-object v2, p2, Lsq0/a;->a:Ljava/lang/String;

    .line 69
    .line 70
    iget-object v4, p2, Lsq0/a;->b:Ljava/lang/String;

    .line 71
    .line 72
    iget-object p2, p2, Lsq0/a;->c:Ljava/lang/String;

    .line 73
    .line 74
    new-instance v6, Lkn0/c;

    .line 75
    .line 76
    invoke-direct {v6, v2, v4, p2, p1}, Lkn0/c;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lne0/c;)V

    .line 77
    .line 78
    .line 79
    iput v5, v0, Lrq0/c;->f:I

    .line 80
    .line 81
    invoke-virtual {p0, v6, v0}, Ljn0/c;->b(Lkn0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    if-ne p0, v1, :cond_5

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_4
    iput v4, v0, Lrq0/c;->f:I

    .line 89
    .line 90
    invoke-virtual {p0, p1, v0}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    if-ne p0, v1, :cond_5

    .line 95
    .line 96
    :goto_1
    return-object v1

    .line 97
    :cond_5
    return-object v3
.end method
