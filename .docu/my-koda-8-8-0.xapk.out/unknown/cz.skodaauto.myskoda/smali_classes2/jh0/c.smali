.class public final Ljh0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llh0/f;


# instance fields
.field public final a:Lnh0/b;

.field public final b:Lyy0/c2;

.field public final c:Lyy0/l1;


# direct methods
.method public constructor <init>(Lnh0/b;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljh0/c;->a:Lnh0/b;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iput-object p1, p0, Ljh0/c;->b:Lyy0/c2;

    .line 12
    .line 13
    new-instance v0, Lyy0/l1;

    .line 14
    .line 15
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Ljh0/c;->c:Lyy0/l1;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Ljh0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ljh0/a;

    .line 7
    .line 8
    iget v1, v0, Ljh0/a;->f:I

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
    iput v1, v0, Ljh0/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ljh0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ljh0/a;-><init>(Ljh0/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ljh0/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ljh0/a;->f:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v4, :cond_1

    .line 36
    .line 37
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iput v4, v0, Ljh0/a;->f:I

    .line 53
    .line 54
    invoke-virtual {p1}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    iget-object p2, p0, Ljh0/c;->a:Lnh0/b;

    .line 59
    .line 60
    sget-object v2, Lge0/b;->c:Lcz0/d;

    .line 61
    .line 62
    new-instance v4, Laa/s;

    .line 63
    .line 64
    const/16 v5, 0x18

    .line 65
    .line 66
    invoke-direct {v4, v5, p2, p1, v3}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 67
    .line 68
    .line 69
    invoke-static {v2, v4, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    if-ne p2, v1, :cond_3

    .line 74
    .line 75
    return-object v1

    .line 76
    :cond_3
    :goto_1
    check-cast p2, [B

    .line 77
    .line 78
    if-eqz p2, :cond_5

    .line 79
    .line 80
    iget-object p0, p0, Ljh0/c;->b:Lyy0/c2;

    .line 81
    .line 82
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    check-cast p1, Ljava/util/List;

    .line 87
    .line 88
    if-nez p1, :cond_4

    .line 89
    .line 90
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 91
    .line 92
    :cond_4
    check-cast p1, Ljava/util/Collection;

    .line 93
    .line 94
    invoke-static {p1, p2}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 99
    .line 100
    .line 101
    invoke-virtual {p0, v3, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    :cond_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 105
    .line 106
    return-object p0
.end method

.method public final b(Ljava/util/List;Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p2, Ljh0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ljh0/b;

    .line 7
    .line 8
    iget v1, v0, Ljh0/b;->l:I

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
    iput v1, v0, Ljh0/b;->l:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ljh0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ljh0/b;-><init>(Ljh0/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ljh0/b;->j:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ljh0/b;->l:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    iget p1, v0, Ljh0/b;->i:I

    .line 38
    .line 39
    iget v2, v0, Ljh0/b;->h:I

    .line 40
    .line 41
    iget v5, v0, Ljh0/b;->g:I

    .line 42
    .line 43
    iget-object v6, v0, Ljh0/b;->f:Lyy0/j1;

    .line 44
    .line 45
    iget-object v7, v0, Ljh0/b;->e:Ljava/util/Iterator;

    .line 46
    .line 47
    iget-object v8, v0, Ljh0/b;->d:Ljava/util/Collection;

    .line 48
    .line 49
    check-cast v8, Ljava/util/Collection;

    .line 50
    .line 51
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_2

    .line 55
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 56
    .line 57
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0

    .line 63
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object p2, p0, Ljh0/c;->b:Lyy0/c2;

    .line 67
    .line 68
    if-eqz p1, :cond_6

    .line 69
    .line 70
    check-cast p1, Ljava/lang/Iterable;

    .line 71
    .line 72
    new-instance v2, Ljava/util/ArrayList;

    .line 73
    .line 74
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 75
    .line 76
    .line 77
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    const/4 v5, 0x0

    .line 82
    move-object v7, p1

    .line 83
    move-object v6, p2

    .line 84
    move-object v8, v2

    .line 85
    move p1, v5

    .line 86
    move v2, p1

    .line 87
    :cond_3
    :goto_1
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 88
    .line 89
    .line 90
    move-result p2

    .line 91
    if-eqz p2, :cond_5

    .line 92
    .line 93
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    check-cast p2, Ljava/lang/String;

    .line 98
    .line 99
    move-object v9, v8

    .line 100
    check-cast v9, Ljava/util/Collection;

    .line 101
    .line 102
    iput-object v9, v0, Ljh0/b;->d:Ljava/util/Collection;

    .line 103
    .line 104
    iput-object v7, v0, Ljh0/b;->e:Ljava/util/Iterator;

    .line 105
    .line 106
    iput-object v6, v0, Ljh0/b;->f:Lyy0/j1;

    .line 107
    .line 108
    iput v5, v0, Ljh0/b;->g:I

    .line 109
    .line 110
    iput v2, v0, Ljh0/b;->h:I

    .line 111
    .line 112
    iput p1, v0, Ljh0/b;->i:I

    .line 113
    .line 114
    iput v3, v0, Ljh0/b;->l:I

    .line 115
    .line 116
    invoke-virtual {p2}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p2

    .line 120
    iget-object v9, p0, Ljh0/c;->a:Lnh0/b;

    .line 121
    .line 122
    sget-object v10, Lge0/b;->c:Lcz0/d;

    .line 123
    .line 124
    new-instance v11, Laa/s;

    .line 125
    .line 126
    const/16 v12, 0x18

    .line 127
    .line 128
    invoke-direct {v11, v12, v9, p2, v4}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 129
    .line 130
    .line 131
    invoke-static {v10, v11, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p2

    .line 135
    if-ne p2, v1, :cond_4

    .line 136
    .line 137
    return-object v1

    .line 138
    :cond_4
    :goto_2
    check-cast p2, [B

    .line 139
    .line 140
    if-eqz p2, :cond_3

    .line 141
    .line 142
    invoke-interface {v8, p2}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_5
    check-cast v8, Ljava/util/List;

    .line 147
    .line 148
    check-cast v6, Lyy0/c2;

    .line 149
    .line 150
    invoke-virtual {v6, v8}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    goto :goto_3

    .line 154
    :cond_6
    invoke-virtual {p2, v4}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 158
    .line 159
    return-object p0
.end method
