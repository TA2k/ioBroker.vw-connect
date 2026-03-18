.class public final Lps0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lrs0/f;
.implements Lme0/a;


# instance fields
.field public final a:Lve0/u;

.field public final b:Lyy0/c2;

.field public final c:Lyy0/i;


# direct methods
.method public constructor <init>(Lve0/u;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lps0/f;->a:Lve0/u;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lps0/f;->b:Lyy0/c2;

    .line 12
    .line 13
    new-instance v0, Lh7/z;

    .line 14
    .line 15
    const/16 v1, 0x13

    .line 16
    .line 17
    invoke-direct {v0, p0, p1, v1}, Lh7/z;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 18
    .line 19
    .line 20
    new-instance p1, Lyy0/m1;

    .line 21
    .line 22
    invoke-direct {p1, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 23
    .line 24
    .line 25
    invoke-static {p1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iput-object p1, p0, Lps0/f;->c:Lyy0/i;

    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lps0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lps0/d;

    .line 7
    .line 8
    iget v1, v0, Lps0/d;->f:I

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
    iput v1, v0, Lps0/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lps0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lps0/d;-><init>(Lps0/f;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lps0/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lps0/d;->f:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    iget-object p0, p0, Lps0/f;->a:Lve0/u;

    .line 35
    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    if-eq v2, v5, :cond_3

    .line 39
    .line 40
    if-eq v2, v4, :cond_2

    .line 41
    .line 42
    if-ne v2, v3, :cond_1

    .line 43
    .line 44
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_4

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iput v5, v0, Lps0/d;->f:I

    .line 68
    .line 69
    const-string p1, "VIN_KEY"

    .line 70
    .line 71
    invoke-virtual {p0, p1, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-ne p1, v1, :cond_5

    .line 76
    .line 77
    goto :goto_3

    .line 78
    :cond_5
    :goto_1
    iput v4, v0, Lps0/d;->f:I

    .line 79
    .line 80
    const-string p1, "COMMISSION_ID_KEY"

    .line 81
    .line 82
    invoke-virtual {p0, p1, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    if-ne p1, v1, :cond_6

    .line 87
    .line 88
    goto :goto_3

    .line 89
    :cond_6
    :goto_2
    iput v3, v0, Lps0/d;->f:I

    .line 90
    .line 91
    const-string p1, "ID_TYPE_KEY"

    .line 92
    .line 93
    invoke-virtual {p0, p1, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    if-ne p0, v1, :cond_7

    .line 98
    .line 99
    :goto_3
    return-object v1

    .line 100
    :cond_7
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 101
    .line 102
    return-object p0
.end method

.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lps0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lps0/c;

    .line 7
    .line 8
    iget v1, v0, Lps0/c;->f:I

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
    iput v1, v0, Lps0/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lps0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lps0/c;-><init>(Lps0/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lps0/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lps0/c;->f:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    iget-object v6, p0, Lps0/f;->a:Lve0/u;

    .line 35
    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    if-eq v2, v5, :cond_3

    .line 39
    .line 40
    if-eq v2, v4, :cond_2

    .line 41
    .line 42
    if-ne v2, v3, :cond_1

    .line 43
    .line 44
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_4

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iput v5, v0, Lps0/c;->f:I

    .line 68
    .line 69
    const-string p1, "VIN_KEY"

    .line 70
    .line 71
    invoke-virtual {v6, p1, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-ne p1, v1, :cond_5

    .line 76
    .line 77
    goto :goto_3

    .line 78
    :cond_5
    :goto_1
    iput v4, v0, Lps0/c;->f:I

    .line 79
    .line 80
    const-string p1, "COMMISSION_ID_KEY"

    .line 81
    .line 82
    invoke-virtual {v6, p1, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    if-ne p1, v1, :cond_6

    .line 87
    .line 88
    goto :goto_3

    .line 89
    :cond_6
    :goto_2
    iput v3, v0, Lps0/c;->f:I

    .line 90
    .line 91
    const-string p1, "ID_TYPE_KEY"

    .line 92
    .line 93
    invoke-virtual {v6, p1, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    if-ne p1, v1, :cond_7

    .line 98
    .line 99
    :goto_3
    return-object v1

    .line 100
    :cond_7
    :goto_4
    iget-object p0, p0, Lps0/f;->b:Lyy0/c2;

    .line 101
    .line 102
    const/4 p1, 0x0

    .line 103
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 107
    .line 108
    return-object p0
.end method

.method public final c(Lss0/d0;Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p2, Lps0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lps0/e;

    .line 7
    .line 8
    iget v1, v0, Lps0/e;->g:I

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
    iput v1, v0, Lps0/e;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lps0/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lps0/e;-><init>(Lps0/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lps0/e;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lps0/e;->g:I

    .line 30
    .line 31
    const-string v3, "ID_TYPE_KEY"

    .line 32
    .line 33
    const/4 v4, 0x4

    .line 34
    const/4 v5, 0x3

    .line 35
    const/4 v6, 0x2

    .line 36
    const/4 v7, 0x1

    .line 37
    iget-object v8, p0, Lps0/f;->a:Lve0/u;

    .line 38
    .line 39
    if-eqz v2, :cond_5

    .line 40
    .line 41
    if-eq v2, v7, :cond_4

    .line 42
    .line 43
    if-eq v2, v6, :cond_3

    .line 44
    .line 45
    if-eq v2, v5, :cond_2

    .line 46
    .line 47
    if-ne v2, v4, :cond_1

    .line 48
    .line 49
    iget-object p1, v0, Lps0/e;->d:Lss0/d0;

    .line 50
    .line 51
    check-cast p1, Lss0/d0;

    .line 52
    .line 53
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto/16 :goto_5

    .line 57
    .line 58
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 59
    .line 60
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 61
    .line 62
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p0

    .line 66
    :cond_2
    iget-object p1, v0, Lps0/e;->d:Lss0/d0;

    .line 67
    .line 68
    check-cast p1, Lss0/d0;

    .line 69
    .line 70
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto :goto_3

    .line 74
    :cond_3
    iget-object p1, v0, Lps0/e;->d:Lss0/d0;

    .line 75
    .line 76
    check-cast p1, Lss0/d0;

    .line 77
    .line 78
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_4
    iget-object p1, v0, Lps0/e;->d:Lss0/d0;

    .line 83
    .line 84
    check-cast p1, Lss0/d0;

    .line 85
    .line 86
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_5
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    instance-of p2, p1, Lss0/j0;

    .line 94
    .line 95
    if-eqz p2, :cond_7

    .line 96
    .line 97
    move-object p2, p1

    .line 98
    check-cast p2, Lss0/j0;

    .line 99
    .line 100
    iget-object p2, p2, Lss0/j0;->d:Ljava/lang/String;

    .line 101
    .line 102
    iput-object p1, v0, Lps0/e;->d:Lss0/d0;

    .line 103
    .line 104
    iput v7, v0, Lps0/e;->g:I

    .line 105
    .line 106
    const-string v2, "VIN_KEY"

    .line 107
    .line 108
    invoke-virtual {v8, v2, p2, v0}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p2

    .line 112
    if-ne p2, v1, :cond_6

    .line 113
    .line 114
    goto :goto_4

    .line 115
    :cond_6
    :goto_1
    move-object p2, p1

    .line 116
    check-cast p2, Lss0/d0;

    .line 117
    .line 118
    iput-object p2, v0, Lps0/e;->d:Lss0/d0;

    .line 119
    .line 120
    iput v6, v0, Lps0/e;->g:I

    .line 121
    .line 122
    const-string p2, "ID_TYPE_VIN"

    .line 123
    .line 124
    invoke-virtual {v8, v3, p2, v0}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object p2

    .line 128
    if-ne p2, v1, :cond_7

    .line 129
    .line 130
    goto :goto_4

    .line 131
    :cond_7
    :goto_2
    instance-of p2, p1, Lss0/g;

    .line 132
    .line 133
    if-eqz p2, :cond_9

    .line 134
    .line 135
    move-object p2, p1

    .line 136
    check-cast p2, Lss0/g;

    .line 137
    .line 138
    iget-object p2, p2, Lss0/g;->d:Ljava/lang/String;

    .line 139
    .line 140
    iput-object p1, v0, Lps0/e;->d:Lss0/d0;

    .line 141
    .line 142
    iput v5, v0, Lps0/e;->g:I

    .line 143
    .line 144
    const-string v2, "COMMISSION_ID_KEY"

    .line 145
    .line 146
    invoke-virtual {v8, v2, p2, v0}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object p2

    .line 150
    if-ne p2, v1, :cond_8

    .line 151
    .line 152
    goto :goto_4

    .line 153
    :cond_8
    :goto_3
    move-object p2, p1

    .line 154
    check-cast p2, Lss0/d0;

    .line 155
    .line 156
    iput-object p2, v0, Lps0/e;->d:Lss0/d0;

    .line 157
    .line 158
    iput v4, v0, Lps0/e;->g:I

    .line 159
    .line 160
    const-string p2, "ID_TYPE_COMMISSION_ID"

    .line 161
    .line 162
    invoke-virtual {v8, v3, p2, v0}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p2

    .line 166
    if-ne p2, v1, :cond_9

    .line 167
    .line 168
    :goto_4
    return-object v1

    .line 169
    :cond_9
    :goto_5
    iget-object p0, p0, Lps0/f;->b:Lyy0/c2;

    .line 170
    .line 171
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 175
    .line 176
    return-object p0
.end method
