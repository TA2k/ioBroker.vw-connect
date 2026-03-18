.class public final Ltq0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lwq0/m0;
.implements Lme0/a;


# instance fields
.field public final a:Lve0/u;


# direct methods
.method public constructor <init>(Lve0/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltq0/i;->a:Lve0/u;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Ltq0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ltq0/e;

    .line 7
    .line 8
    iget v1, v0, Ltq0/e;->f:I

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
    iput v1, v0, Ltq0/e;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltq0/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ltq0/e;-><init>(Ltq0/i;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ltq0/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltq0/e;->f:I

    .line 30
    .line 31
    const/4 v3, 0x4

    .line 32
    const/4 v4, 0x3

    .line 33
    const/4 v5, 0x2

    .line 34
    const/4 v6, 0x1

    .line 35
    iget-object p0, p0, Ltq0/i;->a:Lve0/u;

    .line 36
    .line 37
    if-eqz v2, :cond_5

    .line 38
    .line 39
    if-eq v2, v6, :cond_4

    .line 40
    .line 41
    if-eq v2, v5, :cond_3

    .line 42
    .line 43
    if-eq v2, v4, :cond_2

    .line 44
    .line 45
    if-ne v2, v3, :cond_1

    .line 46
    .line 47
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    goto :goto_5

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    iput v6, v0, Ltq0/e;->f:I

    .line 75
    .line 76
    const-string p1, "ENCRYPTED_SPIN_KEY"

    .line 77
    .line 78
    invoke-virtual {p0, p1, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    if-ne p1, v1, :cond_6

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_6
    :goto_1
    iput v5, v0, Ltq0/e;->f:I

    .line 86
    .line 87
    const-string p1, "INITIALIZATION_VECTOR_KEY"

    .line 88
    .line 89
    invoke-virtual {p0, p1, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    if-ne p1, v1, :cond_7

    .line 94
    .line 95
    goto :goto_4

    .line 96
    :cond_7
    :goto_2
    iput v4, v0, Ltq0/e;->f:I

    .line 97
    .line 98
    const-string p1, "BIOMETRIC_SUGGESTION_ENABLED_KEY"

    .line 99
    .line 100
    invoke-virtual {p0, p1, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    if-ne p1, v1, :cond_8

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_8
    :goto_3
    iput v3, v0, Ltq0/e;->f:I

    .line 108
    .line 109
    const-string p1, "IS_BIOMETRIC_RESET"

    .line 110
    .line 111
    invoke-virtual {p0, p1, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    if-ne p0, v1, :cond_9

    .line 116
    .line 117
    :goto_4
    return-object v1

    .line 118
    :cond_9
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    return-object p0
.end method

.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Ltq0/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ltq0/f;

    .line 7
    .line 8
    iget v1, v0, Ltq0/f;->g:I

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
    iput v1, v0, Ltq0/f;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltq0/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ltq0/f;-><init>(Ltq0/i;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ltq0/f;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltq0/f;->g:I

    .line 30
    .line 31
    iget-object p0, p0, Ltq0/i;->a:Lve0/u;

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v4, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    iget-object p0, v0, Ltq0/f;->d:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
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
    iput v4, v0, Ltq0/f;->g:I

    .line 63
    .line 64
    const-string p1, "ENCRYPTED_SPIN_KEY"

    .line 65
    .line 66
    invoke-virtual {p0, p1, v0}, Lve0/u;->f(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

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
    check-cast p1, Ljava/lang/String;

    .line 74
    .line 75
    iput-object p1, v0, Ltq0/f;->d:Ljava/lang/String;

    .line 76
    .line 77
    iput v3, v0, Ltq0/f;->g:I

    .line 78
    .line 79
    const-string v2, "INITIALIZATION_VECTOR_KEY"

    .line 80
    .line 81
    invoke-virtual {p0, v2, v0}, Lve0/u;->f(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    if-ne p0, v1, :cond_5

    .line 86
    .line 87
    :goto_2
    return-object v1

    .line 88
    :cond_5
    move-object v5, p1

    .line 89
    move-object p1, p0

    .line 90
    move-object p0, v5

    .line 91
    :goto_3
    check-cast p1, Ljava/lang/String;

    .line 92
    .line 93
    if-eqz p0, :cond_7

    .line 94
    .line 95
    if-nez p1, :cond_6

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_6
    new-instance v0, Lyq0/g;

    .line 99
    .line 100
    invoke-direct {v0, p0, p1}, Lyq0/g;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    return-object v0

    .line 104
    :cond_7
    :goto_4
    const/4 p0, 0x0

    .line 105
    return-object p0
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Ltq0/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ltq0/g;

    .line 7
    .line 8
    iget v1, v0, Ltq0/g;->f:I

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
    iput v1, v0, Ltq0/g;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltq0/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ltq0/g;-><init>(Ltq0/i;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ltq0/g;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltq0/g;->f:I

    .line 30
    .line 31
    iget-object p0, p0, Ltq0/i;->a:Lve0/u;

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v4, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_3

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput v4, v0, Ltq0/g;->f:I

    .line 61
    .line 62
    const-string p1, "ENCRYPTED_SPIN_KEY"

    .line 63
    .line 64
    invoke-virtual {p0, p1, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-ne p1, v1, :cond_4

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_4
    :goto_1
    iput v3, v0, Ltq0/g;->f:I

    .line 72
    .line 73
    const-string p1, "INITIALIZATION_VECTOR_KEY"

    .line 74
    .line 75
    invoke-virtual {p0, p1, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    if-ne p0, v1, :cond_5

    .line 80
    .line 81
    :goto_2
    return-object v1

    .line 82
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    return-object p0
.end method

.method public final d(Lyq0/g;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Ltq0/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ltq0/h;

    .line 7
    .line 8
    iget v1, v0, Ltq0/h;->g:I

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
    iput v1, v0, Ltq0/h;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltq0/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ltq0/h;-><init>(Ltq0/i;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ltq0/h;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltq0/h;->g:I

    .line 30
    .line 31
    iget-object p0, p0, Ltq0/i;->a:Lve0/u;

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v4, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_3

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
    iget-object p1, v0, Ltq0/h;->d:Lyq0/g;

    .line 54
    .line 55
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iget-object p2, p1, Lyq0/g;->a:Ljava/lang/String;

    .line 63
    .line 64
    iput-object p1, v0, Ltq0/h;->d:Lyq0/g;

    .line 65
    .line 66
    iput v4, v0, Ltq0/h;->g:I

    .line 67
    .line 68
    const-string v2, "ENCRYPTED_SPIN_KEY"

    .line 69
    .line 70
    invoke-virtual {p0, v2, p2, v0}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    if-ne p2, v1, :cond_4

    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_4
    :goto_1
    iget-object p1, p1, Lyq0/g;->b:Ljava/lang/String;

    .line 78
    .line 79
    const/4 p2, 0x0

    .line 80
    iput-object p2, v0, Ltq0/h;->d:Lyq0/g;

    .line 81
    .line 82
    iput v3, v0, Ltq0/h;->g:I

    .line 83
    .line 84
    const-string p2, "INITIALIZATION_VECTOR_KEY"

    .line 85
    .line 86
    invoke-virtual {p0, p2, p1, v0}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    if-ne p0, v1, :cond_5

    .line 91
    .line 92
    :goto_2
    return-object v1

    .line 93
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 94
    .line 95
    return-object p0
.end method
