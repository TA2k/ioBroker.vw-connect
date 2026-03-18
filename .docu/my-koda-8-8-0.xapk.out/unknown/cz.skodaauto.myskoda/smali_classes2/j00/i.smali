.class public final Lj00/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll00/f;


# instance fields
.field public final a:Lve0/u;

.field public final b:Ljava/util/LinkedHashSet;


# direct methods
.method public constructor <init>(Lve0/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj00/i;->a:Lve0/u;

    .line 5
    .line 6
    new-instance p1, Ljava/util/LinkedHashSet;

    .line 7
    .line 8
    invoke-direct {p1}, Ljava/util/LinkedHashSet;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lj00/i;->b:Ljava/util/LinkedHashSet;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lj00/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lj00/e;

    .line 7
    .line 8
    iget v1, v0, Lj00/e;->i:I

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
    iput v1, v0, Lj00/e;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj00/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lj00/e;-><init>(Lj00/i;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lj00/e;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj00/e;->i:I

    .line 30
    .line 31
    const-string v3, "connectivity_sunset_banner_dismissed_vins"

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
    iget p0, v0, Lj00/e;->f:I

    .line 54
    .line 55
    iget-object p1, v0, Lj00/e;->e:Lve0/u;

    .line 56
    .line 57
    iget-object v2, v0, Lj00/e;->d:Ljava/lang/String;

    .line 58
    .line 59
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    move-object v6, p2

    .line 63
    move-object p2, p1

    .line 64
    move-object p1, v2

    .line 65
    move-object v2, v6

    .line 66
    goto :goto_1

    .line 67
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iput-object p1, v0, Lj00/e;->d:Ljava/lang/String;

    .line 71
    .line 72
    iget-object p0, p0, Lj00/i;->a:Lve0/u;

    .line 73
    .line 74
    iput-object p0, v0, Lj00/e;->e:Lve0/u;

    .line 75
    .line 76
    const/4 p2, 0x0

    .line 77
    iput p2, v0, Lj00/e;->f:I

    .line 78
    .line 79
    iput v5, v0, Lj00/e;->i:I

    .line 80
    .line 81
    invoke-virtual {p0, v3, v0}, Lve0/u;->g(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    if-ne v2, v1, :cond_4

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    move v6, p2

    .line 89
    move-object p2, p0

    .line 90
    move p0, v6

    .line 91
    :goto_1
    check-cast v2, Ljava/util/Set;

    .line 92
    .line 93
    if-nez v2, :cond_5

    .line 94
    .line 95
    sget-object v2, Lmx0/u;->d:Lmx0/u;

    .line 96
    .line 97
    :cond_5
    invoke-static {v2, p1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    const/4 v2, 0x0

    .line 102
    iput-object v2, v0, Lj00/e;->d:Ljava/lang/String;

    .line 103
    .line 104
    iput-object v2, v0, Lj00/e;->e:Lve0/u;

    .line 105
    .line 106
    iput p0, v0, Lj00/e;->f:I

    .line 107
    .line 108
    iput v4, v0, Lj00/e;->i:I

    .line 109
    .line 110
    invoke-virtual {p2, v3, p1, v0}, Lve0/u;->o(Ljava/lang/String;Ljava/util/Set;Lrx0/c;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    if-ne p0, v1, :cond_6

    .line 115
    .line 116
    :goto_2
    return-object v1

    .line 117
    :cond_6
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 118
    .line 119
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lj00/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lj00/f;

    .line 7
    .line 8
    iget v1, v0, Lj00/f;->i:I

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
    iput v1, v0, Lj00/f;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj00/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lj00/f;-><init>(Lj00/i;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lj00/f;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj00/f;->i:I

    .line 30
    .line 31
    const-string v3, "connectivity_sunset_fullscreen_dismissed_vins"

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
    iget p0, v0, Lj00/f;->f:I

    .line 54
    .line 55
    iget-object p1, v0, Lj00/f;->e:Lve0/u;

    .line 56
    .line 57
    iget-object v2, v0, Lj00/f;->d:Ljava/lang/String;

    .line 58
    .line 59
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    move-object v6, p2

    .line 63
    move-object p2, p1

    .line 64
    move-object p1, v2

    .line 65
    move-object v2, v6

    .line 66
    goto :goto_1

    .line 67
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iput-object p1, v0, Lj00/f;->d:Ljava/lang/String;

    .line 71
    .line 72
    iget-object p0, p0, Lj00/i;->a:Lve0/u;

    .line 73
    .line 74
    iput-object p0, v0, Lj00/f;->e:Lve0/u;

    .line 75
    .line 76
    const/4 p2, 0x0

    .line 77
    iput p2, v0, Lj00/f;->f:I

    .line 78
    .line 79
    iput v5, v0, Lj00/f;->i:I

    .line 80
    .line 81
    invoke-virtual {p0, v3, v0}, Lve0/u;->g(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    if-ne v2, v1, :cond_4

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    move v6, p2

    .line 89
    move-object p2, p0

    .line 90
    move p0, v6

    .line 91
    :goto_1
    check-cast v2, Ljava/util/Set;

    .line 92
    .line 93
    if-nez v2, :cond_5

    .line 94
    .line 95
    sget-object v2, Lmx0/u;->d:Lmx0/u;

    .line 96
    .line 97
    :cond_5
    invoke-static {v2, p1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    const/4 v2, 0x0

    .line 102
    iput-object v2, v0, Lj00/f;->d:Ljava/lang/String;

    .line 103
    .line 104
    iput-object v2, v0, Lj00/f;->e:Lve0/u;

    .line 105
    .line 106
    iput p0, v0, Lj00/f;->f:I

    .line 107
    .line 108
    iput v4, v0, Lj00/f;->i:I

    .line 109
    .line 110
    invoke-virtual {p2, v3, p1, v0}, Lve0/u;->o(Ljava/lang/String;Ljava/util/Set;Lrx0/c;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    if-ne p0, v1, :cond_6

    .line 115
    .line 116
    :goto_2
    return-object v1

    .line 117
    :cond_6
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 118
    .line 119
    return-object p0
.end method

.method public final c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lj00/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lj00/g;

    .line 7
    .line 8
    iget v1, v0, Lj00/g;->g:I

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
    iput v1, v0, Lj00/g;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj00/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lj00/g;-><init>(Lj00/i;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lj00/g;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj00/g;->g:I

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
    iget-object p1, v0, Lj00/g;->d:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object p1, v0, Lj00/g;->d:Ljava/lang/String;

    .line 54
    .line 55
    iput v3, v0, Lj00/g;->g:I

    .line 56
    .line 57
    iget-object p0, p0, Lj00/i;->a:Lve0/u;

    .line 58
    .line 59
    const-string p2, "connectivity_sunset_banner_dismissed_vins"

    .line 60
    .line 61
    invoke-virtual {p0, p2, v0}, Lve0/u;->g(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    if-ne p2, v1, :cond_3

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_3
    :goto_1
    check-cast p2, Ljava/util/Set;

    .line 69
    .line 70
    if-nez p2, :cond_4

    .line 71
    .line 72
    sget-object p2, Lmx0/u;->d:Lmx0/u;

    .line 73
    .line 74
    :cond_4
    invoke-interface {p2, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0
.end method

.method public final d(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lj00/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lj00/h;

    .line 7
    .line 8
    iget v1, v0, Lj00/h;->g:I

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
    iput v1, v0, Lj00/h;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj00/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lj00/h;-><init>(Lj00/i;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lj00/h;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj00/h;->g:I

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
    iget-object p1, v0, Lj00/h;->d:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object p1, v0, Lj00/h;->d:Ljava/lang/String;

    .line 54
    .line 55
    iput v3, v0, Lj00/h;->g:I

    .line 56
    .line 57
    iget-object p0, p0, Lj00/i;->a:Lve0/u;

    .line 58
    .line 59
    const-string p2, "connectivity_sunset_fullscreen_dismissed_vins"

    .line 60
    .line 61
    invoke-virtual {p0, p2, v0}, Lve0/u;->g(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    if-ne p2, v1, :cond_3

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_3
    :goto_1
    check-cast p2, Ljava/util/Set;

    .line 69
    .line 70
    if-nez p2, :cond_4

    .line 71
    .line 72
    sget-object p2, Lmx0/u;->d:Lmx0/u;

    .line 73
    .line 74
    :cond_4
    invoke-interface {p2, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0
.end method
