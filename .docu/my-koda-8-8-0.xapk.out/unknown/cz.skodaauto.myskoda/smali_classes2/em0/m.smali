.class public final Lem0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lti0/a;

.field public final b:Lem0/a;

.field public final c:Lyy0/c2;

.field public final d:Lyy0/l1;


# direct methods
.method public constructor <init>(Lti0/a;Lem0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lem0/m;->a:Lti0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lem0/m;->b:Lem0/a;

    .line 7
    .line 8
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 9
    .line 10
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iput-object p1, p0, Lem0/m;->c:Lyy0/c2;

    .line 15
    .line 16
    new-instance p2, Lyy0/l1;

    .line 17
    .line 18
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 19
    .line 20
    .line 21
    iput-object p2, p0, Lem0/m;->d:Lyy0/l1;

    .line 22
    .line 23
    return-void
.end method

.method public static final a(Lem0/m;Lem0/g;)Lem0/g;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v0, v0, Lem0/m;->b:Lem0/a;

    .line 6
    .line 7
    iget-object v2, v1, Lem0/g;->j:Ljava/lang/String;

    .line 8
    .line 9
    check-cast v0, Lim0/c;

    .line 10
    .line 11
    invoke-virtual {v0, v2}, Lim0/c;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v11

    .line 15
    iget-object v2, v1, Lem0/g;->d:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v0, v2}, Lim0/c;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    iget-object v2, v1, Lem0/g;->k:Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {v0, v2}, Lim0/c;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v12

    .line 27
    iget-object v2, v1, Lem0/g;->f:Ljava/lang/String;

    .line 28
    .line 29
    invoke-virtual {v0, v2}, Lim0/c;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v6

    .line 33
    const-wide/16 v18, 0x0

    .line 34
    .line 35
    const v20, 0x1f9d7

    .line 36
    .line 37
    .line 38
    const/4 v2, 0x0

    .line 39
    const/4 v3, 0x0

    .line 40
    const/4 v5, 0x0

    .line 41
    const/4 v7, 0x0

    .line 42
    const-wide/16 v8, 0x0

    .line 43
    .line 44
    const/4 v10, 0x0

    .line 45
    const/4 v13, 0x0

    .line 46
    const/4 v14, 0x0

    .line 47
    const/4 v15, 0x0

    .line 48
    const/16 v16, 0x0

    .line 49
    .line 50
    const/16 v17, 0x0

    .line 51
    .line 52
    invoke-static/range {v1 .. v20}, Lem0/g;->a(Lem0/g;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lhm0/c;JI)Lem0/g;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    return-object v0
.end method


# virtual methods
.method public final b(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Lem0/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lem0/k;

    .line 7
    .line 8
    iget v1, v0, Lem0/k;->g:I

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
    iput v1, v0, Lem0/k;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lem0/k;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lem0/k;-><init>(Lem0/m;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lem0/k;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lem0/k;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    iget-wide p1, v0, Lem0/k;->d:J

    .line 52
    .line 53
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput-wide p1, v0, Lem0/k;->d:J

    .line 61
    .line 62
    iput v4, v0, Lem0/k;->g:I

    .line 63
    .line 64
    iget-object p0, p0, Lem0/m;->a:Lti0/a;

    .line 65
    .line 66
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p3

    .line 70
    if-ne p3, v1, :cond_4

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    :goto_1
    check-cast p3, Lem0/f;

    .line 74
    .line 75
    iput-wide p1, v0, Lem0/k;->d:J

    .line 76
    .line 77
    iput v3, v0, Lem0/k;->g:I

    .line 78
    .line 79
    iget-object p0, p3, Lem0/f;->a:Lla/u;

    .line 80
    .line 81
    new-instance v2, Le81/e;

    .line 82
    .line 83
    const/4 v3, 0x1

    .line 84
    invoke-direct {v2, p1, p2, p3, v3}, Le81/e;-><init>(JLjava/lang/Object;I)V

    .line 85
    .line 86
    .line 87
    const/4 p1, 0x0

    .line 88
    invoke-static {v0, p0, v4, p1, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p3

    .line 92
    if-ne p3, v1, :cond_5

    .line 93
    .line 94
    :goto_2
    return-object v1

    .line 95
    :cond_5
    :goto_3
    check-cast p3, Lem0/g;

    .line 96
    .line 97
    if-eqz p3, :cond_6

    .line 98
    .line 99
    invoke-static {p3}, Lkp/l6;->b(Lem0/g;)Lhm0/b;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    goto :goto_4

    .line 104
    :cond_6
    const/4 p0, 0x0

    .line 105
    :goto_4
    new-instance p1, Lyy0/m;

    .line 106
    .line 107
    const/4 p2, 0x0

    .line 108
    invoke-direct {p1, p0, p2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 109
    .line 110
    .line 111
    return-object p1
.end method
