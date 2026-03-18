.class public final Lxl0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lam0/b;


# static fields
.field public static final d:Lcm0/b;


# instance fields
.field public final a:Lve0/u;

.field public final b:Lyy0/c2;

.field public final c:Lrz/k;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lcm0/b;->d:Lcm0/b;

    .line 2
    .line 3
    sput-object v0, Lxl0/o;->d:Lcm0/b;

    .line 4
    .line 5
    return-void
.end method

.method public constructor <init>(Lve0/u;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxl0/o;->a:Lve0/u;

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
    iput-object p1, p0, Lxl0/o;->b:Lyy0/c2;

    .line 12
    .line 13
    new-instance v0, Lrz/k;

    .line 14
    .line 15
    const/16 v1, 0x15

    .line 16
    .line 17
    invoke-direct {v0, p1, v1}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lxl0/o;->c:Lrz/k;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Enum;
    .locals 6

    .line 1
    instance-of v0, p1, Lxl0/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lxl0/k;

    .line 7
    .line 8
    iget v1, v0, Lxl0/k;->i:I

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
    iput v1, v0, Lxl0/k;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxl0/k;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lxl0/k;-><init>(Lxl0/o;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lxl0/k;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lxl0/k;->i:I

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
    iget-object p0, v0, Lxl0/k;->e:Lcm0/b;

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object p0

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
    iget p0, v0, Lxl0/k;->f:I

    .line 54
    .line 55
    iget-object v2, v0, Lxl0/k;->d:Lxl0/o;

    .line 56
    .line 57
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    move-object v5, p1

    .line 61
    move p1, p0

    .line 62
    move-object p0, v2

    .line 63
    move-object v2, v5

    .line 64
    goto :goto_1

    .line 65
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iget-object p1, p0, Lxl0/o;->b:Lyy0/c2;

    .line 69
    .line 70
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    check-cast p1, Lcm0/b;

    .line 75
    .line 76
    if-nez p1, :cond_6

    .line 77
    .line 78
    iput-object p0, v0, Lxl0/k;->d:Lxl0/o;

    .line 79
    .line 80
    const/4 p1, 0x0

    .line 81
    iput p1, v0, Lxl0/k;->f:I

    .line 82
    .line 83
    iput v4, v0, Lxl0/k;->i:I

    .line 84
    .line 85
    invoke-virtual {p0, v0}, Lxl0/o;->b(Lrx0/c;)Ljava/lang/Enum;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    if-ne v2, v1, :cond_4

    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_4
    :goto_1
    check-cast v2, Lcm0/b;

    .line 93
    .line 94
    const/4 v4, 0x0

    .line 95
    iput-object v4, v0, Lxl0/k;->d:Lxl0/o;

    .line 96
    .line 97
    iput-object v2, v0, Lxl0/k;->e:Lcm0/b;

    .line 98
    .line 99
    iput p1, v0, Lxl0/k;->f:I

    .line 100
    .line 101
    iput v3, v0, Lxl0/k;->i:I

    .line 102
    .line 103
    invoke-virtual {p0, v2, v0}, Lxl0/o;->c(Lcm0/b;Lrx0/c;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    if-ne p0, v1, :cond_5

    .line 108
    .line 109
    :goto_2
    return-object v1

    .line 110
    :cond_5
    return-object v2

    .line 111
    :cond_6
    return-object p1
.end method

.method public final b(Lrx0/c;)Ljava/lang/Enum;
    .locals 4

    .line 1
    instance-of v0, p1, Lxl0/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lxl0/l;

    .line 7
    .line 8
    iget v1, v0, Lxl0/l;->f:I

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
    iput v1, v0, Lxl0/l;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxl0/l;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lxl0/l;-><init>(Lxl0/o;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lxl0/l;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lxl0/l;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput v3, v0, Lxl0/l;->f:I

    .line 52
    .line 53
    iget-object p1, p0, Lxl0/o;->a:Lve0/u;

    .line 54
    .line 55
    const-string v2, "active_environment"

    .line 56
    .line 57
    invoke-virtual {p1, v2, v0}, Lve0/u;->f(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

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
    check-cast p1, Ljava/lang/String;

    .line 65
    .line 66
    sget-object v0, Lxl0/o;->d:Lcm0/b;

    .line 67
    .line 68
    if-nez p1, :cond_4

    .line 69
    .line 70
    return-object v0

    .line 71
    :cond_4
    :try_start_0
    invoke-static {p1}, Lcm0/b;->valueOf(Ljava/lang/String;)Lcm0/b;

    .line 72
    .line 73
    .line 74
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 75
    return-object p0

    .line 76
    :catch_0
    move-exception p1

    .line 77
    new-instance v1, Lgd0/b;

    .line 78
    .line 79
    const/4 v2, 0x3

    .line 80
    invoke-direct {v1, v2, p1}, Lgd0/b;-><init>(ILjava/lang/IllegalArgumentException;)V

    .line 81
    .line 82
    .line 83
    const/4 p1, 0x0

    .line 84
    invoke-static {p1, p0, v1}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 85
    .line 86
    .line 87
    return-object v0
.end method

.method public final c(Lcm0/b;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lxl0/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lxl0/m;

    .line 7
    .line 8
    iget v1, v0, Lxl0/m;->g:I

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
    iput v1, v0, Lxl0/m;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxl0/m;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lxl0/m;-><init>(Lxl0/o;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lxl0/m;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lxl0/m;->g:I

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
    iget-object p1, v0, Lxl0/m;->d:Lcm0/b;

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
    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    iput-object p1, v0, Lxl0/m;->d:Lcm0/b;

    .line 58
    .line 59
    iput v3, v0, Lxl0/m;->g:I

    .line 60
    .line 61
    iget-object v2, p0, Lxl0/o;->a:Lve0/u;

    .line 62
    .line 63
    const-string v3, "active_environment"

    .line 64
    .line 65
    invoke-virtual {v2, v3, p2, v0}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    if-ne p2, v1, :cond_3

    .line 70
    .line 71
    return-object v1

    .line 72
    :cond_3
    :goto_1
    iget-object p0, p0, Lxl0/o;->b:Lyy0/c2;

    .line 73
    .line 74
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 78
    .line 79
    return-object p0
.end method

.method public final d(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lxl0/n;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lxl0/n;

    .line 7
    .line 8
    iget v1, v0, Lxl0/n;->f:I

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
    iput v1, v0, Lxl0/n;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxl0/n;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lxl0/n;-><init>(Lxl0/o;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Lxl0/n;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget p1, v0, Lxl0/n;->f:I

    .line 30
    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    const/4 v0, 0x1

    .line 34
    if-ne p1, v0, :cond_2

    .line 35
    .line 36
    :cond_1
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0
.end method
