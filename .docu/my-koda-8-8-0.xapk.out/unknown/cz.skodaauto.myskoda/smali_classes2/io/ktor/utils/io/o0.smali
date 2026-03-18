.class public final Lio/ktor/utils/io/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/ktor/utils/io/t;


# instance fields
.field public final b:Lio/ktor/utils/io/t;

.field public final c:Lnz0/a;

.field public d:J

.field public e:J


# direct methods
.method public constructor <init>(Lio/ktor/utils/io/t;)V
    .locals 1

    .line 1
    const-string v0, "delegate"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lio/ktor/utils/io/o0;->b:Lio/ktor/utils/io/t;

    .line 10
    .line 11
    new-instance p1, Lnz0/a;

    .line 12
    .line 13
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lio/ktor/utils/io/o0;->c:Lnz0/a;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lio/ktor/utils/io/o0;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lio/ktor/utils/io/o0;->b:Lio/ktor/utils/io/t;

    .line 5
    .line 6
    invoke-interface {v0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iget-object v1, p0, Lio/ktor/utils/io/o0;->c:Lnz0/a;

    .line 11
    .line 12
    invoke-virtual {v1, v0}, Lnz0/a;->g(Lnz0/d;)J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    iget-wide v2, p0, Lio/ktor/utils/io/o0;->d:J

    .line 17
    .line 18
    add-long/2addr v2, v0

    .line 19
    iput-wide v2, p0, Lio/ktor/utils/io/o0;->d:J

    .line 20
    .line 21
    return-void
.end method

.method public final b()V
    .locals 6

    .line 1
    iget-wide v0, p0, Lio/ktor/utils/io/o0;->e:J

    .line 2
    .line 3
    iget-wide v2, p0, Lio/ktor/utils/io/o0;->d:J

    .line 4
    .line 5
    iget-object v4, p0, Lio/ktor/utils/io/o0;->c:Lnz0/a;

    .line 6
    .line 7
    iget-wide v4, v4, Lnz0/a;->f:J

    .line 8
    .line 9
    sub-long/2addr v2, v4

    .line 10
    add-long/2addr v2, v0

    .line 11
    iput-wide v2, p0, Lio/ktor/utils/io/o0;->e:J

    .line 12
    .line 13
    iput-wide v4, p0, Lio/ktor/utils/io/o0;->d:J

    .line 14
    .line 15
    return-void
.end method

.method public final c(Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/ktor/utils/io/o0;->b:Lio/ktor/utils/io/t;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lio/ktor/utils/io/t;->c(Ljava/lang/Throwable;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d()Ljava/lang/Throwable;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/ktor/utils/io/o0;->b:Lio/ktor/utils/io/t;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/ktor/utils/io/t;->d()Ljava/lang/Throwable;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final e()Lnz0/a;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/ktor/utils/io/o0;->a()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lio/ktor/utils/io/o0;->c:Lnz0/a;

    .line 5
    .line 6
    return-object p0
.end method

.method public final f(ILrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lio/ktor/utils/io/n0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lio/ktor/utils/io/n0;

    .line 7
    .line 8
    iget v1, v0, Lio/ktor/utils/io/n0;->f:I

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
    iput v1, v0, Lio/ktor/utils/io/n0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lio/ktor/utils/io/n0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lio/ktor/utils/io/n0;-><init>(Lio/ktor/utils/io/o0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lio/ktor/utils/io/n0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lio/ktor/utils/io/n0;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0}, Lio/ktor/utils/io/o0;->a()V

    .line 52
    .line 53
    .line 54
    iget-object p2, p0, Lio/ktor/utils/io/o0;->c:Lnz0/a;

    .line 55
    .line 56
    iget-wide v4, p2, Lnz0/a;->f:J

    .line 57
    .line 58
    int-to-long v6, p1

    .line 59
    cmp-long p2, v4, v6

    .line 60
    .line 61
    if-ltz p2, :cond_3

    .line 62
    .line 63
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 64
    .line 65
    return-object p0

    .line 66
    :cond_3
    iput v3, v0, Lio/ktor/utils/io/n0;->f:I

    .line 67
    .line 68
    iget-object p2, p0, Lio/ktor/utils/io/o0;->b:Lio/ktor/utils/io/t;

    .line 69
    .line 70
    invoke-interface {p2, p1, v0}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    if-ne p2, v1, :cond_4

    .line 75
    .line 76
    return-object v1

    .line 77
    :cond_4
    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    .line 78
    .line 79
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    if-eqz p1, :cond_5

    .line 84
    .line 85
    invoke-virtual {p0}, Lio/ktor/utils/io/o0;->a()V

    .line 86
    .line 87
    .line 88
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 89
    .line 90
    return-object p0

    .line 91
    :cond_5
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 92
    .line 93
    return-object p0
.end method

.method public final g()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lio/ktor/utils/io/o0;->c:Lnz0/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Lnz0/a;->Z()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lio/ktor/utils/io/o0;->b:Lio/ktor/utils/io/t;

    .line 10
    .line 11
    invoke-interface {p0}, Lio/ktor/utils/io/t;->g()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method
