.class public final Lti/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lsi/f;


# instance fields
.field public final a:Lvy0/b0;

.field public final b:Lth/b;

.field public final c:Lt10/k;

.field public final d:Lt61/d;

.field public final e:Lyy0/c2;

.field public final f:Llx0/q;


# direct methods
.method public constructor <init>(Lvy0/b0;Lth/b;Lth/b;Lt10/k;Lt61/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lti/c;->a:Lvy0/b0;

    .line 5
    .line 6
    iput-object p3, p0, Lti/c;->b:Lth/b;

    .line 7
    .line 8
    iput-object p4, p0, Lti/c;->c:Lt10/k;

    .line 9
    .line 10
    iput-object p5, p0, Lti/c;->d:Lt61/d;

    .line 11
    .line 12
    sget-object p1, Lti/e;->b:Lti/e;

    .line 13
    .line 14
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iput-object p1, p0, Lti/c;->e:Lyy0/c2;

    .line 19
    .line 20
    new-instance p1, Lr1/b;

    .line 21
    .line 22
    const/16 p2, 0x1a

    .line 23
    .line 24
    invoke-direct {p1, p0, p2}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 25
    .line 26
    .line 27
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    iput-object p1, p0, Lti/c;->f:Llx0/q;

    .line 32
    .line 33
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lti/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lti/b;

    .line 7
    .line 8
    iget v1, v0, Lti/b;->f:I

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
    iput v1, v0, Lti/b;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lti/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lti/b;-><init>(Lti/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lti/b;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lti/b;->f:I

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
    new-instance p2, Lui/i;

    .line 52
    .line 53
    invoke-direct {p2, p1}, Lui/i;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iput v3, v0, Lti/b;->f:I

    .line 57
    .line 58
    iget-object p1, p0, Lti/c;->b:Lth/b;

    .line 59
    .line 60
    invoke-virtual {p1, p2, v0}, Lth/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p2

    .line 64
    if-ne p2, v1, :cond_3

    .line 65
    .line 66
    return-object v1

    .line 67
    :cond_3
    :goto_1
    check-cast p2, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 68
    .line 69
    invoke-static {p2}, Lkp/j0;->b(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    instance-of p2, p1, Llx0/n;

    .line 74
    .line 75
    if-nez p2, :cond_5

    .line 76
    .line 77
    :cond_4
    iget-object p2, p0, Lti/c;->e:Lyy0/c2;

    .line 78
    .line 79
    invoke-virtual {p2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    move-object v1, v0

    .line 84
    check-cast v1, Lti/g;

    .line 85
    .line 86
    new-instance v1, Lti/h;

    .line 87
    .line 88
    iget-object v2, p0, Lti/c;->d:Lt61/d;

    .line 89
    .line 90
    invoke-virtual {v2}, Lt61/d;->invoke()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    check-cast v2, Ljava/lang/Number;

    .line 95
    .line 96
    invoke-virtual {v2}, Ljava/lang/Number;->longValue()J

    .line 97
    .line 98
    .line 99
    move-result-wide v2

    .line 100
    invoke-direct {v1, v2, v3}, Lti/h;-><init>(J)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p2, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result p2

    .line 107
    if-eqz p2, :cond_4

    .line 108
    .line 109
    :cond_5
    return-object p1
.end method
