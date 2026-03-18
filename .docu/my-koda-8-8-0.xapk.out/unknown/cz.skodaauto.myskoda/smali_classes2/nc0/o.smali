.class public final Lnc0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lic0/c;


# instance fields
.field public final a:Lkc0/g;


# direct methods
.method public constructor <init>(Lkc0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnc0/o;->a:Lkc0/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lnc0/n;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lnc0/n;

    .line 7
    .line 8
    iget v1, v0, Lnc0/n;->f:I

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
    iput v1, v0, Lnc0/n;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lnc0/n;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lnc0/n;-><init>(Lnc0/o;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lnc0/n;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lnc0/n;->f:I

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
    iput v3, v0, Lnc0/n;->f:I

    .line 52
    .line 53
    iget-object p0, p0, Lnc0/o;->a:Lkc0/g;

    .line 54
    .line 55
    check-cast p0, Lic0/p;

    .line 56
    .line 57
    const/4 p1, 0x0

    .line 58
    invoke-virtual {p0, p1, v0}, Lic0/p;->d(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    if-ne p1, v1, :cond_3

    .line 63
    .line 64
    return-object v1

    .line 65
    :cond_3
    :goto_1
    check-cast p1, Lne0/t;

    .line 66
    .line 67
    instance-of p0, p1, Lne0/c;

    .line 68
    .line 69
    if-nez p0, :cond_5

    .line 70
    .line 71
    instance-of p0, p1, Lne0/e;

    .line 72
    .line 73
    if-eqz p0, :cond_4

    .line 74
    .line 75
    check-cast p1, Lne0/e;

    .line 76
    .line 77
    iget-object p0, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Llc0/a;

    .line 80
    .line 81
    iget-object p0, p0, Llc0/a;->a:Ljava/lang/String;

    .line 82
    .line 83
    return-object p0

    .line 84
    :cond_4
    new-instance p0, La8/r0;

    .line 85
    .line 86
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 87
    .line 88
    .line 89
    throw p0

    .line 90
    :cond_5
    check-cast p1, Lne0/c;

    .line 91
    .line 92
    iget-object p0, p1, Lne0/c;->a:Ljava/lang/Throwable;

    .line 93
    .line 94
    throw p0
.end method
