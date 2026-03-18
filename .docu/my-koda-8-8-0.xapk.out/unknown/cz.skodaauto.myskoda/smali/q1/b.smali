.class public final Lq1/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ln2/b;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ln2/b;

    .line 5
    .line 6
    const/16 v1, 0x10

    .line 7
    .line 8
    new-array v1, v1, [Lq1/c;

    .line 9
    .line 10
    invoke-direct {v0, v1}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lq1/b;->a:Ln2/b;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a(Ld3/c;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lq1/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lq1/a;

    .line 7
    .line 8
    iget v1, v0, Lq1/a;->j:I

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
    iput v1, v0, Lq1/a;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lq1/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lq1/a;-><init>(Lq1/b;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lq1/a;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lq1/a;->j:I

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
    iget p0, v0, Lq1/a;->g:I

    .line 37
    .line 38
    iget p1, v0, Lq1/a;->f:I

    .line 39
    .line 40
    iget-object v2, v0, Lq1/a;->e:[Ljava/lang/Object;

    .line 41
    .line 42
    iget-object v4, v0, Lq1/a;->d:Ld3/c;

    .line 43
    .line 44
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    move-object p2, v4

    .line 48
    goto :goto_2

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p0, p0, Lq1/b;->a:Ln2/b;

    .line 61
    .line 62
    iget-object p2, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 63
    .line 64
    iget p0, p0, Ln2/b;->f:I

    .line 65
    .line 66
    const/4 v2, 0x0

    .line 67
    move-object v7, p2

    .line 68
    move-object p2, p1

    .line 69
    move p1, v2

    .line 70
    move-object v2, v7

    .line 71
    :goto_1
    if-ge p1, p0, :cond_4

    .line 72
    .line 73
    aget-object v4, v2, p1

    .line 74
    .line 75
    check-cast v4, Lq1/c;

    .line 76
    .line 77
    new-instance v5, Lmc/e;

    .line 78
    .line 79
    const/16 v6, 0x16

    .line 80
    .line 81
    invoke-direct {v5, p2, v6}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 82
    .line 83
    .line 84
    iput-object p2, v0, Lq1/a;->d:Ld3/c;

    .line 85
    .line 86
    iput-object v2, v0, Lq1/a;->e:[Ljava/lang/Object;

    .line 87
    .line 88
    iput p1, v0, Lq1/a;->f:I

    .line 89
    .line 90
    iput p0, v0, Lq1/a;->g:I

    .line 91
    .line 92
    iput v3, v0, Lq1/a;->j:I

    .line 93
    .line 94
    invoke-static {v4, v5, v0}, Lcp0/r;->a(Lv3/m;Lay0/a;Lrx0/c;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    if-ne v4, v1, :cond_3

    .line 99
    .line 100
    return-object v1

    .line 101
    :cond_3
    :goto_2
    add-int/2addr p1, v3

    .line 102
    goto :goto_1

    .line 103
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object p0
.end method
