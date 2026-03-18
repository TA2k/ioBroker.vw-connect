.class public final Lzl/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lzl/l;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lzl/l;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lzl/l;->a:Lzl/l;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lyl/l;Lmm/g;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p3, Lzl/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lzl/k;

    .line 7
    .line 8
    iget v1, v0, Lzl/k;->g:I

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
    iput v1, v0, Lzl/k;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzl/k;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lzl/k;-><init>(Lzl/l;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Lzl/k;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p3, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lzl/k;->g:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-ne v1, v2, :cond_1

    .line 35
    .line 36
    iget-object p2, v0, Lzl/k;->d:Lmm/g;

    .line 37
    .line 38
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object p2, v0, Lzl/k;->d:Lmm/g;

    .line 54
    .line 55
    iput v2, v0, Lzl/k;->g:I

    .line 56
    .line 57
    check-cast p1, Lyl/r;

    .line 58
    .line 59
    invoke-virtual {p1, p2, v0}, Lyl/r;->b(Lmm/g;Lrx0/c;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    if-ne p0, p3, :cond_3

    .line 64
    .line 65
    return-object p3

    .line 66
    :cond_3
    :goto_1
    check-cast p0, Lmm/j;

    .line 67
    .line 68
    instance-of p1, p0, Lmm/p;

    .line 69
    .line 70
    if-eqz p1, :cond_4

    .line 71
    .line 72
    new-instance p1, Lzl/f;

    .line 73
    .line 74
    check-cast p0, Lmm/p;

    .line 75
    .line 76
    iget-object p3, p0, Lmm/p;->a:Lyl/j;

    .line 77
    .line 78
    iget-object p2, p2, Lmm/g;->a:Landroid/content/Context;

    .line 79
    .line 80
    invoke-static {p3, p2, v2}, Lzl/j;->f(Lyl/j;Landroid/content/Context;I)Li3/c;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    invoke-direct {p1, p2, p0}, Lzl/f;-><init>(Li3/c;Lmm/p;)V

    .line 85
    .line 86
    .line 87
    return-object p1

    .line 88
    :cond_4
    instance-of p1, p0, Lmm/c;

    .line 89
    .line 90
    if-eqz p1, :cond_6

    .line 91
    .line 92
    new-instance p1, Lzl/d;

    .line 93
    .line 94
    check-cast p0, Lmm/c;

    .line 95
    .line 96
    iget-object p3, p0, Lmm/c;->a:Lyl/j;

    .line 97
    .line 98
    if-eqz p3, :cond_5

    .line 99
    .line 100
    iget-object p2, p2, Lmm/g;->a:Landroid/content/Context;

    .line 101
    .line 102
    invoke-static {p3, p2, v2}, Lzl/j;->f(Lyl/j;Landroid/content/Context;I)Li3/c;

    .line 103
    .line 104
    .line 105
    move-result-object p2

    .line 106
    goto :goto_2

    .line 107
    :cond_5
    const/4 p2, 0x0

    .line 108
    :goto_2
    invoke-direct {p1, p2, p0}, Lzl/d;-><init>(Li3/c;Lmm/c;)V

    .line 109
    .line 110
    .line 111
    return-object p1

    .line 112
    :cond_6
    new-instance p0, La8/r0;

    .line 113
    .line 114
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 115
    .line 116
    .line 117
    throw p0
.end method
