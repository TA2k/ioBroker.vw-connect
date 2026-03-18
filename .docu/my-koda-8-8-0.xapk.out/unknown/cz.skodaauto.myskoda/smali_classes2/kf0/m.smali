.class public final Lkf0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Lif0/f0;


# direct methods
.method public constructor <init>(Lkf0/o;Lif0/f0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkf0/m;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lkf0/m;->b:Lif0/f0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lkf0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lkf0/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lkf0/l;

    .line 7
    .line 8
    iget v1, v0, Lkf0/l;->f:I

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
    iput v1, v0, Lkf0/l;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkf0/l;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lkf0/l;-><init>(Lkf0/m;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lkf0/l;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkf0/l;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iput v4, v0, Lkf0/l;->f:I

    .line 59
    .line 60
    iget-object p1, p0, Lkf0/m;->a:Lkf0/o;

    .line 61
    .line 62
    invoke-virtual {p1, v0}, Lkf0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    if-ne p1, v1, :cond_4

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_4
    :goto_1
    check-cast p1, Lne0/t;

    .line 70
    .line 71
    instance-of v2, p1, Lne0/e;

    .line 72
    .line 73
    if-eqz v2, :cond_7

    .line 74
    .line 75
    check-cast p1, Lne0/e;

    .line 76
    .line 77
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p1, Lss0/j0;

    .line 80
    .line 81
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 82
    .line 83
    iput v3, v0, Lkf0/l;->f:I

    .line 84
    .line 85
    iget-object p0, p0, Lkf0/m;->b:Lif0/f0;

    .line 86
    .line 87
    invoke-virtual {p0, p1, v0}, Lif0/f0;->d(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    if-ne p1, v1, :cond_5

    .line 92
    .line 93
    :goto_2
    return-object v1

    .line 94
    :cond_5
    :goto_3
    check-cast p1, Lss0/k;

    .line 95
    .line 96
    if-nez p1, :cond_6

    .line 97
    .line 98
    new-instance v0, Lne0/c;

    .line 99
    .line 100
    new-instance v1, Lss0/g0;

    .line 101
    .line 102
    invoke-direct {v1}, Lss0/g0;-><init>()V

    .line 103
    .line 104
    .line 105
    const/4 v4, 0x0

    .line 106
    const/16 v5, 0x1e

    .line 107
    .line 108
    const/4 v2, 0x0

    .line 109
    const/4 v3, 0x0

    .line 110
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 111
    .line 112
    .line 113
    return-object v0

    .line 114
    :cond_6
    new-instance p0, Lne0/e;

    .line 115
    .line 116
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    return-object p0

    .line 120
    :cond_7
    instance-of p0, p1, Lne0/c;

    .line 121
    .line 122
    if-eqz p0, :cond_8

    .line 123
    .line 124
    return-object p1

    .line 125
    :cond_8
    new-instance p0, La8/r0;

    .line 126
    .line 127
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 128
    .line 129
    .line 130
    throw p0
.end method
