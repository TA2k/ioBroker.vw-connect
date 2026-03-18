.class public final Lu60/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lzd0/c;


# direct methods
.method public constructor <init>(Lzd0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu60/c;->a:Lzd0/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lu60/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    iget-object v0, p0, Lu60/c;->a:Lzd0/c;

    .line 2
    .line 3
    iget-object v0, v0, Lzd0/c;->a:Lxd0/b;

    .line 4
    .line 5
    instance-of v1, p1, Lu60/b;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    move-object v1, p1

    .line 10
    check-cast v1, Lu60/b;

    .line 11
    .line 12
    iget v2, v1, Lu60/b;->f:I

    .line 13
    .line 14
    const/high16 v3, -0x80000000

    .line 15
    .line 16
    and-int v4, v2, v3

    .line 17
    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    sub-int/2addr v2, v3

    .line 21
    iput v2, v1, Lu60/b;->f:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Lu60/b;

    .line 25
    .line 26
    invoke-direct {v1, p0, p1}, Lu60/b;-><init>(Lu60/c;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p0, v1, Lu60/b;->d:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v2, v1, Lu60/b;->f:I

    .line 34
    .line 35
    const/4 v3, 0x3

    .line 36
    const/4 v4, 0x2

    .line 37
    const/4 v5, 0x1

    .line 38
    if-eqz v2, :cond_4

    .line 39
    .line 40
    if-eq v2, v5, :cond_3

    .line 41
    .line 42
    if-eq v2, v4, :cond_2

    .line 43
    .line 44
    if-ne v2, v3, :cond_1

    .line 45
    .line 46
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_4

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_3
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_4
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iput v5, v1, Lu60/b;->f:I

    .line 70
    .line 71
    sget-object p0, Llc0/c;->a:Llc0/c;

    .line 72
    .line 73
    invoke-virtual {v0, p0, v1}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    if-ne p0, p1, :cond_5

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_5
    :goto_1
    check-cast p0, Lne0/t;

    .line 81
    .line 82
    instance-of v2, p0, Lne0/c;

    .line 83
    .line 84
    if-eqz v2, :cond_6

    .line 85
    .line 86
    check-cast p0, Lne0/c;

    .line 87
    .line 88
    return-object p0

    .line 89
    :cond_6
    sget-object p0, Lw60/a;->a:Lw60/a;

    .line 90
    .line 91
    iput v4, v1, Lu60/b;->f:I

    .line 92
    .line 93
    invoke-virtual {v0, p0, v1}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    if-ne p0, p1, :cond_7

    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_7
    :goto_2
    check-cast p0, Lne0/t;

    .line 101
    .line 102
    instance-of v2, p0, Lne0/c;

    .line 103
    .line 104
    if-eqz v2, :cond_8

    .line 105
    .line 106
    check-cast p0, Lne0/c;

    .line 107
    .line 108
    return-object p0

    .line 109
    :cond_8
    sget-object p0, Lw60/a;->b:Lw60/a;

    .line 110
    .line 111
    iput v3, v1, Lu60/b;->f:I

    .line 112
    .line 113
    invoke-virtual {v0, p0, v1}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    if-ne p0, p1, :cond_9

    .line 118
    .line 119
    :goto_3
    return-object p1

    .line 120
    :cond_9
    :goto_4
    check-cast p0, Lne0/t;

    .line 121
    .line 122
    instance-of p1, p0, Lne0/c;

    .line 123
    .line 124
    if-eqz p1, :cond_a

    .line 125
    .line 126
    check-cast p0, Lne0/c;

    .line 127
    .line 128
    return-object p0

    .line 129
    :cond_a
    new-instance p0, Lne0/e;

    .line 130
    .line 131
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    return-object p0
.end method
