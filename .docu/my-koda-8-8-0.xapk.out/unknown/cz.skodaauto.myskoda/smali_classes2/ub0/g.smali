.class public final Lub0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lub0/a;

.field public final b:Lub0/c;


# direct methods
.method public constructor <init>(Lub0/a;Lub0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lub0/g;->a:Lub0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lub0/g;->b:Lub0/c;

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
    invoke-virtual {p0, p2}, Lub0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lub0/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lub0/f;

    .line 7
    .line 8
    iget v1, v0, Lub0/f;->f:I

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
    iput v1, v0, Lub0/f;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lub0/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lub0/f;-><init>(Lub0/g;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lub0/f;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lub0/f;->f:I

    .line 30
    .line 31
    iget-object v3, p0, Lub0/g;->a:Lub0/a;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    const/4 v5, 0x2

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v5, :cond_1

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput v4, v0, Lub0/f;->f:I

    .line 61
    .line 62
    move-object p1, v3

    .line 63
    check-cast p1, Lsb0/b;

    .line 64
    .line 65
    invoke-virtual {p1, v0}, Lsb0/b;->a(Lrx0/c;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    if-ne p1, v1, :cond_4

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_4
    :goto_1
    check-cast p1, Ljava/lang/String;

    .line 73
    .line 74
    const-string v2, "8.8.0"

    .line 75
    .line 76
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result p1

    .line 80
    if-eqz p1, :cond_6

    .line 81
    .line 82
    iput v5, v0, Lub0/f;->f:I

    .line 83
    .line 84
    iget-object p0, p0, Lub0/g;->b:Lub0/c;

    .line 85
    .line 86
    invoke-virtual {p0, v0}, Lub0/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    if-ne p0, v1, :cond_5

    .line 91
    .line 92
    :goto_2
    return-object v1

    .line 93
    :cond_5
    :goto_3
    new-instance p0, Lru0/l;

    .line 94
    .line 95
    const/16 p1, 0x17

    .line 96
    .line 97
    const/4 v0, 0x0

    .line 98
    invoke-direct {p0, v5, v0, p1}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 99
    .line 100
    .line 101
    new-instance p1, Lyy0/m1;

    .line 102
    .line 103
    invoke-direct {p1, p0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 104
    .line 105
    .line 106
    return-object p1

    .line 107
    :cond_6
    check-cast v3, Lsb0/b;

    .line 108
    .line 109
    iget-object p0, v3, Lsb0/b;->a:Lve0/u;

    .line 110
    .line 111
    const-string p1, "last_update_version"

    .line 112
    .line 113
    const-string v0, ""

    .line 114
    .line 115
    invoke-virtual {p0, p1, v0}, Lve0/u;->j(Ljava/lang/String;Ljava/lang/String;)Lsw0/c;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    new-instance p1, Lub0/e;

    .line 120
    .line 121
    const/4 v0, 0x0

    .line 122
    invoke-direct {p1, p0, v0}, Lub0/e;-><init>(Lsw0/c;I)V

    .line 123
    .line 124
    .line 125
    return-object p1
.end method
