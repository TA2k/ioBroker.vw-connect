.class public final Lo40/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lm40/g;

.field public final b:Lkf0/o;


# direct methods
.method public constructor <init>(Lm40/g;Lkf0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo40/c;->a:Lm40/g;

    .line 5
    .line 6
    iput-object p2, p0, Lo40/c;->b:Lkf0/o;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lo40/c;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lo40/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lo40/b;

    .line 7
    .line 8
    iget v1, v0, Lo40/b;->h:I

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
    iput v1, v0, Lo40/b;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lo40/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lo40/b;-><init>(Lo40/c;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lo40/b;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lo40/b;->h:I

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
    iget-object p1, v0, Lo40/b;->e:Ljava/lang/String;

    .line 37
    .line 38
    iget-object p0, v0, Lo40/b;->d:Lm40/g;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    move-object v4, p0

    .line 44
    :goto_1
    move-object v5, p1

    .line 45
    goto :goto_2

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-object p2, p0, Lo40/c;->a:Lm40/g;

    .line 58
    .line 59
    iput-object p2, v0, Lo40/b;->d:Lm40/g;

    .line 60
    .line 61
    iput-object p1, v0, Lo40/b;->e:Ljava/lang/String;

    .line 62
    .line 63
    iput v3, v0, Lo40/b;->h:I

    .line 64
    .line 65
    iget-object p0, p0, Lo40/c;->b:Lkf0/o;

    .line 66
    .line 67
    invoke-virtual {p0, v0}, Lkf0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    if-ne p0, v1, :cond_3

    .line 72
    .line 73
    return-object v1

    .line 74
    :cond_3
    move-object v4, p2

    .line 75
    move-object p2, p0

    .line 76
    goto :goto_1

    .line 77
    :goto_2
    check-cast p2, Lne0/t;

    .line 78
    .line 79
    instance-of p0, p2, Lne0/c;

    .line 80
    .line 81
    const/4 v7, 0x0

    .line 82
    if-eqz p0, :cond_4

    .line 83
    .line 84
    move-object p0, v7

    .line 85
    goto :goto_3

    .line 86
    :cond_4
    instance-of p0, p2, Lne0/e;

    .line 87
    .line 88
    if-eqz p0, :cond_6

    .line 89
    .line 90
    check-cast p2, Lne0/e;

    .line 91
    .line 92
    iget-object p0, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 93
    .line 94
    :goto_3
    check-cast p0, Lss0/j0;

    .line 95
    .line 96
    if-eqz p0, :cond_5

    .line 97
    .line 98
    iget-object p0, p0, Lss0/j0;->d:Ljava/lang/String;

    .line 99
    .line 100
    move-object v6, p0

    .line 101
    goto :goto_4

    .line 102
    :cond_5
    move-object v6, v7

    .line 103
    :goto_4
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    const-string p0, "locationId"

    .line 107
    .line 108
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    iget-object p0, v4, Lm40/g;->a:Lxl0/f;

    .line 112
    .line 113
    new-instance v2, La30/b;

    .line 114
    .line 115
    const/16 v3, 0x1a

    .line 116
    .line 117
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 118
    .line 119
    .line 120
    new-instance p1, Lm40/e;

    .line 121
    .line 122
    const/4 p2, 0x2

    .line 123
    invoke-direct {p1, p2}, Lm40/e;-><init>(I)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {p0, v2, p1, v7}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    return-object p0

    .line 131
    :cond_6
    new-instance p0, La8/r0;

    .line 132
    .line 133
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 134
    .line 135
    .line 136
    throw p0
.end method
