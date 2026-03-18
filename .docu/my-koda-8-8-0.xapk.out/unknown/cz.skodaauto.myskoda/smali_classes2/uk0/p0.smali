.class public final Luk0/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lal0/v;

.field public final b:Lbd0/c;

.field public final c:Lsk0/d;


# direct methods
.method public constructor <init>(Lal0/v;Lbd0/c;Lsk0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luk0/p0;->a:Lal0/v;

    .line 5
    .line 6
    iput-object p2, p0, Luk0/p0;->b:Lbd0/c;

    .line 7
    .line 8
    iput-object p3, p0, Luk0/p0;->c:Lsk0/d;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Luk0/p0;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p2, Luk0/o0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Luk0/o0;

    .line 7
    .line 8
    iget v1, v0, Luk0/o0;->h:I

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
    iput v1, v0, Luk0/o0;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Luk0/o0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Luk0/o0;-><init>(Luk0/p0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Luk0/o0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Luk0/o0;->h:I

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
    iget-object p1, v0, Luk0/o0;->e:Ljava/lang/String;

    .line 37
    .line 38
    iget-object v0, v0, Luk0/o0;->d:Lsk0/d;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    move-object v4, v0

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
    iget-object p2, p0, Luk0/p0;->c:Lsk0/d;

    .line 58
    .line 59
    iput-object p2, v0, Luk0/o0;->d:Lsk0/d;

    .line 60
    .line 61
    iput-object p1, v0, Luk0/o0;->e:Ljava/lang/String;

    .line 62
    .line 63
    iput v3, v0, Luk0/o0;->h:I

    .line 64
    .line 65
    iget-object v0, p0, Luk0/p0;->a:Lal0/v;

    .line 66
    .line 67
    iget-object v0, v0, Lal0/v;->a:Lal0/b0;

    .line 68
    .line 69
    check-cast v0, Lyk0/e;

    .line 70
    .line 71
    iget-object v2, v0, Lyk0/e;->e:Ljava/util/UUID;

    .line 72
    .line 73
    if-nez v2, :cond_3

    .line 74
    .line 75
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    iput-object v2, v0, Lyk0/e;->e:Ljava/util/UUID;

    .line 80
    .line 81
    const-string v0, "also(...)"

    .line 82
    .line 83
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    :cond_3
    if-ne v2, v1, :cond_4

    .line 87
    .line 88
    return-object v1

    .line 89
    :cond_4
    move-object v4, p2

    .line 90
    move-object p2, v2

    .line 91
    goto :goto_1

    .line 92
    :goto_2
    move-object v6, p2

    .line 93
    check-cast v6, Ljava/util/UUID;

    .line 94
    .line 95
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    const-string p1, "id"

    .line 99
    .line 100
    invoke-static {v5, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    const-string p1, "sessionId"

    .line 104
    .line 105
    invoke-static {v6, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    iget-object p1, v4, Lsk0/d;->a:Lxl0/f;

    .line 109
    .line 110
    new-instance v3, Lo10/l;

    .line 111
    .line 112
    const/16 v8, 0xa

    .line 113
    .line 114
    const/4 v7, 0x0

    .line 115
    invoke-direct/range {v3 .. v8}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 116
    .line 117
    .line 118
    new-instance p2, Lsb/a;

    .line 119
    .line 120
    const/16 v0, 0x9

    .line 121
    .line 122
    invoke-direct {p2, v0}, Lsb/a;-><init>(I)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {p1, v3, p2, v7}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    new-instance p2, Ls10/a0;

    .line 130
    .line 131
    const/16 v0, 0xd

    .line 132
    .line 133
    invoke-direct {p2, p0, v7, v0}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 134
    .line 135
    .line 136
    invoke-static {p2, p1}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    return-object p0
.end method
