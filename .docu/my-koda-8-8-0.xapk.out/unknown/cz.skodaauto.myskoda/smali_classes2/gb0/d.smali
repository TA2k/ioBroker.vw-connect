.class public final Lgb0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lrs0/b;

.field public final b:Lgn0/a;

.field public final c:Lkf0/e;

.field public final d:Lgb0/l;


# direct methods
.method public constructor <init>(Lrs0/b;Lgn0/a;Lkf0/e;Lgb0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgb0/d;->a:Lrs0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lgb0/d;->b:Lgn0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lgb0/d;->c:Lkf0/e;

    .line 9
    .line 10
    iput-object p4, p0, Lgb0/d;->d:Lgb0/l;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lgb0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Lgb0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lgb0/c;

    .line 7
    .line 8
    iget v1, v0, Lgb0/c;->f:I

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
    iput v1, v0, Lgb0/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lgb0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lgb0/c;-><init>(Lgb0/d;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lgb0/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lgb0/c;->f:I

    .line 30
    .line 31
    const/4 v3, 0x4

    .line 32
    const/4 v4, 0x3

    .line 33
    const/4 v5, 0x2

    .line 34
    const/4 v6, 0x1

    .line 35
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    if-eqz v2, :cond_5

    .line 38
    .line 39
    if-eq v2, v6, :cond_4

    .line 40
    .line 41
    if-eq v2, v5, :cond_3

    .line 42
    .line 43
    if-eq v2, v4, :cond_2

    .line 44
    .line 45
    if-ne v2, v3, :cond_1

    .line 46
    .line 47
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    return-object v7

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    return-object v7

    .line 63
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    return-object v7

    .line 67
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    iput v6, v0, Lgb0/c;->f:I

    .line 75
    .line 76
    iget-object p1, p0, Lgb0/d;->a:Lrs0/b;

    .line 77
    .line 78
    invoke-virtual {p1, v0}, Lrs0/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    if-ne p1, v1, :cond_6

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_6
    :goto_1
    check-cast p1, Lne0/t;

    .line 86
    .line 87
    instance-of v2, p1, Lne0/e;

    .line 88
    .line 89
    if-eqz v2, :cond_7

    .line 90
    .line 91
    check-cast p1, Lne0/e;

    .line 92
    .line 93
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p1, Lss0/d0;

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_7
    instance-of p1, p1, Lne0/c;

    .line 99
    .line 100
    if-eqz p1, :cond_c

    .line 101
    .line 102
    const/4 p1, 0x0

    .line 103
    :goto_2
    instance-of v2, p1, Lss0/g;

    .line 104
    .line 105
    if-eqz v2, :cond_8

    .line 106
    .line 107
    iget-object p0, p0, Lgb0/d;->b:Lgn0/a;

    .line 108
    .line 109
    invoke-virtual {p0}, Lgn0/a;->invoke()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    check-cast p0, Lyy0/i;

    .line 114
    .line 115
    iput v5, v0, Lgb0/c;->f:I

    .line 116
    .line 117
    invoke-static {p0, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    if-ne p0, v1, :cond_a

    .line 122
    .line 123
    goto :goto_3

    .line 124
    :cond_8
    instance-of v2, p1, Lss0/j0;

    .line 125
    .line 126
    if-eqz v2, :cond_9

    .line 127
    .line 128
    iget-object p0, p0, Lgb0/d;->c:Lkf0/e;

    .line 129
    .line 130
    invoke-virtual {p0}, Lkf0/e;->invoke()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    check-cast p0, Lyy0/i;

    .line 135
    .line 136
    iput v4, v0, Lgb0/c;->f:I

    .line 137
    .line 138
    invoke-static {p0, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    if-ne p0, v1, :cond_a

    .line 143
    .line 144
    goto :goto_3

    .line 145
    :cond_9
    if-nez p1, :cond_b

    .line 146
    .line 147
    iput v3, v0, Lgb0/c;->f:I

    .line 148
    .line 149
    iget-object p0, p0, Lgb0/d;->d:Lgb0/l;

    .line 150
    .line 151
    invoke-virtual {p0, v0}, Lgb0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    if-ne p0, v1, :cond_a

    .line 156
    .line 157
    :goto_3
    return-object v1

    .line 158
    :cond_a
    return-object v7

    .line 159
    :cond_b
    new-instance p0, La8/r0;

    .line 160
    .line 161
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 162
    .line 163
    .line 164
    throw p0

    .line 165
    :cond_c
    new-instance p0, La8/r0;

    .line 166
    .line 167
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 168
    .line 169
    .line 170
    throw p0
.end method
