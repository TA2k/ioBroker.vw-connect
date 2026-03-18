.class public final Lal0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lml0/a;

.field public final b:Lml0/e;

.field public final c:Lal0/e0;

.field public final d:Lyk0/q;


# direct methods
.method public constructor <init>(Lml0/a;Lml0/e;Lal0/e0;Lyk0/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lal0/j;->a:Lml0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lal0/j;->b:Lml0/e;

    .line 7
    .line 8
    iput-object p3, p0, Lal0/j;->c:Lal0/e0;

    .line 9
    .line 10
    iput-object p4, p0, Lal0/j;->d:Lyk0/q;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lal0/e;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lal0/j;->b(Lal0/e;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lal0/e;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v1, p2, Lal0/g;

    .line 2
    .line 3
    if-eqz v1, :cond_0

    .line 4
    .line 5
    move-object v1, p2

    .line 6
    check-cast v1, Lal0/g;

    .line 7
    .line 8
    iget v3, v1, Lal0/g;->g:I

    .line 9
    .line 10
    const/high16 v4, -0x80000000

    .line 11
    .line 12
    and-int v5, v3, v4

    .line 13
    .line 14
    if-eqz v5, :cond_0

    .line 15
    .line 16
    sub-int/2addr v3, v4

    .line 17
    iput v3, v1, Lal0/g;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v1, Lal0/g;

    .line 21
    .line 22
    invoke-direct {v1, p0, p2}, Lal0/g;-><init>(Lal0/j;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object v0, v1, Lal0/g;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v4, v1, Lal0/g;->g:I

    .line 30
    .line 31
    const/4 v5, 0x1

    .line 32
    if-eqz v4, :cond_2

    .line 33
    .line 34
    if-ne v4, v5, :cond_1

    .line 35
    .line 36
    iget-object v1, v1, Lal0/g;->d:Lal0/e;

    .line 37
    .line 38
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    move-object v3, v1

    .line 42
    goto :goto_1

    .line 43
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw v0

    .line 51
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-object v0, p0, Lal0/j;->c:Lal0/e0;

    .line 55
    .line 56
    check-cast v0, Lyk0/j;

    .line 57
    .line 58
    iget-object v0, v0, Lyk0/j;->h:Lyy0/c2;

    .line 59
    .line 60
    iput-object p1, v1, Lal0/g;->d:Lal0/e;

    .line 61
    .line 62
    iput v5, v1, Lal0/g;->g:I

    .line 63
    .line 64
    invoke-static {v0, v1}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    if-ne v0, v3, :cond_3

    .line 69
    .line 70
    return-object v3

    .line 71
    :cond_3
    move-object v3, p1

    .line 72
    :goto_1
    move-object v4, v0

    .line 73
    check-cast v4, Lbl0/h0;

    .line 74
    .line 75
    if-nez v4, :cond_4

    .line 76
    .line 77
    new-instance v6, Lne0/c;

    .line 78
    .line 79
    new-instance v7, Ljava/lang/Exception;

    .line 80
    .line 81
    const-string v0, "Missing selected poi category"

    .line 82
    .line 83
    invoke-direct {v7, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    const/4 v10, 0x0

    .line 87
    const/16 v11, 0x1e

    .line 88
    .line 89
    const/4 v8, 0x0

    .line 90
    const/4 v9, 0x0

    .line 91
    invoke-direct/range {v6 .. v11}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 92
    .line 93
    .line 94
    new-instance v0, Lyy0/m;

    .line 95
    .line 96
    const/4 v1, 0x0

    .line 97
    invoke-direct {v0, v6, v1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 98
    .line 99
    .line 100
    return-object v0

    .line 101
    :cond_4
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 102
    .line 103
    .line 104
    move-result v0

    .line 105
    if-eq v0, v5, :cond_5

    .line 106
    .line 107
    const/4 v1, 0x2

    .line 108
    if-eq v0, v1, :cond_5

    .line 109
    .line 110
    iget-object v0, p0, Lal0/j;->b:Lml0/e;

    .line 111
    .line 112
    invoke-virtual {v0}, Lml0/e;->invoke()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    check-cast v0, Lyy0/i;

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_5
    iget-object v0, p0, Lal0/j;->a:Lml0/a;

    .line 120
    .line 121
    invoke-virtual {v0}, Lml0/a;->invoke()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    check-cast v0, Lyy0/i;

    .line 126
    .line 127
    :goto_2
    invoke-static {v0}, Lbb/j0;->i(Lyy0/i;)Lyy0/m1;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    new-instance v6, Lal0/i;

    .line 132
    .line 133
    const/4 v1, 0x0

    .line 134
    invoke-direct {v6, v0, v1}, Lal0/i;-><init>(Lyy0/m1;I)V

    .line 135
    .line 136
    .line 137
    new-instance v0, Lal0/f;

    .line 138
    .line 139
    const/4 v5, 0x0

    .line 140
    move-object v2, p0

    .line 141
    invoke-direct/range {v0 .. v5}, Lal0/f;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 142
    .line 143
    .line 144
    invoke-static {v6, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    return-object v0
.end method
