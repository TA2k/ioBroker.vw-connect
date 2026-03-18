.class public final Ltw0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:Lyy0/j;

.field public final synthetic e:Low0/e;

.field public final synthetic f:Ljava/nio/charset/Charset;

.field public final synthetic g:Lzw0/a;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lyy0/j;Low0/e;Ljava/nio/charset/Charset;Lzw0/a;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltw0/e;->d:Lyy0/j;

    .line 5
    .line 6
    iput-object p2, p0, Ltw0/e;->e:Low0/e;

    .line 7
    .line 8
    iput-object p3, p0, Ltw0/e;->f:Ljava/nio/charset/Charset;

    .line 9
    .line 10
    iput-object p4, p0, Ltw0/e;->g:Lzw0/a;

    .line 11
    .line 12
    iput-object p5, p0, Ltw0/e;->h:Ljava/lang/Object;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p2, Ltw0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ltw0/d;

    .line 7
    .line 8
    iget v1, v0, Ltw0/d;->e:I

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
    iput v1, v0, Ltw0/d;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltw0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ltw0/d;-><init>(Ltw0/e;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ltw0/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltw0/d;->e:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v5, 0x0

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v4, :cond_2

    .line 37
    .line 38
    if-ne v2, v3, :cond_1

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto/16 :goto_5

    .line 44
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
    iget p0, v0, Ltw0/d;->h:I

    .line 54
    .line 55
    iget-object p1, v0, Ltw0/d;->g:Lyy0/j;

    .line 56
    .line 57
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    move-object v7, p1

    .line 65
    check-cast v7, Luw0/h;

    .line 66
    .line 67
    iget-object p1, p0, Ltw0/e;->d:Lyy0/j;

    .line 68
    .line 69
    iput-object p1, v0, Ltw0/d;->g:Lyy0/j;

    .line 70
    .line 71
    const/4 p2, 0x0

    .line 72
    iput p2, v0, Ltw0/d;->h:I

    .line 73
    .line 74
    iput v4, v0, Ltw0/d;->e:I

    .line 75
    .line 76
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    sget-object v2, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 80
    .line 81
    iget-object v10, p0, Ltw0/e;->f:Ljava/nio/charset/Charset;

    .line 82
    .line 83
    invoke-static {v10, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    if-eqz v2, :cond_5

    .line 88
    .line 89
    iget-object v2, p0, Ltw0/e;->g:Lzw0/a;

    .line 90
    .line 91
    iget-object v4, v2, Lzw0/a;->a:Lhy0/d;

    .line 92
    .line 93
    const-class v6, Lyy0/i;

    .line 94
    .line 95
    sget-object v8, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 96
    .line 97
    invoke-virtual {v8, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 98
    .line 99
    .line 100
    move-result-object v6

    .line 101
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v4

    .line 105
    if-nez v4, :cond_4

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_4
    invoke-static {v2}, Llp/oa;->a(Lzw0/a;)Lzw0/a;

    .line 109
    .line 110
    .line 111
    move-result-object v2

    .line 112
    iget-object v4, v7, Luw0/h;->a:Lvz0/d;

    .line 113
    .line 114
    iget-object v4, v4, Lvz0/d;->b:Lwq/f;

    .line 115
    .line 116
    invoke-static {v4, v2}, Llp/n0;->d(Lwq/f;Lzw0/a;)Lqz0/a;

    .line 117
    .line 118
    .line 119
    move-result-object v9

    .line 120
    new-instance v2, Lrw0/a;

    .line 121
    .line 122
    new-instance v6, Laa/i0;

    .line 123
    .line 124
    const/4 v11, 0x0

    .line 125
    const/16 v12, 0x15

    .line 126
    .line 127
    iget-object v8, p0, Ltw0/e;->h:Ljava/lang/Object;

    .line 128
    .line 129
    invoke-direct/range {v6 .. v12}, Laa/i0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 130
    .line 131
    .line 132
    iget-object p0, p0, Ltw0/e;->e:Low0/e;

    .line 133
    .line 134
    invoke-static {p0, v10}, Ljp/ic;->k(Low0/e;Ljava/nio/charset/Charset;)Low0/e;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    invoke-direct {v2, v6, p0}, Lrw0/a;-><init>(Laa/i0;Low0/e;)V

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_5
    :goto_1
    move-object v2, v5

    .line 143
    :goto_2
    if-ne v2, v1, :cond_6

    .line 144
    .line 145
    goto :goto_4

    .line 146
    :cond_6
    move p0, p2

    .line 147
    move-object p2, v2

    .line 148
    :goto_3
    iput-object v5, v0, Ltw0/d;->g:Lyy0/j;

    .line 149
    .line 150
    iput p0, v0, Ltw0/d;->h:I

    .line 151
    .line 152
    iput v3, v0, Ltw0/d;->e:I

    .line 153
    .line 154
    invoke-interface {p1, p2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    if-ne p0, v1, :cond_7

    .line 159
    .line 160
    :goto_4
    return-object v1

    .line 161
    :cond_7
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 162
    .line 163
    return-object p0
.end method
