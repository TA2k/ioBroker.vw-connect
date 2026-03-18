.class public final Lgb0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lif0/f0;

.field public final b:Len0/s;

.field public final c:Lrs0/f;


# direct methods
.method public constructor <init>(Lif0/f0;Len0/s;Lrs0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgb0/j;->a:Lif0/f0;

    .line 5
    .line 6
    iput-object p2, p0, Lgb0/j;->b:Len0/s;

    .line 7
    .line 8
    iput-object p3, p0, Lgb0/j;->c:Lrs0/f;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lgb0/j;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p1, Lgb0/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lgb0/i;

    .line 7
    .line 8
    iget v1, v0, Lgb0/i;->f:I

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
    iput v1, v0, Lgb0/i;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lgb0/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lgb0/i;-><init>(Lgb0/j;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lgb0/i;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lgb0/i;->f:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_4

    .line 35
    .line 36
    if-eq v2, v5, :cond_3

    .line 37
    .line 38
    if-eq v2, v4, :cond_2

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto/16 :goto_4

    .line 46
    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object p1, p0, Lgb0/j;->c:Lrs0/f;

    .line 67
    .line 68
    check-cast p1, Lps0/f;

    .line 69
    .line 70
    iget-object p1, p1, Lps0/f;->c:Lyy0/i;

    .line 71
    .line 72
    iput v5, v0, Lgb0/i;->f:I

    .line 73
    .line 74
    invoke-static {p1, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    if-ne p1, v1, :cond_5

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_5
    :goto_1
    check-cast p1, Lss0/d0;

    .line 82
    .line 83
    if-nez p1, :cond_6

    .line 84
    .line 85
    new-instance v5, Lne0/c;

    .line 86
    .line 87
    new-instance v6, Ljava/lang/Exception;

    .line 88
    .line 89
    const-string p0, "There is no selected vehicle id"

    .line 90
    .line 91
    invoke-direct {v6, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    const/4 v9, 0x0

    .line 95
    const/16 v10, 0x1e

    .line 96
    .line 97
    const/4 v7, 0x0

    .line 98
    const/4 v8, 0x0

    .line 99
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 100
    .line 101
    .line 102
    return-object v5

    .line 103
    :cond_6
    instance-of v2, p1, Lss0/j0;

    .line 104
    .line 105
    if-eqz v2, :cond_9

    .line 106
    .line 107
    check-cast p1, Lss0/j0;

    .line 108
    .line 109
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 110
    .line 111
    iput v4, v0, Lgb0/i;->f:I

    .line 112
    .line 113
    iget-object p0, p0, Lgb0/j;->a:Lif0/f0;

    .line 114
    .line 115
    invoke-virtual {p0, p1, v0}, Lif0/f0;->d(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    if-ne p1, v1, :cond_7

    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_7
    :goto_2
    check-cast p1, Lss0/k;

    .line 123
    .line 124
    if-nez p1, :cond_8

    .line 125
    .line 126
    new-instance v0, Lne0/c;

    .line 127
    .line 128
    new-instance v1, Lss0/g0;

    .line 129
    .line 130
    invoke-direct {v1}, Lss0/g0;-><init>()V

    .line 131
    .line 132
    .line 133
    const/4 v4, 0x0

    .line 134
    const/16 v5, 0x1e

    .line 135
    .line 136
    const/4 v2, 0x0

    .line 137
    const/4 v3, 0x0

    .line 138
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 139
    .line 140
    .line 141
    return-object v0

    .line 142
    :cond_8
    new-instance p0, Lne0/e;

    .line 143
    .line 144
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    return-object p0

    .line 148
    :cond_9
    instance-of v2, p1, Lss0/g;

    .line 149
    .line 150
    if-eqz v2, :cond_c

    .line 151
    .line 152
    check-cast p1, Lss0/g;

    .line 153
    .line 154
    iget-object p1, p1, Lss0/g;->d:Ljava/lang/String;

    .line 155
    .line 156
    iput v3, v0, Lgb0/i;->f:I

    .line 157
    .line 158
    iget-object p0, p0, Lgb0/j;->b:Len0/s;

    .line 159
    .line 160
    invoke-virtual {p0, p1, v0}, Len0/s;->c(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object p1

    .line 164
    if-ne p1, v1, :cond_a

    .line 165
    .line 166
    :goto_3
    return-object v1

    .line 167
    :cond_a
    :goto_4
    check-cast p1, Lss0/u;

    .line 168
    .line 169
    if-nez p1, :cond_b

    .line 170
    .line 171
    new-instance v0, Lne0/c;

    .line 172
    .line 173
    new-instance v1, Lss0/g0;

    .line 174
    .line 175
    invoke-direct {v1}, Lss0/g0;-><init>()V

    .line 176
    .line 177
    .line 178
    const/4 v4, 0x0

    .line 179
    const/16 v5, 0x1e

    .line 180
    .line 181
    const/4 v2, 0x0

    .line 182
    const/4 v3, 0x0

    .line 183
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 184
    .line 185
    .line 186
    return-object v0

    .line 187
    :cond_b
    new-instance p0, Lne0/e;

    .line 188
    .line 189
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    return-object p0

    .line 193
    :cond_c
    new-instance p0, La8/r0;

    .line 194
    .line 195
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 196
    .line 197
    .line 198
    throw p0
.end method
