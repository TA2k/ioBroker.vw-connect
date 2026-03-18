.class public final Lpg/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lyj/b;

.field public final b:Lmg/b;

.field public final c:Ljava/lang/String;

.field public final d:Llg/h;

.field public final e:Lyi/a;


# direct methods
.method public constructor <init>(Lyj/b;Lmg/b;Ljava/lang/String;Llg/h;Lyi/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpg/c;->a:Lyj/b;

    .line 5
    .line 6
    iput-object p2, p0, Lpg/c;->b:Lmg/b;

    .line 7
    .line 8
    iput-object p3, p0, Lpg/c;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lpg/c;->d:Llg/h;

    .line 11
    .line 12
    iput-object p5, p0, Lpg/c;->e:Lyi/a;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p1, Lpg/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lpg/b;

    .line 7
    .line 8
    iget v1, v0, Lpg/b;->f:I

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
    iput v1, v0, Lpg/b;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpg/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lpg/b;-><init>(Lpg/c;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lpg/b;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpg/b;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    check-cast p1, Llx0/o;

    .line 40
    .line 41
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 42
    .line 43
    goto/16 :goto_7

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    iget-object p1, p0, Lpg/c;->b:Lmg/b;

    .line 57
    .line 58
    iget-object v2, p1, Lmg/b;->b:Lkg/p0;

    .line 59
    .line 60
    iget-object v6, v2, Lkg/p0;->d:Ljava/lang/String;

    .line 61
    .line 62
    iget-object v2, p1, Lmg/b;->c:Lac/e;

    .line 63
    .line 64
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    invoke-static {v2}, Lac/f;->a(Lac/e;)Lac/c;

    .line 68
    .line 69
    .line 70
    move-result-object v7

    .line 71
    iget-object v4, p1, Lmg/b;->d:Log/i;

    .line 72
    .line 73
    sget-object v5, Log/i;->f:Log/i;

    .line 74
    .line 75
    if-eq v4, v5, :cond_3

    .line 76
    .line 77
    move v5, v3

    .line 78
    goto :goto_1

    .line 79
    :cond_3
    const/4 v5, 0x0

    .line 80
    :goto_1
    const/4 v8, -0x1

    .line 81
    if-nez v4, :cond_4

    .line 82
    .line 83
    move v4, v8

    .line 84
    goto :goto_2

    .line 85
    :cond_4
    sget-object v9, Lpg/d;->a:[I

    .line 86
    .line 87
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 88
    .line 89
    .line 90
    move-result v4

    .line 91
    aget v4, v9, v4

    .line 92
    .line 93
    :goto_2
    const/4 v9, 0x0

    .line 94
    if-eq v4, v8, :cond_5

    .line 95
    .line 96
    if-eq v4, v3, :cond_5

    .line 97
    .line 98
    const/4 v8, 0x2

    .line 99
    if-eq v4, v8, :cond_7

    .line 100
    .line 101
    const/4 v8, 0x3

    .line 102
    if-ne v4, v8, :cond_6

    .line 103
    .line 104
    iget-object v4, p1, Lmg/b;->e:Lac/e;

    .line 105
    .line 106
    if-eqz v4, :cond_5

    .line 107
    .line 108
    invoke-static {v4}, Lac/f;->a(Lac/e;)Lac/c;

    .line 109
    .line 110
    .line 111
    move-result-object v4

    .line 112
    goto :goto_3

    .line 113
    :cond_5
    move-object v4, v9

    .line 114
    goto :goto_3

    .line 115
    :cond_6
    new-instance p0, La8/r0;

    .line 116
    .line 117
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 118
    .line 119
    .line 120
    throw p0

    .line 121
    :cond_7
    invoke-static {v2}, Lac/f;->a(Lac/e;)Lac/c;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    :goto_3
    iget-object p1, p1, Lmg/b;->a:Ljava/util/List;

    .line 126
    .line 127
    check-cast p1, Ljava/lang/Iterable;

    .line 128
    .line 129
    new-instance v8, Ljava/util/ArrayList;

    .line 130
    .line 131
    const/16 v10, 0xa

    .line 132
    .line 133
    invoke-static {p1, v10}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 134
    .line 135
    .line 136
    move-result v10

    .line 137
    invoke-direct {v8, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 138
    .line 139
    .line 140
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    :goto_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 145
    .line 146
    .line 147
    move-result v10

    .line 148
    if-eqz v10, :cond_8

    .line 149
    .line 150
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v10

    .line 154
    check-cast v10, Ldc/w;

    .line 155
    .line 156
    new-instance v11, Lkg/x;

    .line 157
    .line 158
    iget-object v10, v10, Ldc/w;->e:Ljava/lang/String;

    .line 159
    .line 160
    invoke-direct {v11, v10}, Lkg/x;-><init>(Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    goto :goto_4

    .line 167
    :cond_8
    iget-object p1, v2, Lac/e;->l:Ljava/lang/String;

    .line 168
    .line 169
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 170
    .line 171
    .line 172
    move-result v2

    .line 173
    if-nez v2, :cond_9

    .line 174
    .line 175
    move-object v10, p1

    .line 176
    :goto_5
    move-object v9, v4

    .line 177
    goto :goto_6

    .line 178
    :cond_9
    move-object v10, v9

    .line 179
    goto :goto_5

    .line 180
    :goto_6
    new-instance v4, Lkg/u;

    .line 181
    .line 182
    iget-object v11, p0, Lpg/c;->c:Ljava/lang/String;

    .line 183
    .line 184
    invoke-direct/range {v4 .. v11}, Lkg/u;-><init>(ZLjava/lang/String;Lac/c;Ljava/util/ArrayList;Lac/c;Ljava/lang/String;Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    iput v3, v0, Lpg/b;->f:I

    .line 188
    .line 189
    iget-object p1, p0, Lpg/c;->d:Llg/h;

    .line 190
    .line 191
    invoke-virtual {p1, v4, v0}, Llg/h;->b(Lkg/u;Lrx0/c;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object p1

    .line 195
    if-ne p1, v1, :cond_a

    .line 196
    .line 197
    return-object v1

    .line 198
    :cond_a
    :goto_7
    iget-object p0, p0, Lpg/c;->e:Lyi/a;

    .line 199
    .line 200
    check-cast p0, Lmj/k;

    .line 201
    .line 202
    invoke-virtual {p0}, Lmj/k;->b()V

    .line 203
    .line 204
    .line 205
    return-object p1
.end method
