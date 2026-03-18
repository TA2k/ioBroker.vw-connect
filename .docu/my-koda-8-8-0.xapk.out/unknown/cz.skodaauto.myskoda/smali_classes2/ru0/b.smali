.class public final Lru0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lb00/b;

.field public final b:Le60/b;

.field public final c:Lkf0/k;

.field public final d:Llq0/d;


# direct methods
.method public constructor <init>(Lb00/b;Le60/b;Lkf0/k;Llq0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lru0/b;->a:Lb00/b;

    .line 5
    .line 6
    iput-object p2, p0, Lru0/b;->b:Le60/b;

    .line 7
    .line 8
    iput-object p3, p0, Lru0/b;->c:Lkf0/k;

    .line 9
    .line 10
    iput-object p4, p0, Lru0/b;->d:Llq0/d;

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
    invoke-virtual {p0, p2}, Lru0/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lru0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lru0/a;

    .line 7
    .line 8
    iget v1, v0, Lru0/a;->g:I

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
    iput v1, v0, Lru0/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lru0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lru0/a;-><init>(Lru0/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lru0/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lru0/a;->g:I

    .line 30
    .line 31
    iget-object v3, p0, Lru0/b;->b:Le60/b;

    .line 32
    .line 33
    iget-object v4, p0, Lru0/b;->d:Llq0/d;

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x0

    .line 38
    packed-switch v2, :pswitch_data_0

    .line 39
    .line 40
    .line 41
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :pswitch_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    return-object v5

    .line 53
    :pswitch_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto/16 :goto_4

    .line 57
    .line 58
    :pswitch_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    return-object v5

    .line 62
    :pswitch_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_3

    .line 66
    :pswitch_4
    iget-object p0, v0, Lru0/a;->d:Lss0/b;

    .line 67
    .line 68
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    goto :goto_2

    .line 72
    :pswitch_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :pswitch_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    const/4 p1, 0x1

    .line 80
    iput p1, v0, Lru0/a;->g:I

    .line 81
    .line 82
    iget-object p1, p0, Lru0/b;->c:Lkf0/k;

    .line 83
    .line 84
    invoke-virtual {p1, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    if-ne p1, v1, :cond_1

    .line 89
    .line 90
    goto/16 :goto_5

    .line 91
    .line 92
    :cond_1
    :goto_1
    check-cast p1, Lss0/b;

    .line 93
    .line 94
    sget-object v2, Lss0/e;->g:Lss0/e;

    .line 95
    .line 96
    invoke-static {p1, v2}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    sget-object v7, Llf0/i;->j:Llf0/i;

    .line 101
    .line 102
    if-ne v2, v7, :cond_3

    .line 103
    .line 104
    iput-object p1, v0, Lru0/a;->d:Lss0/b;

    .line 105
    .line 106
    const/4 v2, 0x2

    .line 107
    iput v2, v0, Lru0/a;->g:I

    .line 108
    .line 109
    iget-object p0, p0, Lru0/b;->a:Lb00/b;

    .line 110
    .line 111
    invoke-virtual {p0, v5, v0}, Lb00/b;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    if-ne p0, v1, :cond_2

    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_2
    move-object p0, p1

    .line 119
    goto :goto_2

    .line 120
    :cond_3
    sget-object p0, Lmq0/b;->e:Lmq0/b;

    .line 121
    .line 122
    iput-object p1, v0, Lru0/a;->d:Lss0/b;

    .line 123
    .line 124
    const/4 v2, 0x3

    .line 125
    iput v2, v0, Lru0/a;->g:I

    .line 126
    .line 127
    invoke-virtual {v4, p0, v0}, Llq0/d;->b(Lmq0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    if-ne p0, v1, :cond_2

    .line 132
    .line 133
    goto :goto_5

    .line 134
    :goto_2
    sget-object p1, Lss0/e;->S:Lss0/e;

    .line 135
    .line 136
    invoke-static {p0, p1}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    sget-object p1, Llf0/i;->j:Llf0/i;

    .line 141
    .line 142
    if-ne p0, p1, :cond_5

    .line 143
    .line 144
    sget-object p0, Lf60/a;->e:Lf60/a;

    .line 145
    .line 146
    iput-object v6, v0, Lru0/a;->d:Lss0/b;

    .line 147
    .line 148
    const/4 p1, 0x4

    .line 149
    iput p1, v0, Lru0/a;->g:I

    .line 150
    .line 151
    invoke-virtual {v3, p0, v0}, Le60/b;->b(Lf60/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    if-ne p0, v1, :cond_4

    .line 156
    .line 157
    goto :goto_5

    .line 158
    :cond_4
    :goto_3
    sget-object p0, Lf60/a;->d:Lf60/a;

    .line 159
    .line 160
    iput-object v6, v0, Lru0/a;->d:Lss0/b;

    .line 161
    .line 162
    const/4 p1, 0x5

    .line 163
    iput p1, v0, Lru0/a;->g:I

    .line 164
    .line 165
    invoke-virtual {v3, p0, v0}, Le60/b;->b(Lf60/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    if-ne p0, v1, :cond_7

    .line 170
    .line 171
    goto :goto_5

    .line 172
    :cond_5
    sget-object p0, Lmq0/b;->f:Lmq0/b;

    .line 173
    .line 174
    iput-object v6, v0, Lru0/a;->d:Lss0/b;

    .line 175
    .line 176
    const/4 p1, 0x6

    .line 177
    iput p1, v0, Lru0/a;->g:I

    .line 178
    .line 179
    invoke-virtual {v4, p0, v0}, Llq0/d;->b(Lmq0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    if-ne p0, v1, :cond_6

    .line 184
    .line 185
    goto :goto_5

    .line 186
    :cond_6
    :goto_4
    sget-object p0, Lmq0/b;->g:Lmq0/b;

    .line 187
    .line 188
    iput-object v6, v0, Lru0/a;->d:Lss0/b;

    .line 189
    .line 190
    const/4 p1, 0x7

    .line 191
    iput p1, v0, Lru0/a;->g:I

    .line 192
    .line 193
    invoke-virtual {v4, p0, v0}, Llq0/d;->b(Lmq0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    if-ne p0, v1, :cond_7

    .line 198
    .line 199
    :goto_5
    return-object v1

    .line 200
    :cond_7
    return-object v5

    .line 201
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
