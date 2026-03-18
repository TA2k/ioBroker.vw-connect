.class public final Le60/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Llq0/b;

.field public final b:Lkf0/o;


# direct methods
.method public constructor <init>(Llq0/b;Lkf0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le60/b;->a:Llq0/b;

    .line 5
    .line 6
    iput-object p2, p0, Le60/b;->b:Lkf0/o;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lf60/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Le60/b;->b(Lf60/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lf60/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Le60/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Le60/a;

    .line 7
    .line 8
    iget v1, v0, Le60/a;->g:I

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
    iput v1, v0, Le60/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Le60/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Le60/a;-><init>(Le60/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Le60/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Le60/a;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto/16 :goto_5

    .line 43
    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    iget-object p1, v0, Le60/a;->d:Lf60/a;

    .line 53
    .line 54
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iput-object p1, v0, Le60/a;->d:Lf60/a;

    .line 62
    .line 63
    iput v4, v0, Le60/a;->g:I

    .line 64
    .line 65
    iget-object p2, p0, Le60/b;->b:Lkf0/o;

    .line 66
    .line 67
    invoke-virtual {p2, v0}, Lkf0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    if-ne p2, v1, :cond_4

    .line 72
    .line 73
    goto :goto_4

    .line 74
    :cond_4
    :goto_1
    check-cast p2, Lne0/t;

    .line 75
    .line 76
    instance-of v2, p2, Lne0/c;

    .line 77
    .line 78
    if-eqz v2, :cond_5

    .line 79
    .line 80
    check-cast p2, Lne0/c;

    .line 81
    .line 82
    return-object p2

    .line 83
    :cond_5
    instance-of v2, p2, Lne0/e;

    .line 84
    .line 85
    if-eqz v2, :cond_b

    .line 86
    .line 87
    check-cast p2, Lne0/e;

    .line 88
    .line 89
    iget-object p2, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast p2, Lss0/j0;

    .line 92
    .line 93
    iget-object p2, p2, Lss0/j0;->d:Ljava/lang/String;

    .line 94
    .line 95
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    if-eqz v2, :cond_7

    .line 100
    .line 101
    if-ne v2, v4, :cond_6

    .line 102
    .line 103
    const-string v2, "honk_and_flash"

    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_6
    new-instance p0, La8/r0;

    .line 107
    .line 108
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :cond_7
    const-string v2, "flash"

    .line 113
    .line 114
    :goto_2
    sget-object v5, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Maps:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 115
    .line 116
    invoke-virtual {v5}, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->getLink-Q-Ouzws()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v5

    .line 120
    const-string v6, "action"

    .line 121
    .line 122
    invoke-static {v5, v6, v2}, Lhf0/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    const-string v5, "vin"

    .line 127
    .line 128
    invoke-static {v2, v5, p2}, Lhf0/d;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object p2

    .line 132
    new-instance v2, Lmq0/a;

    .line 133
    .line 134
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 135
    .line 136
    .line 137
    move-result p1

    .line 138
    if-eqz p1, :cond_9

    .line 139
    .line 140
    if-ne p1, v4, :cond_8

    .line 141
    .line 142
    sget-object p1, Lmq0/b;->f:Lmq0/b;

    .line 143
    .line 144
    goto :goto_3

    .line 145
    :cond_8
    new-instance p0, La8/r0;

    .line 146
    .line 147
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 148
    .line 149
    .line 150
    throw p0

    .line 151
    :cond_9
    sget-object p1, Lmq0/b;->g:Lmq0/b;

    .line 152
    .line 153
    :goto_3
    invoke-direct {v2, p1, p2}, Lmq0/a;-><init>(Lmq0/b;Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    const/4 p1, 0x0

    .line 157
    iput-object p1, v0, Le60/a;->d:Lf60/a;

    .line 158
    .line 159
    iput v3, v0, Le60/a;->g:I

    .line 160
    .line 161
    iget-object p0, p0, Le60/b;->a:Llq0/b;

    .line 162
    .line 163
    invoke-virtual {p0, v2, v0}, Llq0/b;->b(Lmq0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    if-ne p0, v1, :cond_a

    .line 168
    .line 169
    :goto_4
    return-object v1

    .line 170
    :cond_a
    :goto_5
    new-instance p0, Lne0/e;

    .line 171
    .line 172
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 173
    .line 174
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    return-object p0

    .line 178
    :cond_b
    new-instance p0, La8/r0;

    .line 179
    .line 180
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 181
    .line 182
    .line 183
    throw p0
.end method
