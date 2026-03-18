.class public final Lu40/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ls40/d;

.field public final b:Lfg0/d;

.field public final c:Lkf0/b0;


# direct methods
.method public constructor <init>(Ls40/d;Lfg0/d;Lkf0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu40/v;->a:Ls40/d;

    .line 5
    .line 6
    iput-object p2, p0, Lu40/v;->b:Lfg0/d;

    .line 7
    .line 8
    iput-object p3, p0, Lu40/v;->c:Lkf0/b0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lu40/t;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lu40/v;->b(Lu40/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lu40/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Lu40/u;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lu40/u;

    .line 11
    .line 12
    iget v3, v2, Lu40/u;->h:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lu40/u;->h:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lu40/u;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lu40/u;-><init>(Lu40/v;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lu40/u;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lu40/u;->h:I

    .line 34
    .line 35
    const/4 v5, 0x2

    .line 36
    const/4 v6, 0x1

    .line 37
    if-eqz v4, :cond_3

    .line 38
    .line 39
    if-eq v4, v6, :cond_2

    .line 40
    .line 41
    if-ne v4, v5, :cond_1

    .line 42
    .line 43
    iget-object v3, v2, Lu40/u;->e:Lgg0/a;

    .line 44
    .line 45
    iget-object v2, v2, Lu40/u;->d:Lu40/t;

    .line 46
    .line 47
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    goto :goto_3

    .line 51
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v0

    .line 59
    :cond_2
    iget-object v4, v2, Lu40/u;->d:Lu40/t;

    .line 60
    .line 61
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iget-object v1, v0, Lu40/v;->b:Lfg0/d;

    .line 69
    .line 70
    invoke-virtual {v1}, Lfg0/d;->invoke()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    check-cast v1, Lyy0/i;

    .line 75
    .line 76
    move-object/from16 v4, p1

    .line 77
    .line 78
    iput-object v4, v2, Lu40/u;->d:Lu40/t;

    .line 79
    .line 80
    iput v6, v2, Lu40/u;->h:I

    .line 81
    .line 82
    invoke-static {v1, v2}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    if-ne v1, v3, :cond_4

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_4
    :goto_1
    check-cast v1, Lgg0/a;

    .line 90
    .line 91
    iget-object v6, v0, Lu40/v;->c:Lkf0/b0;

    .line 92
    .line 93
    invoke-virtual {v6}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v6

    .line 97
    check-cast v6, Lyy0/i;

    .line 98
    .line 99
    iput-object v4, v2, Lu40/u;->d:Lu40/t;

    .line 100
    .line 101
    iput-object v1, v2, Lu40/u;->e:Lgg0/a;

    .line 102
    .line 103
    iput v5, v2, Lu40/u;->h:I

    .line 104
    .line 105
    invoke-static {v6, v2}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    if-ne v2, v3, :cond_5

    .line 110
    .line 111
    :goto_2
    return-object v3

    .line 112
    :cond_5
    move-object v3, v1

    .line 113
    move-object v1, v2

    .line 114
    move-object v2, v4

    .line 115
    :goto_3
    if-eqz v1, :cond_8

    .line 116
    .line 117
    check-cast v1, Lss0/j0;

    .line 118
    .line 119
    iget-object v10, v1, Lss0/j0;->d:Ljava/lang/String;

    .line 120
    .line 121
    iget-object v12, v2, Lu40/t;->a:Ljava/lang/String;

    .line 122
    .line 123
    iget-object v9, v2, Lu40/t;->b:Ljava/lang/String;

    .line 124
    .line 125
    iget-object v11, v2, Lu40/t;->c:Ljava/time/OffsetDateTime;

    .line 126
    .line 127
    iget-object v14, v2, Lu40/t;->d:Ljava/lang/String;

    .line 128
    .line 129
    iget-object v13, v2, Lu40/t;->e:Ljava/lang/String;

    .line 130
    .line 131
    const/4 v1, 0x0

    .line 132
    if-eqz v3, :cond_6

    .line 133
    .line 134
    iget-wide v4, v3, Lgg0/a;->a:D

    .line 135
    .line 136
    new-instance v6, Ljava/lang/Double;

    .line 137
    .line 138
    invoke-direct {v6, v4, v5}, Ljava/lang/Double;-><init>(D)V

    .line 139
    .line 140
    .line 141
    move-object v5, v6

    .line 142
    goto :goto_4

    .line 143
    :cond_6
    move-object v5, v1

    .line 144
    :goto_4
    if-eqz v3, :cond_7

    .line 145
    .line 146
    iget-wide v3, v3, Lgg0/a;->b:D

    .line 147
    .line 148
    new-instance v1, Ljava/lang/Double;

    .line 149
    .line 150
    invoke-direct {v1, v3, v4}, Ljava/lang/Double;-><init>(D)V

    .line 151
    .line 152
    .line 153
    :cond_7
    move-object v6, v1

    .line 154
    iget-boolean v8, v2, Lu40/t;->f:Z

    .line 155
    .line 156
    iget-object v7, v0, Lu40/v;->a:Ls40/d;

    .line 157
    .line 158
    const-string v0, "locationId"

    .line 159
    .line 160
    invoke-static {v12, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 164
    .line 165
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-deliveredvehicle-model-LicensePlate$-licensePlate$0"

    .line 169
    .line 170
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    const-string v0, "stopTime"

    .line 174
    .line 175
    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    iget-object v0, v7, Ls40/d;->a:Lxl0/f;

    .line 179
    .line 180
    new-instance v4, Ls40/c;

    .line 181
    .line 182
    const/4 v15, 0x0

    .line 183
    invoke-direct/range {v4 .. v15}, Ls40/c;-><init>(Ljava/lang/Double;Ljava/lang/Double;Ls40/d;ZLjava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 184
    .line 185
    .line 186
    new-instance v1, Lr40/e;

    .line 187
    .line 188
    const/16 v2, 0x1a

    .line 189
    .line 190
    invoke-direct {v1, v2}, Lr40/e;-><init>(I)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v0, v4, v1}, Lxl0/f;->d(Lay0/k;Lay0/k;)Lyy0/m1;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    return-object v0

    .line 198
    :cond_8
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 199
    .line 200
    const-string v1, "Required value was null."

    .line 201
    .line 202
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    throw v0
.end method
