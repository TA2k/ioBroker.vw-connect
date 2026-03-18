.class public final Leh0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Lzg0/a;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lzg0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Leh0/e;->a:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p2, p0, Leh0/e;->b:Lzg0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Intent;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    instance-of v3, v2, Leh0/d;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Leh0/d;

    .line 13
    .line 14
    iget v4, v3, Leh0/d;->g:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Leh0/d;->g:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Leh0/d;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Leh0/d;-><init>(Leh0/e;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Leh0/d;->e:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Leh0/d;->g:I

    .line 36
    .line 37
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    iget-object v7, v0, Leh0/e;->b:Lzg0/a;

    .line 40
    .line 41
    const/4 v8, 0x2

    .line 42
    const/4 v9, 0x1

    .line 43
    const/4 v10, 0x0

    .line 44
    if-eqz v5, :cond_3

    .line 45
    .line 46
    if-eq v5, v9, :cond_2

    .line 47
    .line 48
    if-ne v5, v8, :cond_1

    .line 49
    .line 50
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    goto/16 :goto_5

    .line 54
    .line 55
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 56
    .line 57
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 58
    .line 59
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw v0

    .line 63
    :cond_2
    iget-object v0, v3, Leh0/d;->d:Ljava/lang/String;

    .line 64
    .line 65
    :try_start_0
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 66
    .line 67
    .line 68
    return-object v6

    .line 69
    :catch_0
    move-object v1, v0

    .line 70
    goto :goto_2

    .line 71
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    if-eqz v1, :cond_5

    .line 75
    .line 76
    :try_start_1
    iget-object v0, v0, Leh0/e;->a:Landroid/content/Context;

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    .line 79
    .line 80
    .line 81
    new-instance v0, Lne0/e;

    .line 82
    .line 83
    invoke-direct {v0, v6}, Lne0/e;-><init>(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 84
    .line 85
    .line 86
    move-object/from16 v1, p2

    .line 87
    .line 88
    :try_start_2
    iput-object v1, v3, Leh0/d;->d:Ljava/lang/String;

    .line 89
    .line 90
    iput v9, v3, Leh0/d;->g:I

    .line 91
    .line 92
    sget-object v2, Lge0/b;->a:Lcz0/e;

    .line 93
    .line 94
    new-instance v5, Lyz/b;

    .line 95
    .line 96
    const/4 v9, 0x6

    .line 97
    invoke-direct {v5, v9, v7, v0, v10}, Lyz/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 98
    .line 99
    .line 100
    invoke-static {v2, v5, v3}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    if-ne v0, v4, :cond_4

    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_4
    move-object v0, v6

    .line 108
    :goto_1
    if-ne v0, v4, :cond_7

    .line 109
    .line 110
    goto :goto_4

    .line 111
    :catch_1
    move-object/from16 v1, p2

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_5
    move-object/from16 v1, p2

    .line 115
    .line 116
    const-string v0, "Required value was null."

    .line 117
    .line 118
    new-instance v2, Ljava/lang/IllegalArgumentException;

    .line 119
    .line 120
    invoke-direct {v2, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw v2
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    .line 124
    :catch_2
    :goto_2
    new-instance v11, Lne0/c;

    .line 125
    .line 126
    new-instance v12, Lb0/l;

    .line 127
    .line 128
    const-string v0, "message"

    .line 129
    .line 130
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    invoke-direct {v12, v1, v10}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 134
    .line 135
    .line 136
    const/4 v15, 0x0

    .line 137
    const/16 v16, 0x1e

    .line 138
    .line 139
    const/4 v13, 0x0

    .line 140
    const/4 v14, 0x0

    .line 141
    invoke-direct/range {v11 .. v16}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 142
    .line 143
    .line 144
    iput-object v10, v3, Leh0/d;->d:Ljava/lang/String;

    .line 145
    .line 146
    iput v8, v3, Leh0/d;->g:I

    .line 147
    .line 148
    sget-object v0, Lge0/b;->a:Lcz0/e;

    .line 149
    .line 150
    new-instance v1, Lyz/b;

    .line 151
    .line 152
    const/4 v2, 0x6

    .line 153
    invoke-direct {v1, v2, v7, v11, v10}, Lyz/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 154
    .line 155
    .line 156
    invoke-static {v0, v1, v3}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 161
    .line 162
    if-ne v0, v1, :cond_6

    .line 163
    .line 164
    goto :goto_3

    .line 165
    :cond_6
    move-object v0, v6

    .line 166
    :goto_3
    if-ne v0, v4, :cond_7

    .line 167
    .line 168
    :goto_4
    return-object v4

    .line 169
    :cond_7
    :goto_5
    return-object v6
.end method
