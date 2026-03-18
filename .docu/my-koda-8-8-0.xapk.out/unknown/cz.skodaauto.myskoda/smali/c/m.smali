.class public final Lc/m;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Z

.field public synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc/m;->d:I

    iput-object p1, p0, Lc/m;->f:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p4, p0, Lc/m;->d:I

    iput-object p1, p0, Lc/m;->f:Ljava/lang/Object;

    iput-boolean p2, p0, Lc/m;->e:Z

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(ZLkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lc/m;->d:I

    .line 3
    iput-boolean p1, p0, Lc/m;->e:Z

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lc/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lc/m;

    .line 7
    .line 8
    iget-object p0, p0, Lc/m;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lu31/h;

    .line 11
    .line 12
    const/16 v1, 0x9

    .line 13
    .line 14
    invoke-direct {v0, p0, p2, v1}, Lc/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    check-cast p1, Ljava/lang/Boolean;

    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    iput-boolean p0, v0, Lc/m;->e:Z

    .line 24
    .line 25
    return-object v0

    .line 26
    :pswitch_0
    new-instance p1, Lc/m;

    .line 27
    .line 28
    iget-object v0, p0, Lc/m;->f:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v0, Ltd/x;

    .line 31
    .line 32
    iget-boolean p0, p0, Lc/m;->e:Z

    .line 33
    .line 34
    const/16 v1, 0x8

    .line 35
    .line 36
    invoke-direct {p1, v0, p0, p2, v1}, Lc/m;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 37
    .line 38
    .line 39
    return-object p1

    .line 40
    :pswitch_1
    new-instance v0, Lc/m;

    .line 41
    .line 42
    iget-object p0, p0, Lc/m;->f:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 45
    .line 46
    const/4 v1, 0x7

    .line 47
    invoke-direct {v0, p0, p2, v1}, Lc/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    check-cast p1, Ljava/lang/Boolean;

    .line 51
    .line 52
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    iput-boolean p0, v0, Lc/m;->e:Z

    .line 57
    .line 58
    return-object v0

    .line 59
    :pswitch_2
    new-instance p1, Lc/m;

    .line 60
    .line 61
    iget-object v0, p0, Lc/m;->f:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v0, Loi/c;

    .line 64
    .line 65
    iget-boolean p0, p0, Lc/m;->e:Z

    .line 66
    .line 67
    const/4 v1, 0x6

    .line 68
    invoke-direct {p1, v0, p0, p2, v1}, Lc/m;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 69
    .line 70
    .line 71
    return-object p1

    .line 72
    :pswitch_3
    new-instance v0, Lc/m;

    .line 73
    .line 74
    iget-object p0, p0, Lc/m;->f:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p0, Lh2/yb;

    .line 77
    .line 78
    const/4 v1, 0x5

    .line 79
    invoke-direct {v0, p0, p2, v1}, Lc/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 80
    .line 81
    .line 82
    check-cast p1, Ljava/lang/Boolean;

    .line 83
    .line 84
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    iput-boolean p0, v0, Lc/m;->e:Z

    .line 89
    .line 90
    return-object v0

    .line 91
    :pswitch_4
    new-instance v0, Lc/m;

    .line 92
    .line 93
    iget-object p0, p0, Lc/m;->f:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p0, Lhg/x;

    .line 96
    .line 97
    const/4 v1, 0x4

    .line 98
    invoke-direct {v0, p0, p2, v1}, Lc/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 99
    .line 100
    .line 101
    check-cast p1, Ljava/lang/Boolean;

    .line 102
    .line 103
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    iput-boolean p0, v0, Lc/m;->e:Z

    .line 108
    .line 109
    return-object v0

    .line 110
    :pswitch_5
    new-instance v0, Lc/m;

    .line 111
    .line 112
    iget-boolean p0, p0, Lc/m;->e:Z

    .line 113
    .line 114
    invoke-direct {v0, p0, p2}, Lc/m;-><init>(ZLkotlin/coroutines/Continuation;)V

    .line 115
    .line 116
    .line 117
    iput-object p1, v0, Lc/m;->f:Ljava/lang/Object;

    .line 118
    .line 119
    return-object v0

    .line 120
    :pswitch_6
    new-instance v0, Lc/m;

    .line 121
    .line 122
    iget-object p0, p0, Lc/m;->f:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast p0, Landroid/content/Context;

    .line 125
    .line 126
    const/4 v1, 0x2

    .line 127
    invoke-direct {v0, p0, p2, v1}, Lc/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 128
    .line 129
    .line 130
    check-cast p1, Ljava/lang/Boolean;

    .line 131
    .line 132
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 133
    .line 134
    .line 135
    move-result p0

    .line 136
    iput-boolean p0, v0, Lc/m;->e:Z

    .line 137
    .line 138
    return-object v0

    .line 139
    :pswitch_7
    new-instance v0, Lc/m;

    .line 140
    .line 141
    iget-object p0, p0, Lc/m;->f:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast p0, Lc00/i0;

    .line 144
    .line 145
    const/4 v1, 0x1

    .line 146
    invoke-direct {v0, p0, p2, v1}, Lc/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 147
    .line 148
    .line 149
    check-cast p1, Ljava/lang/Boolean;

    .line 150
    .line 151
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 152
    .line 153
    .line 154
    move-result p0

    .line 155
    iput-boolean p0, v0, Lc/m;->e:Z

    .line 156
    .line 157
    return-object v0

    .line 158
    :pswitch_8
    new-instance p1, Lc/m;

    .line 159
    .line 160
    iget-object v0, p0, Lc/m;->f:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast v0, Lc/l;

    .line 163
    .line 164
    iget-boolean p0, p0, Lc/m;->e:Z

    .line 165
    .line 166
    const/4 v1, 0x0

    .line 167
    invoke-direct {p1, v0, p0, p2, v1}, Lc/m;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 168
    .line 169
    .line 170
    return-object p1

    .line 171
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lc/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 12
    .line 13
    invoke-virtual {p0, p1, p2}, Lc/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lc/m;

    .line 18
    .line 19
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lc/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    return-object p1

    .line 25
    :pswitch_0
    check-cast p1, Lvy0/b0;

    .line 26
    .line 27
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    invoke-virtual {p0, p1, p2}, Lc/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Lc/m;

    .line 34
    .line 35
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Lc/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    return-object p1

    .line 41
    :pswitch_1
    check-cast p1, Ljava/lang/Boolean;

    .line 42
    .line 43
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 44
    .line 45
    .line 46
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 47
    .line 48
    invoke-virtual {p0, p1, p2}, Lc/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    check-cast p0, Lc/m;

    .line 53
    .line 54
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 55
    .line 56
    invoke-virtual {p0, p1}, Lc/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    return-object p1

    .line 60
    :pswitch_2
    check-cast p1, Lvy0/b0;

    .line 61
    .line 62
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    invoke-virtual {p0, p1, p2}, Lc/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    check-cast p0, Lc/m;

    .line 69
    .line 70
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 71
    .line 72
    invoke-virtual {p0, p1}, Lc/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    return-object p1

    .line 76
    :pswitch_3
    check-cast p1, Ljava/lang/Boolean;

    .line 77
    .line 78
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 79
    .line 80
    .line 81
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 82
    .line 83
    invoke-virtual {p0, p1, p2}, Lc/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    check-cast p0, Lc/m;

    .line 88
    .line 89
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 90
    .line 91
    invoke-virtual {p0, p1}, Lc/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    return-object p1

    .line 95
    :pswitch_4
    check-cast p1, Ljava/lang/Boolean;

    .line 96
    .line 97
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 98
    .line 99
    .line 100
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 101
    .line 102
    invoke-virtual {p0, p1, p2}, Lc/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    check-cast p0, Lc/m;

    .line 107
    .line 108
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    invoke-virtual {p0, p1}, Lc/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    return-object p1

    .line 114
    :pswitch_5
    check-cast p1, Lkw0/c;

    .line 115
    .line 116
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 117
    .line 118
    invoke-virtual {p0, p1, p2}, Lc/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    check-cast p0, Lc/m;

    .line 123
    .line 124
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 125
    .line 126
    invoke-virtual {p0, p1}, Lc/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    return-object p1

    .line 130
    :pswitch_6
    check-cast p1, Ljava/lang/Boolean;

    .line 131
    .line 132
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 133
    .line 134
    .line 135
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 136
    .line 137
    invoke-virtual {p0, p1, p2}, Lc/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    check-cast p0, Lc/m;

    .line 142
    .line 143
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 144
    .line 145
    invoke-virtual {p0, p1}, Lc/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    return-object p1

    .line 149
    :pswitch_7
    check-cast p1, Ljava/lang/Boolean;

    .line 150
    .line 151
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 152
    .line 153
    .line 154
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 155
    .line 156
    invoke-virtual {p0, p1, p2}, Lc/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    check-cast p0, Lc/m;

    .line 161
    .line 162
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 163
    .line 164
    invoke-virtual {p0, p1}, Lc/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    return-object p1

    .line 168
    :pswitch_8
    check-cast p1, Lvy0/b0;

    .line 169
    .line 170
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 171
    .line 172
    invoke-virtual {p0, p1, p2}, Lc/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    check-cast p0, Lc/m;

    .line 177
    .line 178
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 179
    .line 180
    invoke-virtual {p0, p1}, Lc/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    return-object p1

    .line 184
    nop

    .line 185
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc/m;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    packed-switch v1, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-boolean v1, v0, Lc/m;->e:Z

    .line 11
    .line 12
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    iget-object v0, v0, Lc/m;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lu31/h;

    .line 20
    .line 21
    iget-object v3, v0, Lq41/b;->d:Lyy0/c2;

    .line 22
    .line 23
    :cond_0
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    move-object v4, v0

    .line 28
    check-cast v4, Lu31/i;

    .line 29
    .line 30
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    new-instance v4, Lu31/i;

    .line 34
    .line 35
    invoke-direct {v4, v1}, Lu31/i;-><init>(Z)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v3, v0, v4}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_0

    .line 43
    .line 44
    return-object v2

    .line 45
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 46
    .line 47
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    iget-object v1, v0, Lc/m;->f:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v1, Ltd/x;

    .line 53
    .line 54
    iget-object v3, v1, Ltd/x;->h:Lyy0/c2;

    .line 55
    .line 56
    iget-boolean v8, v0, Lc/m;->e:Z

    .line 57
    .line 58
    :cond_1
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    move-object v12, v0

    .line 63
    check-cast v12, Ltd/t;

    .line 64
    .line 65
    new-instance v13, Ltd/t;

    .line 66
    .line 67
    new-instance v14, Llc/q;

    .line 68
    .line 69
    invoke-direct {v14, v2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    iget-object v4, v1, Ltd/x;->g:Ltd/h;

    .line 73
    .line 74
    iget-object v5, v1, Ltd/x;->k:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v6, v1, Ltd/x;->l:Ljava/lang/String;

    .line 77
    .line 78
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 79
    .line 80
    .line 81
    invoke-static {v5, v6}, Ltd/h;->a(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v9

    .line 85
    iget-object v4, v12, Ltd/t;->b:Ltd/p;

    .line 86
    .line 87
    iget-object v5, v4, Ltd/p;->a:Ljava/lang/String;

    .line 88
    .line 89
    iget-boolean v6, v4, Ltd/p;->b:Z

    .line 90
    .line 91
    iget-object v7, v4, Ltd/p;->c:Ljava/util/List;

    .line 92
    .line 93
    iget-object v10, v4, Ltd/p;->f:Ljava/util/List;

    .line 94
    .line 95
    new-instance v4, Ltd/p;

    .line 96
    .line 97
    const/16 v11, 0x40

    .line 98
    .line 99
    invoke-direct/range {v4 .. v11}, Ltd/p;-><init>(Ljava/lang/String;ZLjava/util/List;ZLjava/lang/String;Ljava/util/List;I)V

    .line 100
    .line 101
    .line 102
    iget-object v5, v12, Ltd/t;->d:Ljava/util/Set;

    .line 103
    .line 104
    const/4 v6, 0x4

    .line 105
    invoke-direct {v13, v14, v4, v5, v6}, Ltd/t;-><init>(Llc/q;Ltd/p;Ljava/util/Set;I)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v3, v0, v13}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    if-eqz v0, :cond_1

    .line 113
    .line 114
    return-object v2

    .line 115
    :pswitch_1
    iget-boolean v1, v0, Lc/m;->e:Z

    .line 116
    .line 117
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 118
    .line 119
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    iget-object v0, v0, Lc/m;->f:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 125
    .line 126
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->getRpaDispatcher()Ln71/a;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    new-instance v4, Lc/d;

    .line 131
    .line 132
    const/16 v5, 0xd

    .line 133
    .line 134
    invoke-direct {v4, v0, v1, v5}, Lc/d;-><init>(Ljava/lang/Object;ZI)V

    .line 135
    .line 136
    .line 137
    invoke-static {v3, v4}, Ln71/a;->a(Ln71/a;Lay0/a;)V

    .line 138
    .line 139
    .line 140
    return-object v2

    .line 141
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 142
    .line 143
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    iget-object v1, v0, Lc/m;->f:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v1, Loi/c;

    .line 149
    .line 150
    iget-boolean v0, v0, Lc/m;->e:Z

    .line 151
    .line 152
    iget-object v1, v1, Loi/c;->e:Lyy0/c2;

    .line 153
    .line 154
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 159
    .line 160
    .line 161
    const/4 v3, 0x0

    .line 162
    invoke-virtual {v1, v3, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    return-object v2

    .line 166
    :pswitch_3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 167
    .line 168
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    iget-boolean v1, v0, Lc/m;->e:Z

    .line 172
    .line 173
    if-nez v1, :cond_2

    .line 174
    .line 175
    iget-object v0, v0, Lc/m;->f:Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v0, Lh2/yb;

    .line 178
    .line 179
    invoke-virtual {v0}, Lh2/yb;->a()V

    .line 180
    .line 181
    .line 182
    :cond_2
    return-object v2

    .line 183
    :pswitch_4
    iget-object v1, v0, Lc/m;->f:Ljava/lang/Object;

    .line 184
    .line 185
    check-cast v1, Lhg/x;

    .line 186
    .line 187
    iget-object v1, v1, Lhg/x;->k:Lyy0/c2;

    .line 188
    .line 189
    iget-boolean v0, v0, Lc/m;->e:Z

    .line 190
    .line 191
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 192
    .line 193
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 194
    .line 195
    .line 196
    if-eqz v0, :cond_4

    .line 197
    .line 198
    :cond_3
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    move-object v3, v0

    .line 203
    check-cast v3, Lhg/y;

    .line 204
    .line 205
    const/4 v11, 0x0

    .line 206
    const/16 v12, 0x3fb

    .line 207
    .line 208
    const/4 v4, 0x0

    .line 209
    const/4 v5, 0x0

    .line 210
    const/4 v6, 0x0

    .line 211
    const/4 v7, 0x0

    .line 212
    const/4 v8, 0x0

    .line 213
    const/4 v9, 0x0

    .line 214
    const/4 v10, 0x0

    .line 215
    invoke-static/range {v3 .. v12}, Lhg/y;->a(Lhg/y;ZLhg/c;Ljava/util/ArrayList;ZZZLjava/lang/String;ZI)Lhg/y;

    .line 216
    .line 217
    .line 218
    move-result-object v3

    .line 219
    invoke-virtual {v1, v0, v3}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    move-result v0

    .line 223
    if-eqz v0, :cond_3

    .line 224
    .line 225
    goto :goto_0

    .line 226
    :cond_4
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v0

    .line 230
    move-object v3, v0

    .line 231
    check-cast v3, Lhg/y;

    .line 232
    .line 233
    const/4 v11, 0x0

    .line 234
    const/16 v12, 0x3fe

    .line 235
    .line 236
    const/4 v4, 0x0

    .line 237
    const/4 v5, 0x0

    .line 238
    const/4 v6, 0x0

    .line 239
    const/4 v7, 0x0

    .line 240
    const/4 v8, 0x0

    .line 241
    const/4 v9, 0x0

    .line 242
    const/4 v10, 0x0

    .line 243
    invoke-static/range {v3 .. v12}, Lhg/y;->a(Lhg/y;ZLhg/c;Ljava/util/ArrayList;ZZZLjava/lang/String;ZI)Lhg/y;

    .line 244
    .line 245
    .line 246
    move-result-object v3

    .line 247
    invoke-virtual {v1, v0, v3}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v0

    .line 251
    if-eqz v0, :cond_4

    .line 252
    .line 253
    :goto_0
    return-object v2

    .line 254
    :pswitch_5
    iget-object v1, v0, Lc/m;->f:Ljava/lang/Object;

    .line 255
    .line 256
    check-cast v1, Lkw0/c;

    .line 257
    .line 258
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 259
    .line 260
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 261
    .line 262
    .line 263
    iget-object v1, v1, Lkw0/c;->f:Lvw0/d;

    .line 264
    .line 265
    sget-object v3, Lfw0/s;->c:Lvw0/a;

    .line 266
    .line 267
    iget-boolean v0, v0, Lc/m;->e:Z

    .line 268
    .line 269
    new-instance v4, Lfw0/n;

    .line 270
    .line 271
    const/4 v5, 0x0

    .line 272
    invoke-direct {v4, v5, v0}, Lfw0/n;-><init>(IZ)V

    .line 273
    .line 274
    .line 275
    invoke-virtual {v1, v3, v4}, Lvw0/d;->a(Lvw0/a;Lay0/a;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    return-object v2

    .line 279
    :pswitch_6
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 280
    .line 281
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 282
    .line 283
    .line 284
    iget-boolean v1, v0, Lc/m;->e:Z

    .line 285
    .line 286
    iget-object v0, v0, Lc/m;->f:Ljava/lang/Object;

    .line 287
    .line 288
    check-cast v0, Landroid/content/Context;

    .line 289
    .line 290
    const-class v3, Landroidx/work/impl/background/systemalarm/RescheduleReceiver;

    .line 291
    .line 292
    invoke-static {v0, v3, v1}, Lnb/f;->a(Landroid/content/Context;Ljava/lang/Class;Z)V

    .line 293
    .line 294
    .line 295
    return-object v2

    .line 296
    :pswitch_7
    iget-boolean v1, v0, Lc/m;->e:Z

    .line 297
    .line 298
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 299
    .line 300
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    iget-object v0, v0, Lc/m;->f:Ljava/lang/Object;

    .line 304
    .line 305
    check-cast v0, Lc00/i0;

    .line 306
    .line 307
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 308
    .line 309
    .line 310
    move-result-object v3

    .line 311
    move-object v4, v3

    .line 312
    check-cast v4, Lc00/d0;

    .line 313
    .line 314
    const/16 v25, 0x0

    .line 315
    .line 316
    const v26, 0x3fefff

    .line 317
    .line 318
    .line 319
    const/4 v5, 0x0

    .line 320
    const/4 v6, 0x0

    .line 321
    const/4 v7, 0x0

    .line 322
    const/4 v8, 0x0

    .line 323
    const/4 v9, 0x0

    .line 324
    const/4 v10, 0x0

    .line 325
    const/4 v11, 0x0

    .line 326
    const/4 v12, 0x0

    .line 327
    const/4 v13, 0x0

    .line 328
    const/4 v14, 0x0

    .line 329
    const/4 v15, 0x0

    .line 330
    const/16 v16, 0x0

    .line 331
    .line 332
    const/16 v18, 0x0

    .line 333
    .line 334
    const/16 v19, 0x0

    .line 335
    .line 336
    const/16 v20, 0x0

    .line 337
    .line 338
    const/16 v21, 0x0

    .line 339
    .line 340
    const/16 v22, 0x0

    .line 341
    .line 342
    const/16 v23, 0x0

    .line 343
    .line 344
    const/16 v24, 0x0

    .line 345
    .line 346
    move/from16 v17, v1

    .line 347
    .line 348
    invoke-static/range {v4 .. v26}, Lc00/d0;->a(Lc00/d0;Lc00/z;ZZLc00/a0;ZZZLc00/y;Lc00/c0;Lc00/b0;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Llf0/i;ZZZZZZI)Lc00/d0;

    .line 349
    .line 350
    .line 351
    move-result-object v1

    .line 352
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 353
    .line 354
    .line 355
    return-object v2

    .line 356
    :pswitch_8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 357
    .line 358
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 359
    .line 360
    .line 361
    iget-object v1, v0, Lc/m;->f:Ljava/lang/Object;

    .line 362
    .line 363
    check-cast v1, Lc/l;

    .line 364
    .line 365
    iget-boolean v0, v0, Lc/m;->e:Z

    .line 366
    .line 367
    if-nez v0, :cond_5

    .line 368
    .line 369
    iget-boolean v3, v1, Lc/l;->e:Z

    .line 370
    .line 371
    if-nez v3, :cond_5

    .line 372
    .line 373
    invoke-virtual {v1}, Lb/a0;->isEnabled()Z

    .line 374
    .line 375
    .line 376
    move-result v3

    .line 377
    if-eqz v3, :cond_5

    .line 378
    .line 379
    iget-object v3, v1, Lc/l;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 380
    .line 381
    if-eqz v3, :cond_5

    .line 382
    .line 383
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/i4;->l()V

    .line 384
    .line 385
    .line 386
    :cond_5
    invoke-virtual {v1, v0}, Lb/a0;->setEnabled(Z)V

    .line 387
    .line 388
    .line 389
    return-object v2

    .line 390
    nop

    .line 391
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
