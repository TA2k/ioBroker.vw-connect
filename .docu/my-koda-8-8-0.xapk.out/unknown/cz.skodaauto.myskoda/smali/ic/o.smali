.class public final Lic/o;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lic/q;


# direct methods
.method public synthetic constructor <init>(Lic/q;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lic/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lic/o;->f:Lic/q;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lic/o;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lic/o;

    .line 7
    .line 8
    iget-object p0, p0, Lic/o;->f:Lic/q;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lic/o;-><init>(Lic/q;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lic/o;

    .line 16
    .line 17
    iget-object p0, p0, Lic/o;->f:Lic/q;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lic/o;-><init>(Lic/q;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lic/o;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lic/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lic/o;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lic/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lic/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lic/o;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lic/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lic/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lic/o;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object v3, p0, Lic/o;->f:Lic/q;

    .line 12
    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v2, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, v3, Lic/q;->m:Lyy0/c2;

    .line 33
    .line 34
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    check-cast p1, Lac/a0;

    .line 42
    .line 43
    iget-object p1, p1, Lac/a0;->e:Ljava/lang/String;

    .line 44
    .line 45
    const-string v1, "SELECTED: "

    .line 46
    .line 47
    invoke-static {v1, p1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    sget-object v4, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 52
    .line 53
    invoke-virtual {v4, v1}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    iget-object v1, v3, Lic/q;->g:Lag/c;

    .line 57
    .line 58
    iput v2, p0, Lic/o;->e:I

    .line 59
    .line 60
    invoke-virtual {v1, p1, p0}, Lag/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    if-ne p1, v0, :cond_2

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    :goto_0
    check-cast p1, Llx0/o;

    .line 68
    .line 69
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 70
    .line 71
    instance-of p1, p0, Llx0/n;

    .line 72
    .line 73
    if-nez p1, :cond_3

    .line 74
    .line 75
    move-object p1, p0

    .line 76
    check-cast p1, Ldc/t;

    .line 77
    .line 78
    invoke-static {v3, p1}, Lic/q;->b(Lic/q;Ldc/t;)V

    .line 79
    .line 80
    .line 81
    :cond_3
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    if-eqz p0, :cond_4

    .line 86
    .line 87
    invoke-static {v3, p0}, Lic/q;->a(Lic/q;Ljava/lang/Throwable;)V

    .line 88
    .line 89
    .line 90
    :cond_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    :goto_1
    return-object v0

    .line 93
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 94
    .line 95
    iget v1, p0, Lic/o;->e:I

    .line 96
    .line 97
    const/4 v2, 0x1

    .line 98
    iget-object v3, p0, Lic/o;->f:Lic/q;

    .line 99
    .line 100
    if-eqz v1, :cond_6

    .line 101
    .line 102
    if-ne v1, v2, :cond_5

    .line 103
    .line 104
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 109
    .line 110
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 111
    .line 112
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    iget-object p1, v3, Lic/q;->k:Lyy0/c2;

    .line 120
    .line 121
    new-instance v1, Llc/q;

    .line 122
    .line 123
    sget-object v4, Llc/a;->c:Llc/c;

    .line 124
    .line 125
    invoke-direct {v1, v4}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 129
    .line 130
    .line 131
    const/4 v4, 0x0

    .line 132
    invoke-virtual {p1, v4, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    iget-object p1, v3, Lic/q;->g:Lag/c;

    .line 136
    .line 137
    iput v2, p0, Lic/o;->e:I

    .line 138
    .line 139
    invoke-virtual {p1, v4, p0}, Lag/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    if-ne p1, v0, :cond_7

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_7
    :goto_2
    check-cast p1, Llx0/o;

    .line 147
    .line 148
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 149
    .line 150
    instance-of p1, p0, Llx0/n;

    .line 151
    .line 152
    if-nez p1, :cond_8

    .line 153
    .line 154
    move-object p1, p0

    .line 155
    check-cast p1, Ldc/t;

    .line 156
    .line 157
    invoke-static {v3, p1}, Lic/q;->b(Lic/q;Ldc/t;)V

    .line 158
    .line 159
    .line 160
    :cond_8
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    if-eqz p0, :cond_9

    .line 165
    .line 166
    invoke-static {v3, p0}, Lic/q;->a(Lic/q;Ljava/lang/Throwable;)V

    .line 167
    .line 168
    .line 169
    :cond_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 170
    .line 171
    :goto_3
    return-object v0

    .line 172
    nop

    .line 173
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
