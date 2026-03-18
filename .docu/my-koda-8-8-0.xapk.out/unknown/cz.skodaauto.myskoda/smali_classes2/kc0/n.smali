.class public final Lkc0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lcu0/a;


# direct methods
.method public constructor <init>(Lcu0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkc0/n;->a:Lcu0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lkc0/n;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lkc0/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lkc0/m;

    .line 7
    .line 8
    iget v1, v0, Lkc0/m;->f:I

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
    iput v1, v0, Lkc0/m;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkc0/m;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lkc0/m;-><init>(Lkc0/n;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lkc0/m;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkc0/m;->f:I

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
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    :try_start_1
    iget-object p0, p0, Lkc0/n;->a:Lcu0/a;

    .line 52
    .line 53
    const-string p1, "auth"

    .line 54
    .line 55
    iput v3, v0, Lkc0/m;->f:I

    .line 56
    .line 57
    iget-object p0, p0, Lcu0/a;->a:Lcu0/h;

    .line 58
    .line 59
    check-cast p0, Lau0/g;

    .line 60
    .line 61
    invoke-virtual {p0, p1, v0}, Lau0/g;->a(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    if-ne p1, v1, :cond_3

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_3
    :goto_1
    check-cast p1, Lne0/t;

    .line 69
    .line 70
    new-instance p0, Ljy/b;

    .line 71
    .line 72
    const/16 v0, 0x17

    .line 73
    .line 74
    invoke-direct {p0, v0}, Ljy/b;-><init>(I)V

    .line 75
    .line 76
    .line 77
    invoke-static {p1, p0}, Lbb/j0;->c(Lne0/t;Lay0/k;)Lne0/t;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    instance-of p1, p0, Lne0/c;

    .line 82
    .line 83
    if-nez p1, :cond_9

    .line 84
    .line 85
    instance-of p1, p0, Lne0/e;

    .line 86
    .line 87
    if-eqz p1, :cond_8

    .line 88
    .line 89
    check-cast p0, Lne0/e;

    .line 90
    .line 91
    iget-object p0, p0, Lne0/e;->a:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast p0, Llx0/l;

    .line 94
    .line 95
    if-eqz p0, :cond_4

    .line 96
    .line 97
    iget-object p0, p0, Llx0/l;->e:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p0, Ljava/lang/String;

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_4
    const/4 p0, 0x0

    .line 103
    :goto_2
    if-eqz p0, :cond_7

    .line 104
    .line 105
    new-instance p1, Lcom/auth0/android/jwt/c;

    .line 106
    .line 107
    invoke-direct {p1, p0}, Lcom/auth0/android/jwt/c;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    const-string p0, "sub"

    .line 111
    .line 112
    invoke-virtual {p1, p0}, Lcom/auth0/android/jwt/c;->b(Ljava/lang/String;)Lcom/auth0/android/jwt/a;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    invoke-virtual {p0}, Lcom/auth0/android/jwt/a;->a()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    if-eqz p0, :cond_6

    .line 121
    .line 122
    const-string v0, "email"

    .line 123
    .line 124
    invoke-virtual {p1, v0}, Lcom/auth0/android/jwt/c;->b(Ljava/lang/String;)Lcom/auth0/android/jwt/a;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    invoke-virtual {p1}, Lcom/auth0/android/jwt/a;->a()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    if-eqz p1, :cond_5

    .line 133
    .line 134
    new-instance v0, Lne0/e;

    .line 135
    .line 136
    new-instance v1, Llc0/n;

    .line 137
    .line 138
    invoke-direct {v1, p0, p1}, Llc0/n;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    invoke-direct {v0, v1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    return-object v0

    .line 145
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 146
    .line 147
    const-string p1, "Unable to get email from connect token. Email value is null."

    .line 148
    .line 149
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    throw p0

    .line 153
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 154
    .line 155
    const-string p1, "Unable to get user id from connect token. UserId value is null."

    .line 156
    .line 157
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    throw p0

    .line 161
    :goto_3
    move-object v1, p0

    .line 162
    goto :goto_4

    .line 163
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 164
    .line 165
    const-string p1, "Unable to get user id from connect token. Id token is not available."

    .line 166
    .line 167
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    throw p0

    .line 171
    :cond_8
    new-instance p0, La8/r0;

    .line 172
    .line 173
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 174
    .line 175
    .line 176
    throw p0

    .line 177
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 178
    .line 179
    const-string p1, "Unable to get user id from remote tokens. Id token is not available."

    .line 180
    .line 181
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    throw p0
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0

    .line 185
    :catch_0
    move-exception v0

    .line 186
    move-object p0, v0

    .line 187
    goto :goto_3

    .line 188
    :goto_4
    new-instance v0, Lne0/c;

    .line 189
    .line 190
    const/4 v4, 0x0

    .line 191
    const/16 v5, 0x1e

    .line 192
    .line 193
    const/4 v2, 0x0

    .line 194
    const/4 v3, 0x0

    .line 195
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 196
    .line 197
    .line 198
    return-object v0
.end method
