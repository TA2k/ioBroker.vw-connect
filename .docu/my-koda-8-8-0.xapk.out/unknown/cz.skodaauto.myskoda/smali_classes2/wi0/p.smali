.class public final Lwi0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwi0/j;

.field public final b:Lui0/f;


# direct methods
.method public constructor <init>(Lwi0/j;Lui0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwi0/p;->a:Lwi0/j;

    .line 5
    .line 6
    iput-object p2, p0, Lwi0/p;->b:Lui0/f;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lwi0/p;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lwi0/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lwi0/o;

    .line 7
    .line 8
    iget v1, v0, Lwi0/o;->g:I

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
    iput v1, v0, Lwi0/o;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwi0/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lwi0/o;-><init>(Lwi0/p;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lwi0/o;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwi0/o;->g:I

    .line 30
    .line 31
    iget-object v3, p0, Lwi0/p;->a:Lwi0/j;

    .line 32
    .line 33
    const/4 v4, 0x3

    .line 34
    const/4 v5, 0x2

    .line 35
    const/4 v6, 0x1

    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    if-eq v2, v6, :cond_3

    .line 39
    .line 40
    if-eq v2, v5, :cond_2

    .line 41
    .line 42
    if-ne v2, v4, :cond_1

    .line 43
    .line 44
    iget-object p0, v0, Lwi0/o;->d:Lne0/e;

    .line 45
    .line 46
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_5

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iput v6, v0, Lwi0/o;->g:I

    .line 70
    .line 71
    move-object p1, v3

    .line 72
    check-cast p1, Lui0/d;

    .line 73
    .line 74
    invoke-virtual {p1, v0}, Lui0/d;->b(Lrx0/c;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    if-ne p1, v1, :cond_5

    .line 79
    .line 80
    goto :goto_4

    .line 81
    :cond_5
    :goto_1
    check-cast p1, Lne0/t;

    .line 82
    .line 83
    instance-of v2, p1, Lne0/e;

    .line 84
    .line 85
    if-eqz v2, :cond_6

    .line 86
    .line 87
    goto :goto_6

    .line 88
    :cond_6
    instance-of p1, p1, Lne0/c;

    .line 89
    .line 90
    if-eqz p1, :cond_b

    .line 91
    .line 92
    iput v5, v0, Lwi0/o;->g:I

    .line 93
    .line 94
    iget-object p0, p0, Lwi0/p;->b:Lui0/f;

    .line 95
    .line 96
    iget-object p1, p0, Lui0/f;->a:Lxl0/f;

    .line 97
    .line 98
    new-instance v2, La90/s;

    .line 99
    .line 100
    const/16 v5, 0x1b

    .line 101
    .line 102
    const/4 v6, 0x0

    .line 103
    invoke-direct {v2, p0, v6, v5}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 104
    .line 105
    .line 106
    sget-object p0, Lui0/e;->d:Lui0/e;

    .line 107
    .line 108
    invoke-virtual {p1, v2, p0, v6, v0}, Lxl0/f;->g(Lay0/k;Lay0/k;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    if-ne p1, v1, :cond_7

    .line 113
    .line 114
    goto :goto_4

    .line 115
    :cond_7
    :goto_2
    move-object p0, p1

    .line 116
    check-cast p0, Lne0/t;

    .line 117
    .line 118
    instance-of p1, p0, Lne0/e;

    .line 119
    .line 120
    if-eqz p1, :cond_9

    .line 121
    .line 122
    move-object p1, p0

    .line 123
    check-cast p1, Lne0/e;

    .line 124
    .line 125
    iget-object v2, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast v2, Lyi0/a;

    .line 128
    .line 129
    iget-object v2, v2, Lyi0/a;->a:Ljava/lang/String;

    .line 130
    .line 131
    iput-object p1, v0, Lwi0/o;->d:Lne0/e;

    .line 132
    .line 133
    iput v4, v0, Lwi0/o;->g:I

    .line 134
    .line 135
    check-cast v3, Lui0/d;

    .line 136
    .line 137
    iget-object p1, v3, Lui0/d;->a:Lve0/u;

    .line 138
    .line 139
    const-string v3, "agent_id"

    .line 140
    .line 141
    invoke-virtual {p1, v3, v2, v0}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    if-ne p1, v1, :cond_8

    .line 146
    .line 147
    goto :goto_3

    .line 148
    :cond_8
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 149
    .line 150
    :goto_3
    if-ne p1, v1, :cond_9

    .line 151
    .line 152
    :goto_4
    return-object v1

    .line 153
    :cond_9
    :goto_5
    move-object p1, p0

    .line 154
    :goto_6
    instance-of p0, p1, Lne0/e;

    .line 155
    .line 156
    if-eqz p0, :cond_a

    .line 157
    .line 158
    move-object p0, p1

    .line 159
    check-cast p0, Lne0/e;

    .line 160
    .line 161
    iget-object p0, p0, Lne0/e;->a:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast p0, Lyi0/a;

    .line 164
    .line 165
    iget-object p0, p0, Lyi0/a;->a:Ljava/lang/String;

    .line 166
    .line 167
    invoke-static {}, Lvr/a;->a()Lcom/google/firebase/analytics/FirebaseAnalytics;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    iget-object v0, v0, Lcom/google/firebase/analytics/FirebaseAnalytics;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 172
    .line 173
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 174
    .line 175
    .line 176
    new-instance v1, Lcom/google/android/gms/internal/measurement/a1;

    .line 177
    .line 178
    invoke-direct {v1, v0, p0}, Lcom/google/android/gms/internal/measurement/a1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 182
    .line 183
    .line 184
    :cond_a
    return-object p1

    .line 185
    :cond_b
    new-instance p0, La8/r0;

    .line 186
    .line 187
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 188
    .line 189
    .line 190
    throw p0
.end method
