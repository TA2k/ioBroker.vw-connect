.class public final Lhu/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhu/m0;


# static fields
.field public static final f:D

.field public static final synthetic g:I


# instance fields
.field public final a:Lsr/f;

.field public final b:Lht/d;

.field public final c:Lku/j;

.field public final d:Lhu/l;

.field public final e:Lpx0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    invoke-static {}, Ljava/lang/Math;->random()D

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    sput-wide v0, Lhu/o0;->f:D

    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>(Lsr/f;Lht/d;Lku/j;Lhu/l;Lpx0/g;)V
    .locals 1

    .line 1
    const-string v0, "firebaseApp"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "firebaseInstallations"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "sessionSettings"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "eventGDTLogger"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "backgroundDispatcher"

    .line 22
    .line 23
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lhu/o0;->a:Lsr/f;

    .line 30
    .line 31
    iput-object p2, p0, Lhu/o0;->b:Lht/d;

    .line 32
    .line 33
    iput-object p3, p0, Lhu/o0;->c:Lku/j;

    .line 34
    .line 35
    iput-object p4, p0, Lhu/o0;->d:Lhu/l;

    .line 36
    .line 37
    iput-object p5, p0, Lhu/o0;->e:Lpx0/g;

    .line 38
    .line 39
    return-void
.end method

.method public static final a(Lhu/o0;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lhu/n0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lhu/n0;

    .line 7
    .line 8
    iget v1, v0, Lhu/n0;->g:I

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
    iput v1, v0, Lhu/n0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lhu/n0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lhu/n0;-><init>(Lhu/o0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lhu/n0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lhu/n0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const-string v5, "FirebaseSessions"

    .line 34
    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    iget-object p0, v0, Lhu/n0;->d:Lhu/o0;

    .line 42
    .line 43
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_3

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
    iget-object p0, v0, Lhu/n0;->d:Lhu/o0;

    .line 56
    .line 57
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    sget-object p1, Liu/c;->a:Liu/c;

    .line 65
    .line 66
    iput-object p0, v0, Lhu/n0;->d:Lhu/o0;

    .line 67
    .line 68
    iput v4, v0, Lhu/n0;->g:I

    .line 69
    .line 70
    invoke-virtual {p1, v0}, Liu/c;->b(Lrx0/c;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    if-ne p1, v1, :cond_4

    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_4
    :goto_1
    check-cast p1, Ljava/util/Map;

    .line 78
    .line 79
    invoke-interface {p1}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    check-cast p1, Ljava/lang/Iterable;

    .line 84
    .line 85
    instance-of v2, p1, Ljava/util/Collection;

    .line 86
    .line 87
    if-eqz v2, :cond_5

    .line 88
    .line 89
    move-object v2, p1

    .line 90
    check-cast v2, Ljava/util/Collection;

    .line 91
    .line 92
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    if-eqz v2, :cond_5

    .line 97
    .line 98
    goto :goto_5

    .line 99
    :cond_5
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    :cond_6
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 104
    .line 105
    .line 106
    move-result v2

    .line 107
    if-eqz v2, :cond_c

    .line 108
    .line 109
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    check-cast v2, Lms/i;

    .line 114
    .line 115
    iget-object v2, v2, Lms/i;->a:Lh8/o;

    .line 116
    .line 117
    invoke-virtual {v2}, Lh8/o;->a()Z

    .line 118
    .line 119
    .line 120
    move-result v2

    .line 121
    if-eqz v2, :cond_6

    .line 122
    .line 123
    iget-object p1, p0, Lhu/o0;->c:Lku/j;

    .line 124
    .line 125
    iput-object p0, v0, Lhu/n0;->d:Lhu/o0;

    .line 126
    .line 127
    iput v3, v0, Lhu/n0;->g:I

    .line 128
    .line 129
    invoke-virtual {p1, v0}, Lku/j;->b(Lrx0/c;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    if-ne p1, v1, :cond_7

    .line 134
    .line 135
    :goto_2
    return-object v1

    .line 136
    :cond_7
    :goto_3
    iget-object p1, p0, Lhu/o0;->c:Lku/j;

    .line 137
    .line 138
    iget-object v0, p1, Lku/j;->a:Lku/n;

    .line 139
    .line 140
    invoke-interface {v0}, Lku/n;->a()Ljava/lang/Boolean;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    if-eqz v0, :cond_8

    .line 145
    .line 146
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 147
    .line 148
    .line 149
    move-result v4

    .line 150
    goto :goto_4

    .line 151
    :cond_8
    iget-object p1, p1, Lku/j;->b:Lku/n;

    .line 152
    .line 153
    invoke-interface {p1}, Lku/n;->a()Ljava/lang/Boolean;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    if-eqz p1, :cond_9

    .line 158
    .line 159
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 160
    .line 161
    .line 162
    move-result v4

    .line 163
    :cond_9
    :goto_4
    if-nez v4, :cond_a

    .line 164
    .line 165
    const-string p0, "Sessions SDK disabled through settings API. Events will not be sent."

    .line 166
    .line 167
    invoke-static {v5, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 168
    .line 169
    .line 170
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 171
    .line 172
    return-object p0

    .line 173
    :cond_a
    iget-object p0, p0, Lhu/o0;->c:Lku/j;

    .line 174
    .line 175
    invoke-virtual {p0}, Lku/j;->a()D

    .line 176
    .line 177
    .line 178
    move-result-wide p0

    .line 179
    sget-wide v0, Lhu/o0;->f:D

    .line 180
    .line 181
    cmpg-double p0, v0, p0

    .line 182
    .line 183
    if-gtz p0, :cond_b

    .line 184
    .line 185
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 186
    .line 187
    return-object p0

    .line 188
    :cond_b
    const-string p0, "Sessions SDK has dropped this session due to sampling."

    .line 189
    .line 190
    invoke-static {v5, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 191
    .line 192
    .line 193
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 194
    .line 195
    return-object p0

    .line 196
    :cond_c
    :goto_5
    const-string p0, "Sessions SDK disabled through data collection. Events will not be sent."

    .line 197
    .line 198
    invoke-static {v5, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 199
    .line 200
    .line 201
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 202
    .line 203
    return-object p0
.end method
