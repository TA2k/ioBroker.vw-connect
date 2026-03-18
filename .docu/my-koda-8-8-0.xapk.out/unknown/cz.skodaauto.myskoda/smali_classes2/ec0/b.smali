.class public final Lec0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lac0/y;


# instance fields
.field public final a:Lam0/d;


# direct methods
.method public constructor <init>(Lam0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lec0/b;->a:Lam0/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lcm0/b;ZLrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lec0/b;->a:Lam0/d;

    .line 2
    .line 3
    iget-object v0, v0, Lam0/d;->a:Lam0/a;

    .line 4
    .line 5
    instance-of v1, p3, Lec0/a;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    move-object v1, p3

    .line 10
    check-cast v1, Lec0/a;

    .line 11
    .line 12
    iget v2, v1, Lec0/a;->g:I

    .line 13
    .line 14
    const/high16 v3, -0x80000000

    .line 15
    .line 16
    and-int v4, v2, v3

    .line 17
    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    sub-int/2addr v2, v3

    .line 21
    iput v2, v1, Lec0/a;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Lec0/a;

    .line 25
    .line 26
    invoke-direct {v1, p0, p3}, Lec0/a;-><init>(Lec0/b;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p3, v1, Lec0/a;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v3, v1, Lec0/a;->g:I

    .line 34
    .line 35
    const/4 v4, 0x2

    .line 36
    const/4 v5, 0x1

    .line 37
    if-eqz v3, :cond_3

    .line 38
    .line 39
    if-eq v3, v5, :cond_2

    .line 40
    .line 41
    if-ne v3, v4, :cond_1

    .line 42
    .line 43
    iget-object p1, v1, Lec0/a;->d:Lcm0/b;

    .line 44
    .line 45
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_3

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget-object p1, v1, Lec0/a;->d:Lcm0/b;

    .line 58
    .line 59
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    if-eqz p2, :cond_5

    .line 67
    .line 68
    iput-object p1, v1, Lec0/a;->d:Lcm0/b;

    .line 69
    .line 70
    iput v5, v1, Lec0/a;->g:I

    .line 71
    .line 72
    check-cast v0, Lxl0/j;

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Lxl0/j;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p3

    .line 78
    if-ne p3, v2, :cond_4

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_4
    :goto_1
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    new-instance v0, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string p3, "#"

    .line 94
    .line 95
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p2

    .line 105
    goto :goto_4

    .line 106
    :cond_5
    iput-object p1, v1, Lec0/a;->d:Lcm0/b;

    .line 107
    .line 108
    iput v4, v1, Lec0/a;->g:I

    .line 109
    .line 110
    check-cast v0, Lxl0/j;

    .line 111
    .line 112
    invoke-virtual {v0, v1}, Lxl0/j;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object p3

    .line 116
    if-ne p3, v2, :cond_6

    .line 117
    .line 118
    :goto_2
    return-object v2

    .line 119
    :cond_6
    :goto_3
    move-object p2, p3

    .line 120
    check-cast p2, Ljava/lang/String;

    .line 121
    .line 122
    :goto_4
    new-instance p3, Lac0/a;

    .line 123
    .line 124
    const/16 v0, 0x11

    .line 125
    .line 126
    invoke-direct {p3, p2, v0}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 127
    .line 128
    .line 129
    const/4 v0, 0x0

    .line 130
    invoke-static {v0, p0, p3}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 131
    .line 132
    .line 133
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 134
    .line 135
    .line 136
    move-result p0

    .line 137
    const-string p1, ""

    .line 138
    .line 139
    if-eq p0, v4, :cond_8

    .line 140
    .line 141
    const/4 p3, 0x3

    .line 142
    if-eq p0, p3, :cond_7

    .line 143
    .line 144
    const/4 p3, 0x4

    .line 145
    if-eq p0, p3, :cond_7

    .line 146
    .line 147
    new-instance p0, Ldc0/d;

    .line 148
    .line 149
    const-string p1, "ssl://mqtt.messagehub.de:8883"

    .line 150
    .line 151
    invoke-direct {p0, p1, p2}, Ldc0/d;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    return-object p0

    .line 155
    :cond_7
    new-instance p0, Ldc0/c;

    .line 156
    .line 157
    const-string p3, "clientId"

    .line 158
    .line 159
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    invoke-direct {p0, p1, p2, p1}, Ldc0/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    return-object p0

    .line 166
    :cond_8
    new-instance p0, Ldc0/d;

    .line 167
    .line 168
    invoke-direct {p0, p1, p2}, Ldc0/d;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    return-object p0
.end method
