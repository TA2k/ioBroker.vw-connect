.class public final synthetic Lyd/t;
.super Lkotlin/jvm/internal/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Llx0/o;

    .line 2
    .line 3
    check-cast p2, Lvd/l;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/String;

    .line 6
    .line 7
    check-cast p4, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p4

    .line 13
    check-cast p5, Lkotlin/coroutines/Continuation;

    .line 14
    .line 15
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lyd/l;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    const-string p0, "input"

    .line 23
    .line 24
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    if-nez p1, :cond_0

    .line 28
    .line 29
    new-instance p0, Llc/q;

    .line 30
    .line 31
    sget-object p1, Llc/a;->c:Llc/c;

    .line 32
    .line 33
    invoke-direct {p0, p1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_0
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 38
    .line 39
    instance-of p1, p0, Llx0/n;

    .line 40
    .line 41
    const/4 p5, 0x0

    .line 42
    if-nez p1, :cond_1

    .line 43
    .line 44
    if-eqz p2, :cond_1

    .line 45
    .line 46
    invoke-static {p5, p2, p3, p4}, Lyd/l;->b(Ljava/lang/String;Lvd/l;Ljava/lang/String;Z)Lyd/r;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    new-instance p1, Llc/q;

    .line 51
    .line 52
    invoke-direct {p1, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    return-object p1

    .line 56
    :cond_1
    if-eqz p1, :cond_8

    .line 57
    .line 58
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    instance-of v0, p1, Lrc/a;

    .line 66
    .line 67
    if-eqz v0, :cond_2

    .line 68
    .line 69
    check-cast p1, Lrc/a;

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_2
    move-object p1, p5

    .line 73
    :goto_0
    if-eqz p1, :cond_3

    .line 74
    .line 75
    iget-object p1, p1, Lrc/a;->e:Ltb/c;

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_3
    move-object p1, p5

    .line 79
    :goto_1
    if-eqz p1, :cond_6

    .line 80
    .line 81
    iget-object p1, p1, Ltb/c;->d:Ltb/c0;

    .line 82
    .line 83
    if-eqz p1, :cond_6

    .line 84
    .line 85
    iget-object p1, p1, Ltb/c0;->a:Ljava/util/List;

    .line 86
    .line 87
    if-eqz p1, :cond_6

    .line 88
    .line 89
    check-cast p1, Ljava/lang/Iterable;

    .line 90
    .line 91
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    :cond_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    if-eqz v0, :cond_5

    .line 100
    .line 101
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    move-object v1, v0

    .line 106
    check-cast v1, Ltb/o;

    .line 107
    .line 108
    iget-object v1, v1, Ltb/o;->a:Ljava/lang/String;

    .line 109
    .line 110
    const-string v2, "coupon"

    .line 111
    .line 112
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    if-eqz v1, :cond_4

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_5
    move-object v0, p5

    .line 120
    :goto_2
    check-cast v0, Ltb/o;

    .line 121
    .line 122
    if-eqz v0, :cond_6

    .line 123
    .line 124
    iget-object p5, v0, Ltb/o;->b:Ljava/lang/String;

    .line 125
    .line 126
    :cond_6
    if-eqz p5, :cond_7

    .line 127
    .line 128
    if-eqz p2, :cond_7

    .line 129
    .line 130
    invoke-static {p5, p2, p3, p4}, Lyd/l;->b(Ljava/lang/String;Lvd/l;Ljava/lang/String;Z)Lyd/r;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    new-instance p1, Llc/q;

    .line 135
    .line 136
    invoke-direct {p1, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    return-object p1

    .line 140
    :cond_7
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    invoke-static {p0}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    new-instance p1, Llc/q;

    .line 152
    .line 153
    invoke-direct {p1, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    return-object p1

    .line 157
    :cond_8
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 158
    .line 159
    invoke-static {p0}, Llx0/o;->b(Ljava/lang/Object;)Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    new-instance p3, Ljava/lang/StringBuilder;

    .line 164
    .line 165
    const-string p4, "Unexpected state in CouponsOverviewMapper mapping: state="

    .line 166
    .line 167
    invoke-direct {p3, p4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    const-string p0, " couponResponse="

    .line 174
    .line 175
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object p0

    .line 189
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    throw p1
.end method
