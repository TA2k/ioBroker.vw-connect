.class public abstract Lu2/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lu2/l;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltf0/a;

    .line 2
    .line 3
    const/16 v1, 0x12

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ltf0/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lu2/d;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    invoke-direct {v1, v2}, Lu2/d;-><init>(I)V

    .line 12
    .line 13
    .line 14
    new-instance v2, Lu2/l;

    .line 15
    .line 16
    invoke-direct {v2, v0, v1}, Lu2/l;-><init>(Lay0/n;Lay0/k;)V

    .line 17
    .line 18
    .line 19
    sput-object v2, Lu2/m;->a:Lu2/l;

    .line 20
    .line 21
    return-void
.end method

.method public static final a(Ljava/lang/Object;)Ljava/lang/String;
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 7
    .line 8
    .line 9
    const-string p0, " cannot be saved using the current SaveableStateRegistry. The default implementation only supports types which can be stored inside the Bundle. Please consider implementing a custom Saver for this class and pass it to rememberSaveable()."

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public static final b(Lay0/n;Lay0/k;)Lu2/l;
    .locals 3

    .line 1
    new-instance v0, Lcw0/j;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, p0, v1, v2}, Lcw0/j;-><init>(Lay0/n;IB)V

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x1

    .line 9
    invoke-static {p0, p1}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    new-instance p0, Lu2/l;

    .line 13
    .line 14
    invoke-direct {p0, v0, p1}, Lu2/l;-><init>(Lay0/n;Lay0/k;)V

    .line 15
    .line 16
    .line 17
    return-object p0
.end method

.method public static final c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;
    .locals 7

    .line 1
    array-length v0, p0

    .line 2
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    shl-int/lit8 p0, p3, 0x6

    .line 7
    .line 8
    and-int/lit16 p0, p0, 0x1c00

    .line 9
    .line 10
    or-int/lit16 v5, p0, 0x180

    .line 11
    .line 12
    const/4 v6, 0x0

    .line 13
    sget-object v2, Lu2/m;->a:Lu2/l;

    .line 14
    .line 15
    move-object v3, p1

    .line 16
    move-object v4, p2

    .line 17
    invoke-static/range {v1 .. v6}, Lu2/m;->e([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;II)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public static final d([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;I)Ljava/lang/Object;
    .locals 7

    .line 1
    array-length v0, p0

    .line 2
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    shl-int/lit8 p0, p4, 0x3

    .line 7
    .line 8
    and-int/lit16 p0, p0, 0x1c00

    .line 9
    .line 10
    const/16 p4, 0x180

    .line 11
    .line 12
    or-int v5, p4, p0

    .line 13
    .line 14
    const/4 v6, 0x0

    .line 15
    move-object v2, p1

    .line 16
    move-object v3, p2

    .line 17
    move-object v4, p3

    .line 18
    invoke-static/range {v1 .. v6}, Lu2/m;->e([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;II)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public static final e([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;II)Ljava/lang/Object;
    .locals 8

    .line 1
    and-int/lit8 p5, p5, 0x2

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    sget-object p1, Lu2/m;->a:Lu2/l;

    .line 6
    .line 7
    :cond_0
    move-object v1, p1

    .line 8
    check-cast p3, Ll2/t;

    .line 9
    .line 10
    iget-wide v2, p3, Ll2/t;->T:J

    .line 11
    .line 12
    const/16 p1, 0x24

    .line 13
    .line 14
    invoke-static {p1}, Lry/a;->a(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v2, v3, p1}, Ljava/lang/Long;->toString(JI)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    const-string p1, "toString(...)"

    .line 22
    .line 23
    invoke-static {v3, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string p1, "null cannot be cast to non-null type androidx.compose.runtime.saveable.Saver<T of androidx.compose.runtime.saveable.RememberSaveableKt.rememberSaveable, kotlin.Any>"

    .line 27
    .line 28
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    sget-object p1, Lu2/i;->a:Ll2/u2;

    .line 32
    .line 33
    invoke-virtual {p3, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    move-object v2, p1

    .line 38
    check-cast v2, Lu2/g;

    .line 39
    .line 40
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    const/4 p5, 0x0

    .line 45
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 46
    .line 47
    if-ne p1, v6, :cond_3

    .line 48
    .line 49
    if-eqz v2, :cond_1

    .line 50
    .line 51
    invoke-interface {v2, v3}, Lu2/g;->f(Ljava/lang/String;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    if-eqz p1, :cond_1

    .line 56
    .line 57
    invoke-interface {v1, p1}, Lu2/k;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    goto :goto_0

    .line 62
    :cond_1
    move-object p1, p5

    .line 63
    :goto_0
    if-nez p1, :cond_2

    .line 64
    .line 65
    invoke-interface {p2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    :cond_2
    move-object v4, p1

    .line 70
    new-instance v0, Lu2/b;

    .line 71
    .line 72
    move-object v5, p0

    .line 73
    invoke-direct/range {v0 .. v5}, Lu2/b;-><init>(Lu2/k;Lu2/g;Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p3, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    move-object p1, v0

    .line 80
    goto :goto_1

    .line 81
    :cond_3
    move-object v5, p0

    .line 82
    :goto_1
    check-cast p1, Lu2/b;

    .line 83
    .line 84
    iget-object p0, p1, Lu2/b;->h:[Ljava/lang/Object;

    .line 85
    .line 86
    invoke-static {v5, p0}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    if-eqz p0, :cond_4

    .line 91
    .line 92
    iget-object p5, p1, Lu2/b;->g:Ljava/lang/Object;

    .line 93
    .line 94
    :cond_4
    if-nez p5, :cond_5

    .line 95
    .line 96
    invoke-interface {p2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p5

    .line 100
    :cond_5
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    and-int/lit8 p2, p4, 0x70

    .line 105
    .line 106
    xor-int/lit8 p2, p2, 0x30

    .line 107
    .line 108
    const/16 v0, 0x20

    .line 109
    .line 110
    if-le p2, v0, :cond_6

    .line 111
    .line 112
    invoke-virtual {p3, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result p2

    .line 116
    if-nez p2, :cond_7

    .line 117
    .line 118
    :cond_6
    and-int/lit8 p2, p4, 0x30

    .line 119
    .line 120
    if-ne p2, v0, :cond_8

    .line 121
    .line 122
    :cond_7
    const/4 p2, 0x1

    .line 123
    goto :goto_2

    .line 124
    :cond_8
    const/4 p2, 0x0

    .line 125
    :goto_2
    or-int/2addr p0, p2

    .line 126
    invoke-virtual {p3, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p2

    .line 130
    or-int/2addr p0, p2

    .line 131
    invoke-virtual {p3, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result p2

    .line 135
    or-int/2addr p0, p2

    .line 136
    invoke-virtual {p3, p5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result p2

    .line 140
    or-int/2addr p0, p2

    .line 141
    invoke-virtual {p3, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result p2

    .line 145
    or-int/2addr p0, p2

    .line 146
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object p2

    .line 150
    if-nez p0, :cond_a

    .line 151
    .line 152
    if-ne p2, v6, :cond_9

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_9
    move-object v5, p5

    .line 156
    goto :goto_4

    .line 157
    :cond_a
    :goto_3
    new-instance v0, Lh2/w3;

    .line 158
    .line 159
    const/4 v7, 0x1

    .line 160
    move-object v4, v3

    .line 161
    move-object v6, v5

    .line 162
    move-object v5, p5

    .line 163
    move-object v3, v2

    .line 164
    move-object v2, v1

    .line 165
    move-object v1, p1

    .line 166
    invoke-direct/range {v0 .. v7}, Lh2/w3;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {p3, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    move-object p2, v0

    .line 173
    :goto_4
    check-cast p2, Lay0/a;

    .line 174
    .line 175
    invoke-static {p2, p3}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 176
    .line 177
    .line 178
    return-object v5
.end method

.method public static final f(Ll2/o;)Lu2/e;
    .locals 5

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x753e2915

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->Y(I)V

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    new-array v1, v0, [Ljava/lang/Object;

    .line 11
    .line 12
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 17
    .line 18
    if-ne v2, v3, :cond_0

    .line 19
    .line 20
    new-instance v2, Lt61/d;

    .line 21
    .line 22
    const/16 v3, 0x16

    .line 23
    .line 24
    invoke-direct {v2, v3}, Lt61/d;-><init>(I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    check-cast v2, Lay0/a;

    .line 31
    .line 32
    const/16 v3, 0x180

    .line 33
    .line 34
    sget-object v4, Lu2/e;->h:Lu2/l;

    .line 35
    .line 36
    invoke-static {v1, v4, v2, p0, v3}, Lu2/m;->d([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    check-cast v1, Lu2/e;

    .line 41
    .line 42
    sget-object v2, Lu2/i;->a:Ll2/u2;

    .line 43
    .line 44
    invoke-virtual {p0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    check-cast v2, Lu2/g;

    .line 49
    .line 50
    iput-object v2, v1, Lu2/e;->f:Lu2/g;

    .line 51
    .line 52
    invoke-virtual {p0, v0}, Ll2/t;->q(Z)V

    .line 53
    .line 54
    .line 55
    return-object v1
.end method
