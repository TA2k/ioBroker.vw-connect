.class public final Lkotlin/jvm/internal/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhy0/a0;


# instance fields
.field public final d:Lhy0/e;

.field public final e:Ljava/util/List;

.field public final f:I


# direct methods
.method public constructor <init>(Lhy0/e;Ljava/util/List;I)V
    .locals 1

    .line 1
    const-string v0, "classifier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "arguments"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lkotlin/jvm/internal/l0;->d:Lhy0/e;

    .line 15
    .line 16
    iput-object p2, p0, Lkotlin/jvm/internal/l0;->e:Ljava/util/List;

    .line 17
    .line 18
    iput p3, p0, Lkotlin/jvm/internal/l0;->f:I

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a(Z)Ljava/lang/String;
    .locals 9

    .line 1
    iget-object v0, p0, Lkotlin/jvm/internal/l0;->d:Lhy0/e;

    .line 2
    .line 3
    instance-of v1, v0, Lhy0/d;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lhy0/d;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move-object v1, v2

    .line 13
    :goto_0
    if-eqz v1, :cond_1

    .line 14
    .line 15
    invoke-static {v1}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    :cond_1
    if-nez v2, :cond_2

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    goto/16 :goto_1

    .line 26
    .line 27
    :cond_2
    iget v1, p0, Lkotlin/jvm/internal/l0;->f:I

    .line 28
    .line 29
    and-int/lit8 v1, v1, 0x4

    .line 30
    .line 31
    if-eqz v1, :cond_3

    .line 32
    .line 33
    const-string p1, "kotlin.Nothing"

    .line 34
    .line 35
    goto/16 :goto_1

    .line 36
    .line 37
    :cond_3
    invoke-virtual {v2}, Ljava/lang/Class;->isArray()Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_c

    .line 42
    .line 43
    const-class p1, [Z

    .line 44
    .line 45
    invoke-virtual {v2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    if-eqz p1, :cond_4

    .line 50
    .line 51
    const-string p1, "kotlin.BooleanArray"

    .line 52
    .line 53
    goto/16 :goto_1

    .line 54
    .line 55
    :cond_4
    const-class p1, [C

    .line 56
    .line 57
    invoke-virtual {v2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    if-eqz p1, :cond_5

    .line 62
    .line 63
    const-string p1, "kotlin.CharArray"

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_5
    const-class p1, [B

    .line 67
    .line 68
    invoke-virtual {v2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    if-eqz p1, :cond_6

    .line 73
    .line 74
    const-string p1, "kotlin.ByteArray"

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_6
    const-class p1, [S

    .line 78
    .line 79
    invoke-virtual {v2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    if-eqz p1, :cond_7

    .line 84
    .line 85
    const-string p1, "kotlin.ShortArray"

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_7
    const-class p1, [I

    .line 89
    .line 90
    invoke-virtual {v2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result p1

    .line 94
    if-eqz p1, :cond_8

    .line 95
    .line 96
    const-string p1, "kotlin.IntArray"

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_8
    const-class p1, [F

    .line 100
    .line 101
    invoke-virtual {v2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result p1

    .line 105
    if-eqz p1, :cond_9

    .line 106
    .line 107
    const-string p1, "kotlin.FloatArray"

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_9
    const-class p1, [J

    .line 111
    .line 112
    invoke-virtual {v2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result p1

    .line 116
    if-eqz p1, :cond_a

    .line 117
    .line 118
    const-string p1, "kotlin.LongArray"

    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_a
    const-class p1, [D

    .line 122
    .line 123
    invoke-virtual {v2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result p1

    .line 127
    if-eqz p1, :cond_b

    .line 128
    .line 129
    const-string p1, "kotlin.DoubleArray"

    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_b
    const-string p1, "kotlin.Array"

    .line 133
    .line 134
    goto :goto_1

    .line 135
    :cond_c
    if-eqz p1, :cond_d

    .line 136
    .line 137
    invoke-virtual {v2}, Ljava/lang/Class;->isPrimitive()Z

    .line 138
    .line 139
    .line 140
    move-result p1

    .line 141
    if-eqz p1, :cond_d

    .line 142
    .line 143
    const-string p1, "null cannot be cast to non-null type kotlin.reflect.KClass<*>"

    .line 144
    .line 145
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    check-cast v0, Lhy0/d;

    .line 149
    .line 150
    invoke-static {v0}, Ljp/p1;->d(Lhy0/d;)Ljava/lang/Class;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object p1

    .line 158
    goto :goto_1

    .line 159
    :cond_d
    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    :goto_1
    iget-object v0, p0, Lkotlin/jvm/internal/l0;->e:Ljava/util/List;

    .line 164
    .line 165
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 166
    .line 167
    .line 168
    move-result v1

    .line 169
    const-string v2, ""

    .line 170
    .line 171
    if-eqz v1, :cond_e

    .line 172
    .line 173
    move-object v0, v2

    .line 174
    goto :goto_2

    .line 175
    :cond_e
    move-object v3, v0

    .line 176
    check-cast v3, Ljava/lang/Iterable;

    .line 177
    .line 178
    new-instance v7, Li40/e1;

    .line 179
    .line 180
    const/16 v0, 0x14

    .line 181
    .line 182
    invoke-direct {v7, p0, v0}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 183
    .line 184
    .line 185
    const/16 v8, 0x18

    .line 186
    .line 187
    const-string v4, ", "

    .line 188
    .line 189
    const-string v5, "<"

    .line 190
    .line 191
    const-string v6, ">"

    .line 192
    .line 193
    invoke-static/range {v3 .. v8}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    :goto_2
    invoke-virtual {p0}, Lkotlin/jvm/internal/l0;->isMarkedNullable()Z

    .line 198
    .line 199
    .line 200
    move-result p0

    .line 201
    if-eqz p0, :cond_f

    .line 202
    .line 203
    const-string v2, "?"

    .line 204
    .line 205
    :cond_f
    invoke-static {p1, v0, v2}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lkotlin/jvm/internal/l0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lkotlin/jvm/internal/l0;

    .line 6
    .line 7
    iget-object v0, p1, Lkotlin/jvm/internal/l0;->d:Lhy0/e;

    .line 8
    .line 9
    iget-object v1, p0, Lkotlin/jvm/internal/l0;->d:Lhy0/e;

    .line 10
    .line 11
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-object v0, p0, Lkotlin/jvm/internal/l0;->e:Ljava/util/List;

    .line 18
    .line 19
    iget-object v1, p1, Lkotlin/jvm/internal/l0;->e:Ljava/util/List;

    .line 20
    .line 21
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    iget p0, p0, Lkotlin/jvm/internal/l0;->f:I

    .line 28
    .line 29
    iget p1, p1, Lkotlin/jvm/internal/l0;->f:I

    .line 30
    .line 31
    if-ne p0, p1, :cond_0

    .line 32
    .line 33
    const/4 p0, 0x1

    .line 34
    return p0

    .line 35
    :cond_0
    const/4 p0, 0x0

    .line 36
    return p0
.end method

.method public final getAnnotations()Ljava/util/List;
    .locals 0

    .line 1
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getArguments()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/jvm/internal/l0;->e:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getClassifier()Lhy0/e;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/jvm/internal/l0;->d:Lhy0/e;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/jvm/internal/l0;->d:Lhy0/e;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lkotlin/jvm/internal/l0;->e:Ljava/util/List;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget p0, p0, Lkotlin/jvm/internal/l0;->f:I

    .line 17
    .line 18
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    add-int/2addr p0, v0

    .line 23
    return p0
.end method

.method public final isMarkedNullable()Z
    .locals 1

    .line 1
    iget p0, p0, Lkotlin/jvm/internal/l0;->f:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    and-int/2addr p0, v0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return v0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/l0;->a(Z)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    const-string p0, " (Kotlin reflection is not available)"

    .line 15
    .line 16
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
