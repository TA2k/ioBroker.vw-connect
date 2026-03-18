.class public final Lhz0/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhz0/i1;
.implements Llz0/c;


# instance fields
.field public a:Ljava/lang/Integer;

.field public b:Ljava/lang/Integer;

.field public c:Lhz0/h;

.field public d:Ljava/lang/Integer;

.field public e:Ljava/lang/Integer;

.field public f:Ljava/lang/Integer;


# direct methods
.method public synthetic constructor <init>()V
    .locals 7

    const/4 v2, 0x0

    const/4 v1, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v0, p0

    .line 1
    invoke-direct/range {v0 .. v6}, Lhz0/j0;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Lhz0/h;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/Integer;Ljava/lang/Integer;Lhz0/h;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lhz0/j0;->a:Ljava/lang/Integer;

    .line 4
    iput-object p2, p0, Lhz0/j0;->b:Ljava/lang/Integer;

    .line 5
    iput-object p3, p0, Lhz0/j0;->c:Lhz0/h;

    .line 6
    iput-object p4, p0, Lhz0/j0;->d:Ljava/lang/Integer;

    .line 7
    iput-object p5, p0, Lhz0/j0;->e:Ljava/lang/Integer;

    .line 8
    iput-object p6, p0, Lhz0/j0;->f:Ljava/lang/Integer;

    return-void
.end method


# virtual methods
.method public final D(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhz0/j0;->a:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public final E()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/j0;->a:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final a()Lhz0/j0;
    .locals 7

    .line 1
    new-instance v0, Lhz0/j0;

    .line 2
    .line 3
    iget-object v1, p0, Lhz0/j0;->a:Ljava/lang/Integer;

    .line 4
    .line 5
    iget-object v2, p0, Lhz0/j0;->b:Ljava/lang/Integer;

    .line 6
    .line 7
    iget-object v3, p0, Lhz0/j0;->c:Lhz0/h;

    .line 8
    .line 9
    iget-object v4, p0, Lhz0/j0;->d:Ljava/lang/Integer;

    .line 10
    .line 11
    iget-object v5, p0, Lhz0/j0;->e:Ljava/lang/Integer;

    .line 12
    .line 13
    iget-object v6, p0, Lhz0/j0;->f:Ljava/lang/Integer;

    .line 14
    .line 15
    invoke-direct/range {v0 .. v6}, Lhz0/j0;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Lhz0/h;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public final b()Lgz0/y;
    .locals 6

    .line 1
    iget-object v0, p0, Lhz0/j0;->a:Ljava/lang/Integer;

    .line 2
    .line 3
    const/16 v1, 0xc

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v0, :cond_5

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    iget-object v3, p0, Lhz0/j0;->b:Ljava/lang/Integer;

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    if-eqz v3, :cond_1

    .line 16
    .line 17
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    add-int/lit8 v5, v0, 0xb

    .line 22
    .line 23
    rem-int/2addr v5, v1

    .line 24
    add-int/2addr v5, v4

    .line 25
    if-ne v5, v3, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const-string p0, "Inconsistent hour and hour-of-am-pm: hour is "

    .line 29
    .line 30
    const-string v1, ", but hour-of-am-pm is "

    .line 31
    .line 32
    invoke-static {p0, v1, v0, v3}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw v0

    .line 46
    :cond_1
    :goto_0
    iget-object v3, p0, Lhz0/j0;->c:Lhz0/h;

    .line 47
    .line 48
    if-eqz v3, :cond_9

    .line 49
    .line 50
    sget-object v5, Lhz0/h;->d:Lhz0/h;

    .line 51
    .line 52
    if-ne v3, v5, :cond_2

    .line 53
    .line 54
    move v5, v4

    .line 55
    goto :goto_1

    .line 56
    :cond_2
    move v5, v2

    .line 57
    :goto_1
    if-lt v0, v1, :cond_3

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    move v4, v2

    .line 61
    :goto_2
    if-ne v5, v4, :cond_4

    .line 62
    .line 63
    goto :goto_4

    .line 64
    :cond_4
    new-instance p0, Ljava/lang/StringBuilder;

    .line 65
    .line 66
    const-string v1, "Inconsistent hour and the AM/PM marker: hour is "

    .line 67
    .line 68
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v0, ", but the AM/PM marker is "

    .line 75
    .line 76
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 87
    .line 88
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw v0

    .line 96
    :cond_5
    iget-object v0, p0, Lhz0/j0;->b:Ljava/lang/Integer;

    .line 97
    .line 98
    const/4 v3, 0x0

    .line 99
    if-eqz v0, :cond_8

    .line 100
    .line 101
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 102
    .line 103
    .line 104
    move-result v0

    .line 105
    iget-object v4, p0, Lhz0/j0;->c:Lhz0/h;

    .line 106
    .line 107
    if-eqz v4, :cond_8

    .line 108
    .line 109
    if-ne v0, v1, :cond_6

    .line 110
    .line 111
    move v0, v2

    .line 112
    :cond_6
    sget-object v3, Lhz0/h;->d:Lhz0/h;

    .line 113
    .line 114
    if-ne v4, v3, :cond_7

    .line 115
    .line 116
    goto :goto_3

    .line 117
    :cond_7
    move v1, v2

    .line 118
    :goto_3
    add-int/2addr v0, v1

    .line 119
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 120
    .line 121
    .line 122
    move-result-object v3

    .line 123
    :cond_8
    if-eqz v3, :cond_c

    .line 124
    .line 125
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    :cond_9
    :goto_4
    new-instance v1, Lgz0/y;

    .line 130
    .line 131
    iget-object v3, p0, Lhz0/j0;->d:Ljava/lang/Integer;

    .line 132
    .line 133
    const-string v4, "minute"

    .line 134
    .line 135
    invoke-static {v3, v4}, Lhz0/e2;->a(Ljava/lang/Object;Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 139
    .line 140
    .line 141
    move-result v3

    .line 142
    iget-object v4, p0, Lhz0/j0;->e:Ljava/lang/Integer;

    .line 143
    .line 144
    if-eqz v4, :cond_a

    .line 145
    .line 146
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 147
    .line 148
    .line 149
    move-result v4

    .line 150
    goto :goto_5

    .line 151
    :cond_a
    move v4, v2

    .line 152
    :goto_5
    iget-object p0, p0, Lhz0/j0;->f:Ljava/lang/Integer;

    .line 153
    .line 154
    if-eqz p0, :cond_b

    .line 155
    .line 156
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 157
    .line 158
    .line 159
    move-result v2

    .line 160
    :cond_b
    :try_start_0
    invoke-static {v0, v3, v4, v2}, Ljava/time/LocalTime;->of(IIII)Ljava/time/LocalTime;

    .line 161
    .line 162
    .line 163
    move-result-object p0
    :try_end_0
    .catch Ljava/time/DateTimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 164
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    invoke-direct {v1, p0}, Lgz0/y;-><init>(Ljava/time/LocalTime;)V

    .line 168
    .line 169
    .line 170
    return-object v1

    .line 171
    :catch_0
    move-exception p0

    .line 172
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 173
    .line 174
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    .line 175
    .line 176
    .line 177
    throw v0

    .line 178
    :cond_c
    new-instance p0, Lgz0/a;

    .line 179
    .line 180
    const-string v0, "Incomplete time: missing hour"

    .line 181
    .line 182
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    throw p0
.end method

.method public final bridge synthetic copy()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lhz0/j0;->a()Lhz0/j0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final e()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/j0;->f:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lhz0/j0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lhz0/j0;->a:Ljava/lang/Integer;

    .line 6
    .line 7
    check-cast p1, Lhz0/j0;

    .line 8
    .line 9
    iget-object v1, p1, Lhz0/j0;->a:Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-object v0, p0, Lhz0/j0;->b:Ljava/lang/Integer;

    .line 18
    .line 19
    iget-object v1, p1, Lhz0/j0;->b:Ljava/lang/Integer;

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
    iget-object v0, p0, Lhz0/j0;->c:Lhz0/h;

    .line 28
    .line 29
    iget-object v1, p1, Lhz0/j0;->c:Lhz0/h;

    .line 30
    .line 31
    if-ne v0, v1, :cond_0

    .line 32
    .line 33
    iget-object v0, p0, Lhz0/j0;->d:Ljava/lang/Integer;

    .line 34
    .line 35
    iget-object v1, p1, Lhz0/j0;->d:Ljava/lang/Integer;

    .line 36
    .line 37
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_0

    .line 42
    .line 43
    iget-object v0, p0, Lhz0/j0;->e:Ljava/lang/Integer;

    .line 44
    .line 45
    iget-object v1, p1, Lhz0/j0;->e:Ljava/lang/Integer;

    .line 46
    .line 47
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-eqz v0, :cond_0

    .line 52
    .line 53
    iget-object p0, p0, Lhz0/j0;->f:Ljava/lang/Integer;

    .line 54
    .line 55
    iget-object p1, p1, Lhz0/j0;->f:Ljava/lang/Integer;

    .line 56
    .line 57
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    if-eqz p0, :cond_0

    .line 62
    .line 63
    const/4 p0, 0x1

    .line 64
    return p0

    .line 65
    :cond_0
    const/4 p0, 0x0

    .line 66
    return p0
.end method

.method public final f()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/j0;->b:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lhz0/j0;->a:Ljava/lang/Integer;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v0, v1

    .line 12
    :goto_0
    mul-int/lit8 v0, v0, 0x1f

    .line 13
    .line 14
    iget-object v2, p0, Lhz0/j0;->b:Ljava/lang/Integer;

    .line 15
    .line 16
    if-eqz v2, :cond_1

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move v2, v1

    .line 24
    :goto_1
    mul-int/lit8 v2, v2, 0x1f

    .line 25
    .line 26
    add-int/2addr v2, v0

    .line 27
    iget-object v0, p0, Lhz0/j0;->c:Lhz0/h;

    .line 28
    .line 29
    if-eqz v0, :cond_2

    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    goto :goto_2

    .line 36
    :cond_2
    move v0, v1

    .line 37
    :goto_2
    mul-int/lit8 v0, v0, 0x1f

    .line 38
    .line 39
    add-int/2addr v0, v2

    .line 40
    iget-object v2, p0, Lhz0/j0;->d:Ljava/lang/Integer;

    .line 41
    .line 42
    if-eqz v2, :cond_3

    .line 43
    .line 44
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    goto :goto_3

    .line 49
    :cond_3
    move v2, v1

    .line 50
    :goto_3
    mul-int/lit8 v2, v2, 0x1f

    .line 51
    .line 52
    add-int/2addr v2, v0

    .line 53
    iget-object v0, p0, Lhz0/j0;->e:Ljava/lang/Integer;

    .line 54
    .line 55
    if-eqz v0, :cond_4

    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    goto :goto_4

    .line 62
    :cond_4
    move v0, v1

    .line 63
    :goto_4
    mul-int/lit8 v0, v0, 0x1f

    .line 64
    .line 65
    add-int/2addr v0, v2

    .line 66
    iget-object p0, p0, Lhz0/j0;->f:Ljava/lang/Integer;

    .line 67
    .line 68
    if-eqz p0, :cond_5

    .line 69
    .line 70
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    :cond_5
    add-int/2addr v0, v1

    .line 75
    return v0
.end method

.method public final j(Lhz0/h;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhz0/j0;->c:Lhz0/h;

    .line 2
    .line 3
    return-void
.end method

.method public final k()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/j0;->e:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhz0/j0;->e:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public final o()Lhz0/h;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/j0;->c:Lhz0/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public final q(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhz0/j0;->b:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public final r(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhz0/j0;->f:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public final t()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/j0;->d:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lhz0/j0;->a:Ljava/lang/Integer;

    .line 7
    .line 8
    const-string v2, "??"

    .line 9
    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    move-object v1, v2

    .line 13
    :cond_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    const/16 v1, 0x3a

    .line 17
    .line 18
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    iget-object v3, p0, Lhz0/j0;->d:Ljava/lang/Integer;

    .line 22
    .line 23
    if-nez v3, :cond_1

    .line 24
    .line 25
    move-object v3, v2

    .line 26
    :cond_1
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    iget-object v1, p0, Lhz0/j0;->e:Ljava/lang/Integer;

    .line 33
    .line 34
    if-nez v1, :cond_2

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_2
    move-object v2, v1

    .line 38
    :goto_0
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const/16 v1, 0x2e

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Lhz0/j0;->f:Ljava/lang/Integer;

    .line 47
    .line 48
    if-eqz p0, :cond_3

    .line 49
    .line 50
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    rsub-int/lit8 v1, v1, 0x9

    .line 63
    .line 64
    invoke-static {v1, p0}, Lly0/p;->Q(ILjava/lang/String;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    if-nez p0, :cond_4

    .line 69
    .line 70
    :cond_3
    const-string p0, "???"

    .line 71
    .line 72
    :cond_4
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    return-object p0
.end method

.method public final u(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhz0/j0;->d:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method
