.class public interface abstract Lt21/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract a()Z
.end method

.method public abstract b()Z
.end method

.method public abstract c()Z
.end method

.method public abstract d()Z
.end method

.method public abstract e()Z
.end method

.method public abstract f(Ljava/lang/String;Ljava/lang/Throwable;)V
.end method

.method public abstract g(Ljava/lang/String;)V
.end method

.method public abstract h(Ljava/lang/String;)V
.end method

.method public i(I)Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eq p1, v0, :cond_4

    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    if-eq p1, v0, :cond_3

    .line 6
    .line 7
    const/4 v0, 0x3

    .line 8
    if-eq p1, v0, :cond_2

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    if-eq p1, v0, :cond_1

    .line 12
    .line 13
    const/4 v0, 0x5

    .line 14
    if-ne p1, v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    throw p0

    .line 20
    :cond_1
    const/16 v0, 0xa

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_2
    const/16 v0, 0x14

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_3
    const/16 v0, 0x1e

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_4
    const/16 v0, 0x28

    .line 30
    .line 31
    :goto_0
    if-eqz v0, :cond_e

    .line 32
    .line 33
    const/16 v1, 0xa

    .line 34
    .line 35
    if-eq v0, v1, :cond_d

    .line 36
    .line 37
    const/16 v1, 0x14

    .line 38
    .line 39
    if-eq v0, v1, :cond_c

    .line 40
    .line 41
    const/16 v1, 0x1e

    .line 42
    .line 43
    if-eq v0, v1, :cond_b

    .line 44
    .line 45
    const/16 v1, 0x28

    .line 46
    .line 47
    if-ne v0, v1, :cond_5

    .line 48
    .line 49
    invoke-interface {p0}, Lt21/b;->e()Z

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    return p0

    .line 54
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 55
    .line 56
    new-instance v0, Ljava/lang/StringBuilder;

    .line 57
    .line 58
    const-string v1, "Level ["

    .line 59
    .line 60
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    const/4 v1, 0x1

    .line 64
    if-eq p1, v1, :cond_a

    .line 65
    .line 66
    const/4 v1, 0x2

    .line 67
    if-eq p1, v1, :cond_9

    .line 68
    .line 69
    const/4 v1, 0x3

    .line 70
    if-eq p1, v1, :cond_8

    .line 71
    .line 72
    const/4 v1, 0x4

    .line 73
    if-eq p1, v1, :cond_7

    .line 74
    .line 75
    const/4 v1, 0x5

    .line 76
    if-eq p1, v1, :cond_6

    .line 77
    .line 78
    const-string p1, "null"

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_6
    const-string p1, "TRACE"

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_7
    const-string p1, "DEBUG"

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_8
    const-string p1, "INFO"

    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_9
    const-string p1, "WARN"

    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_a
    const-string p1, "ERROR"

    .line 94
    .line 95
    :goto_1
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    const-string p1, "] not recognized."

    .line 99
    .line 100
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    throw p0

    .line 111
    :cond_b
    invoke-interface {p0}, Lt21/b;->a()Z

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    return p0

    .line 116
    :cond_c
    invoke-interface {p0}, Lt21/b;->c()Z

    .line 117
    .line 118
    .line 119
    move-result p0

    .line 120
    return p0

    .line 121
    :cond_d
    invoke-interface {p0}, Lt21/b;->b()Z

    .line 122
    .line 123
    .line 124
    move-result p0

    .line 125
    return p0

    .line 126
    :cond_e
    invoke-interface {p0}, Lt21/b;->d()Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    return p0
.end method
