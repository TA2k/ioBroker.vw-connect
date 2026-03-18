.class public final synthetic Lfl/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# virtual methods
.method public final intercept(Ld01/b0;)Ld01/t0;
    .locals 8

    .line 1
    const-string p0, ""

    .line 2
    .line 3
    check-cast p1, Li01/f;

    .line 4
    .line 5
    iget-object v0, p1, Li01/f;->e:Ld01/k0;

    .line 6
    .line 7
    invoke-virtual {v0}, Ld01/k0;->b()Ld01/j0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const-string v1, "00-"

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    :try_start_0
    sget-object v3, Ley0/e;->e:Ley0/a;

    .line 15
    .line 16
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/16 v4, 0x10

    .line 20
    .line 21
    new-array v4, v4, [B

    .line 22
    .line 23
    invoke-virtual {v3}, Ley0/a;->f()Ljava/util/Random;

    .line 24
    .line 25
    .line 26
    move-result-object v5

    .line 27
    invoke-virtual {v5, v4}, Ljava/util/Random;->nextBytes([B)V

    .line 28
    .line 29
    .line 30
    new-instance v5, Lf31/n;

    .line 31
    .line 32
    const/16 v6, 0x11

    .line 33
    .line 34
    invoke-direct {v5, v6}, Lf31/n;-><init>(I)V

    .line 35
    .line 36
    .line 37
    const/16 v6, 0x1e

    .line 38
    .line 39
    invoke-static {v4, p0, v5, v6}, Lmx0/n;->F([BLjava/lang/String;Lf31/n;I)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    const/16 v5, 0x8

    .line 47
    .line 48
    new-array v5, v5, [B

    .line 49
    .line 50
    invoke-virtual {v3}, Ley0/a;->f()Ljava/util/Random;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    invoke-virtual {v3, v5}, Ljava/util/Random;->nextBytes([B)V

    .line 55
    .line 56
    .line 57
    new-instance v3, Lf31/n;

    .line 58
    .line 59
    const/16 v7, 0x11

    .line 60
    .line 61
    invoke-direct {v3, v7}, Lf31/n;-><init>(I)V

    .line 62
    .line 63
    .line 64
    invoke-static {v5, p0, v3, v6}, Lmx0/n;->F([BLjava/lang/String;Lf31/n;I)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    sget-object v3, Lfl/l;->a:Ljava/lang/String;

    .line 69
    .line 70
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    if-nez v3, :cond_1

    .line 75
    .line 76
    sget-object v3, Lfl/l;->b:Ljava/lang/String;

    .line 77
    .line 78
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v3

    .line 82
    if-eqz v3, :cond_0

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_0
    new-instance v3, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    invoke-direct {v3, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, "-"

    .line 94
    .line 95
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string p0, "-01"

    .line 102
    .line 103
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v2
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 110
    goto :goto_0

    .line 111
    :catch_0
    move-exception p0

    .line 112
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    new-instance v1, Ljava/lang/StringBuilder;

    .line 117
    .line 118
    const-string v3, "Error generating trace header: "

    .line 119
    .line 120
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    const-string v1, "TraceContext"

    .line 131
    .line 132
    invoke-static {v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 133
    .line 134
    .line 135
    :cond_1
    :goto_0
    if-eqz v2, :cond_2

    .line 136
    .line 137
    const-string p0, "traceparent"

    .line 138
    .line 139
    invoke-virtual {v0, p0, v2}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    :cond_2
    new-instance p0, Ld01/k0;

    .line 143
    .line 144
    invoke-direct {p0, v0}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {p1, p0}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0
.end method
