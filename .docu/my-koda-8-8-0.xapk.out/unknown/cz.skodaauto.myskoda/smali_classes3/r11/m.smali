.class public final Lr11/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr11/y;
.implements Lr11/w;


# instance fields
.field public final d:I


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lr11/m;->d:I

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 1

    .line 1
    iget p0, p0, Lr11/m;->d:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-ne p0, v0, :cond_0

    .line 5
    .line 6
    const/4 p0, 0x4

    .line 7
    return p0

    .line 8
    :cond_0
    const/16 p0, 0x14

    .line 9
    .line 10
    return p0
.end method

.method public final b(Ljava/lang/StringBuilder;JLjp/u1;ILn11/f;Ljava/util/Locale;)V
    .locals 5

    .line 1
    int-to-long p4, p5

    .line 2
    sub-long/2addr p2, p4

    .line 3
    const-string p4, ""

    .line 4
    .line 5
    if-nez p6, :cond_0

    .line 6
    .line 7
    goto/16 :goto_6

    .line 8
    .line 9
    :cond_0
    iget-object p5, p6, Ln11/f;->d:Ljava/lang/String;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    const/4 v1, 0x0

    .line 13
    const/4 v2, 0x1

    .line 14
    iget p0, p0, Lr11/m;->d:I

    .line 15
    .line 16
    if-eqz p0, :cond_9

    .line 17
    .line 18
    if-eq p0, v2, :cond_1

    .line 19
    .line 20
    goto/16 :goto_6

    .line 21
    .line 22
    :cond_1
    if-nez p7, :cond_2

    .line 23
    .line 24
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 25
    .line 26
    .line 27
    move-result-object p7

    .line 28
    :cond_2
    invoke-virtual {p6, p2, p3}, Ln11/f;->g(J)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    if-nez p0, :cond_3

    .line 33
    .line 34
    :goto_0
    move-object p4, p5

    .line 35
    goto/16 :goto_6

    .line 36
    .line 37
    :cond_3
    invoke-static {}, Ln11/f;->h()Ls11/f;

    .line 38
    .line 39
    .line 40
    move-result-object p4

    .line 41
    if-eqz p4, :cond_6

    .line 42
    .line 43
    invoke-virtual {p6, p2, p3}, Ln11/f;->i(J)I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    invoke-virtual {p6, p2, p3}, Ln11/f;->l(J)I

    .line 48
    .line 49
    .line 50
    move-result v4

    .line 51
    if-ne v3, v4, :cond_4

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_4
    move v2, v0

    .line 55
    :goto_1
    invoke-virtual {p4, p7, p5, p0, v2}, Ls11/f;->c(Ljava/util/Locale;Ljava/lang/String;Ljava/lang/String;Z)[Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    if-nez p0, :cond_5

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_5
    aget-object v1, p0, v0

    .line 63
    .line 64
    :goto_2
    move-object p4, v1

    .line 65
    goto :goto_3

    .line 66
    :cond_6
    invoke-virtual {p4, p5, p0, p7}, Ls11/f;->b(Ljava/lang/String;Ljava/lang/String;Ljava/util/Locale;)[Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    if-nez p0, :cond_7

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_7
    aget-object v1, p0, v0

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :goto_3
    if-eqz p4, :cond_8

    .line 77
    .line 78
    goto :goto_6

    .line 79
    :cond_8
    invoke-virtual {p6, p2, p3}, Ln11/f;->i(J)I

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    invoke-static {p0}, Ln11/f;->q(I)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p4

    .line 87
    goto :goto_6

    .line 88
    :cond_9
    if-nez p7, :cond_a

    .line 89
    .line 90
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 91
    .line 92
    .line 93
    move-result-object p7

    .line 94
    :cond_a
    invoke-virtual {p6, p2, p3}, Ln11/f;->g(J)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    if-nez p0, :cond_b

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_b
    invoke-static {}, Ln11/f;->h()Ls11/f;

    .line 102
    .line 103
    .line 104
    move-result-object p4

    .line 105
    if-eqz p4, :cond_e

    .line 106
    .line 107
    invoke-virtual {p6, p2, p3}, Ln11/f;->i(J)I

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    invoke-virtual {p6, p2, p3}, Ln11/f;->l(J)I

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    if-ne v3, v4, :cond_c

    .line 116
    .line 117
    move v0, v2

    .line 118
    :cond_c
    invoke-virtual {p4, p7, p5, p0, v0}, Ls11/f;->c(Ljava/util/Locale;Ljava/lang/String;Ljava/lang/String;Z)[Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    if-nez p0, :cond_d

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_d
    aget-object v1, p0, v2

    .line 126
    .line 127
    :goto_4
    move-object p4, v1

    .line 128
    goto :goto_5

    .line 129
    :cond_e
    invoke-virtual {p4, p5, p0, p7}, Ls11/f;->b(Ljava/lang/String;Ljava/lang/String;Ljava/util/Locale;)[Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    if-nez p0, :cond_f

    .line 134
    .line 135
    goto :goto_4

    .line 136
    :cond_f
    aget-object v1, p0, v2

    .line 137
    .line 138
    goto :goto_4

    .line 139
    :goto_5
    if-eqz p4, :cond_10

    .line 140
    .line 141
    goto :goto_6

    .line 142
    :cond_10
    invoke-virtual {p6, p2, p3}, Ln11/f;->i(J)I

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    invoke-static {p0}, Ln11/f;->q(I)Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object p4

    .line 150
    :goto_6
    invoke-virtual {p1, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 151
    .line 152
    .line 153
    return-void
.end method

.method public final c(Ljava/lang/StringBuilder;Lo11/b;Ljava/util/Locale;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final d(Lr11/s;Ljava/lang/CharSequence;I)I
    .locals 6

    .line 1
    sget-object p0, Ln11/c;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/util/Map;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    if-nez v0, :cond_2

    .line 11
    .line 12
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 15
    .line 16
    .line 17
    sget-object v2, Ln11/f;->e:Ln11/n;

    .line 18
    .line 19
    const-string v3, "UT"

    .line 20
    .line 21
    invoke-interface {v0, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    const-string v3, "UTC"

    .line 25
    .line 26
    invoke-interface {v0, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    const-string v3, "GMT"

    .line 30
    .line 31
    invoke-interface {v0, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    const-string v2, "EST"

    .line 35
    .line 36
    const-string v3, "America/New_York"

    .line 37
    .line 38
    invoke-static {v0, v2, v3}, Ln11/c;->b(Ljava/util/LinkedHashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string v2, "EDT"

    .line 42
    .line 43
    invoke-static {v0, v2, v3}, Ln11/c;->b(Ljava/util/LinkedHashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string v2, "CST"

    .line 47
    .line 48
    const-string v3, "America/Chicago"

    .line 49
    .line 50
    invoke-static {v0, v2, v3}, Ln11/c;->b(Ljava/util/LinkedHashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    const-string v2, "CDT"

    .line 54
    .line 55
    invoke-static {v0, v2, v3}, Ln11/c;->b(Ljava/util/LinkedHashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    const-string v2, "MST"

    .line 59
    .line 60
    const-string v3, "America/Denver"

    .line 61
    .line 62
    invoke-static {v0, v2, v3}, Ln11/c;->b(Ljava/util/LinkedHashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    const-string v2, "MDT"

    .line 66
    .line 67
    invoke-static {v0, v2, v3}, Ln11/c;->b(Ljava/util/LinkedHashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const-string v2, "PST"

    .line 71
    .line 72
    const-string v3, "America/Los_Angeles"

    .line 73
    .line 74
    invoke-static {v0, v2, v3}, Ln11/c;->b(Ljava/util/LinkedHashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    const-string v2, "PDT"

    .line 78
    .line 79
    invoke-static {v0, v2, v3}, Ln11/c;->b(Ljava/util/LinkedHashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    :cond_0
    invoke-virtual {p0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    if-eqz v0, :cond_1

    .line 91
    .line 92
    move-object v0, v2

    .line 93
    goto :goto_0

    .line 94
    :cond_1
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    if-eqz v0, :cond_0

    .line 99
    .line 100
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    move-object v0, p0

    .line 105
    check-cast v0, Ljava/util/Map;

    .line 106
    .line 107
    :cond_2
    :goto_0
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    move-object v2, v1

    .line 116
    :cond_3
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 117
    .line 118
    .line 119
    move-result v3

    .line 120
    if-eqz v3, :cond_5

    .line 121
    .line 122
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v3

    .line 126
    check-cast v3, Ljava/lang/String;

    .line 127
    .line 128
    invoke-static {p3, p2, v3}, Lvp/y1;->N(ILjava/lang/CharSequence;Ljava/lang/String;)Z

    .line 129
    .line 130
    .line 131
    move-result v4

    .line 132
    if-eqz v4, :cond_3

    .line 133
    .line 134
    if-eqz v2, :cond_4

    .line 135
    .line 136
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 137
    .line 138
    .line 139
    move-result v4

    .line 140
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 141
    .line 142
    .line 143
    move-result v5

    .line 144
    if-le v4, v5, :cond_3

    .line 145
    .line 146
    :cond_4
    move-object v2, v3

    .line 147
    goto :goto_1

    .line 148
    :cond_5
    if-eqz v2, :cond_6

    .line 149
    .line 150
    invoke-interface {v0, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    check-cast p0, Ln11/f;

    .line 155
    .line 156
    iput-object v1, p1, Lr11/s;->i:Lr11/r;

    .line 157
    .line 158
    iput-object p0, p1, Lr11/s;->d:Ln11/f;

    .line 159
    .line 160
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 161
    .line 162
    .line 163
    move-result p0

    .line 164
    add-int/2addr p0, p3

    .line 165
    return p0

    .line 166
    :cond_6
    not-int p0, p3

    .line 167
    return p0
.end method

.method public final e()I
    .locals 1

    .line 1
    iget p0, p0, Lr11/m;->d:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-ne p0, v0, :cond_0

    .line 5
    .line 6
    const/4 p0, 0x4

    .line 7
    return p0

    .line 8
    :cond_0
    const/16 p0, 0x14

    .line 9
    .line 10
    return p0
.end method
