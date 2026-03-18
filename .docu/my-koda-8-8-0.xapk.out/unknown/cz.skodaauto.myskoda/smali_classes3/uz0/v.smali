.class public final Luz0/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Luz0/v;

.field public static final b:Luz0/h1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Luz0/v;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Luz0/v;->a:Luz0/v;

    .line 7
    .line 8
    new-instance v0, Luz0/h1;

    .line 9
    .line 10
    const-string v1, "kotlin.time.Duration"

    .line 11
    .line 12
    sget-object v2, Lsz0/e;->j:Lsz0/e;

    .line 13
    .line 14
    invoke-direct {v0, v1, v2}, Luz0/h1;-><init>(Ljava/lang/String;Lsz0/f;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Luz0/v;->b:Luz0/h1;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 1

    .line 1
    sget p0, Lmy0/c;->g:I

    .line 2
    .line 3
    invoke-interface {p1}, Ltz0/c;->x()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {p0}, Lmy0/h;->o(Ljava/lang/String;)J

    .line 8
    .line 9
    .line 10
    move-result-wide p0

    .line 11
    new-instance v0, Lmy0/c;

    .line 12
    .line 13
    invoke-direct {v0, p0, p1}, Lmy0/c;-><init>(J)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Luz0/v;->b:Luz0/h1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 12

    .line 1
    check-cast p2, Lmy0/c;

    .line 2
    .line 3
    iget-wide v0, p2, Lmy0/c;->d:J

    .line 4
    .line 5
    sget p0, Lmy0/c;->g:I

    .line 6
    .line 7
    new-instance v2, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-static {v0, v1}, Lmy0/c;->h(J)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    const/16 p0, 0x2d

    .line 19
    .line 20
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    :cond_0
    const-string p0, "PT"

    .line 24
    .line 25
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-static {v0, v1}, Lmy0/c;->h(J)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eqz p0, :cond_1

    .line 33
    .line 34
    invoke-static {v0, v1}, Lmy0/c;->p(J)J

    .line 35
    .line 36
    .line 37
    move-result-wide v3

    .line 38
    goto :goto_0

    .line 39
    :cond_1
    move-wide v3, v0

    .line 40
    :goto_0
    sget-object p0, Lmy0/e;->j:Lmy0/e;

    .line 41
    .line 42
    invoke-static {v3, v4, p0}, Lmy0/c;->n(JLmy0/e;)J

    .line 43
    .line 44
    .line 45
    move-result-wide v5

    .line 46
    invoke-static {v3, v4}, Lmy0/c;->g(J)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    const/16 p2, 0x3c

    .line 51
    .line 52
    const/4 v7, 0x0

    .line 53
    if-eqz p0, :cond_2

    .line 54
    .line 55
    move p0, v7

    .line 56
    goto :goto_1

    .line 57
    :cond_2
    sget-object p0, Lmy0/e;->i:Lmy0/e;

    .line 58
    .line 59
    invoke-static {v3, v4, p0}, Lmy0/c;->n(JLmy0/e;)J

    .line 60
    .line 61
    .line 62
    move-result-wide v8

    .line 63
    int-to-long v10, p2

    .line 64
    rem-long/2addr v8, v10

    .line 65
    long-to-int p0, v8

    .line 66
    :goto_1
    invoke-static {v3, v4}, Lmy0/c;->g(J)Z

    .line 67
    .line 68
    .line 69
    move-result v8

    .line 70
    if-eqz v8, :cond_3

    .line 71
    .line 72
    move p2, v7

    .line 73
    goto :goto_2

    .line 74
    :cond_3
    sget-object v8, Lmy0/e;->h:Lmy0/e;

    .line 75
    .line 76
    invoke-static {v3, v4, v8}, Lmy0/c;->n(JLmy0/e;)J

    .line 77
    .line 78
    .line 79
    move-result-wide v8

    .line 80
    int-to-long v10, p2

    .line 81
    rem-long/2addr v8, v10

    .line 82
    long-to-int p2, v8

    .line 83
    :goto_2
    invoke-static {v3, v4}, Lmy0/c;->f(J)I

    .line 84
    .line 85
    .line 86
    move-result v4

    .line 87
    invoke-static {v0, v1}, Lmy0/c;->g(J)Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-eqz v0, :cond_4

    .line 92
    .line 93
    const-wide v5, 0x9184e729fffL

    .line 94
    .line 95
    .line 96
    .line 97
    .line 98
    :cond_4
    const-wide/16 v0, 0x0

    .line 99
    .line 100
    cmp-long v0, v5, v0

    .line 101
    .line 102
    const/4 v1, 0x1

    .line 103
    if-eqz v0, :cond_5

    .line 104
    .line 105
    move v0, v1

    .line 106
    goto :goto_3

    .line 107
    :cond_5
    move v0, v7

    .line 108
    :goto_3
    if-nez p2, :cond_7

    .line 109
    .line 110
    if-eqz v4, :cond_6

    .line 111
    .line 112
    goto :goto_4

    .line 113
    :cond_6
    move v3, v7

    .line 114
    goto :goto_5

    .line 115
    :cond_7
    :goto_4
    move v3, v1

    .line 116
    :goto_5
    if-nez p0, :cond_8

    .line 117
    .line 118
    if-eqz v3, :cond_9

    .line 119
    .line 120
    if-eqz v0, :cond_9

    .line 121
    .line 122
    :cond_8
    move v7, v1

    .line 123
    :cond_9
    if-eqz v0, :cond_a

    .line 124
    .line 125
    invoke-virtual {v2, v5, v6}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const/16 v1, 0x48

    .line 129
    .line 130
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    :cond_a
    if-eqz v7, :cond_b

    .line 134
    .line 135
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    const/16 p0, 0x4d

    .line 139
    .line 140
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    :cond_b
    if-nez v3, :cond_c

    .line 144
    .line 145
    if-nez v0, :cond_d

    .line 146
    .line 147
    if-nez v7, :cond_d

    .line 148
    .line 149
    :cond_c
    const-string v6, "S"

    .line 150
    .line 151
    const/4 v7, 0x1

    .line 152
    const/16 v5, 0x9

    .line 153
    .line 154
    move v3, p2

    .line 155
    invoke-static/range {v2 .. v7}, Lmy0/c;->b(Ljava/lang/StringBuilder;IIILjava/lang/String;Z)V

    .line 156
    .line 157
    .line 158
    :cond_d
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    invoke-interface {p1, p0}, Ltz0/d;->E(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    return-void
.end method
