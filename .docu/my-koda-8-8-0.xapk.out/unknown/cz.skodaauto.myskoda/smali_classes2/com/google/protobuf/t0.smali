.class public final Lcom/google/protobuf/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lcom/google/protobuf/t0;


# instance fields
.field public final a:Lcom/google/protobuf/f0;

.field public final b:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/protobuf/t0;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/protobuf/t0;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/protobuf/t0;->c:Lcom/google/protobuf/t0;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/google/protobuf/t0;->b:Ljava/util/concurrent/ConcurrentHashMap;

    .line 10
    .line 11
    new-instance v0, Lcom/google/protobuf/f0;

    .line 12
    .line 13
    invoke-direct {v0}, Lcom/google/protobuf/f0;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lcom/google/protobuf/t0;->a:Lcom/google/protobuf/f0;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Class;)Lcom/google/protobuf/w0;
    .locals 8

    .line 1
    sget-object v0, Lcom/google/protobuf/u;->a:Ljava/nio/charset/Charset;

    .line 2
    .line 3
    if-eqz p1, :cond_b

    .line 4
    .line 5
    iget-object v0, p0, Lcom/google/protobuf/t0;->b:Ljava/util/concurrent/ConcurrentHashMap;

    .line 6
    .line 7
    invoke-virtual {v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    check-cast v1, Lcom/google/protobuf/w0;

    .line 12
    .line 13
    if-nez v1, :cond_a

    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/protobuf/t0;->a:Lcom/google/protobuf/f0;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    sget-object v1, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 21
    .line 22
    const-class v1, Lcom/google/protobuf/p;

    .line 23
    .line 24
    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-nez v2, :cond_1

    .line 29
    .line 30
    sget-object v2, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 31
    .line 32
    if-eqz v2, :cond_1

    .line 33
    .line 34
    invoke-virtual {v2, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-eqz v2, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 42
    .line 43
    const-string p1, "Message classes must extend GeneratedMessageV3 or GeneratedMessageLite"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_1
    :goto_0
    iget-object p0, p0, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p0, Lcom/google/protobuf/e0;

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Lcom/google/protobuf/e0;->a(Ljava/lang/Class;)Lcom/google/protobuf/v0;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    iget p0, v2, Lcom/google/protobuf/v0;->d:I

    .line 58
    .line 59
    iget-object v3, v2, Lcom/google/protobuf/v0;->a:Lcom/google/protobuf/a;

    .line 60
    .line 61
    const/4 v4, 0x2

    .line 62
    and-int/2addr p0, v4

    .line 63
    const-string v5, "Protobuf runtime is not correctly loaded."

    .line 64
    .line 65
    if-ne p0, v4, :cond_4

    .line 66
    .line 67
    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    if-eqz p0, :cond_2

    .line 72
    .line 73
    sget-object p0, Lcom/google/protobuf/x0;->c:Lcom/google/protobuf/e1;

    .line 74
    .line 75
    sget-object v1, Lcom/google/protobuf/j;->a:Lcom/google/protobuf/i;

    .line 76
    .line 77
    new-instance v2, Lcom/google/protobuf/o0;

    .line 78
    .line 79
    invoke-direct {v2, p0, v1, v3}, Lcom/google/protobuf/o0;-><init>(Lcom/google/protobuf/e1;Lcom/google/protobuf/i;Lcom/google/protobuf/a;)V

    .line 80
    .line 81
    .line 82
    goto/16 :goto_1

    .line 83
    .line 84
    :cond_2
    sget-object p0, Lcom/google/protobuf/x0;->b:Lcom/google/protobuf/e1;

    .line 85
    .line 86
    sget-object v1, Lcom/google/protobuf/j;->b:Lcom/google/protobuf/i;

    .line 87
    .line 88
    if-eqz v1, :cond_3

    .line 89
    .line 90
    new-instance v2, Lcom/google/protobuf/o0;

    .line 91
    .line 92
    invoke-direct {v2, p0, v1, v3}, Lcom/google/protobuf/o0;-><init>(Lcom/google/protobuf/e1;Lcom/google/protobuf/i;Lcom/google/protobuf/a;)V

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 97
    .line 98
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    throw p0

    .line 102
    :cond_4
    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 103
    .line 104
    .line 105
    move-result p0

    .line 106
    const/4 v1, 0x1

    .line 107
    if-eqz p0, :cond_6

    .line 108
    .line 109
    invoke-virtual {v2}, Lcom/google/protobuf/v0;->a()I

    .line 110
    .line 111
    .line 112
    move-result p0

    .line 113
    invoke-static {p0}, Lu/w;->o(I)I

    .line 114
    .line 115
    .line 116
    move-result p0

    .line 117
    if-eq p0, v1, :cond_5

    .line 118
    .line 119
    sget-object v3, Lcom/google/protobuf/q0;->b:Lcom/google/protobuf/p0;

    .line 120
    .line 121
    sget-object v4, Lcom/google/protobuf/c0;->b:Lcom/google/protobuf/b0;

    .line 122
    .line 123
    sget-object v5, Lcom/google/protobuf/x0;->c:Lcom/google/protobuf/e1;

    .line 124
    .line 125
    sget-object v6, Lcom/google/protobuf/j;->a:Lcom/google/protobuf/i;

    .line 126
    .line 127
    sget-object v7, Lcom/google/protobuf/k0;->b:Lcom/google/protobuf/j0;

    .line 128
    .line 129
    invoke-static/range {v2 .. v7}, Lcom/google/protobuf/n0;->q(Lcom/google/protobuf/v0;Lcom/google/protobuf/p0;Lcom/google/protobuf/c0;Lcom/google/protobuf/e1;Lcom/google/protobuf/i;Lcom/google/protobuf/j0;)Lcom/google/protobuf/n0;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    goto :goto_1

    .line 134
    :cond_5
    sget-object v3, Lcom/google/protobuf/q0;->b:Lcom/google/protobuf/p0;

    .line 135
    .line 136
    sget-object v4, Lcom/google/protobuf/c0;->b:Lcom/google/protobuf/b0;

    .line 137
    .line 138
    sget-object v5, Lcom/google/protobuf/x0;->c:Lcom/google/protobuf/e1;

    .line 139
    .line 140
    const/4 v6, 0x0

    .line 141
    sget-object v7, Lcom/google/protobuf/k0;->b:Lcom/google/protobuf/j0;

    .line 142
    .line 143
    invoke-static/range {v2 .. v7}, Lcom/google/protobuf/n0;->q(Lcom/google/protobuf/v0;Lcom/google/protobuf/p0;Lcom/google/protobuf/c0;Lcom/google/protobuf/e1;Lcom/google/protobuf/i;Lcom/google/protobuf/j0;)Lcom/google/protobuf/n0;

    .line 144
    .line 145
    .line 146
    move-result-object v2

    .line 147
    goto :goto_1

    .line 148
    :cond_6
    invoke-virtual {v2}, Lcom/google/protobuf/v0;->a()I

    .line 149
    .line 150
    .line 151
    move-result p0

    .line 152
    invoke-static {p0}, Lu/w;->o(I)I

    .line 153
    .line 154
    .line 155
    move-result p0

    .line 156
    if-eq p0, v1, :cond_8

    .line 157
    .line 158
    sget-object v3, Lcom/google/protobuf/q0;->a:Lcom/google/protobuf/p0;

    .line 159
    .line 160
    sget-object v4, Lcom/google/protobuf/c0;->a:Lcom/google/protobuf/a0;

    .line 161
    .line 162
    move-object p0, v5

    .line 163
    sget-object v5, Lcom/google/protobuf/x0;->b:Lcom/google/protobuf/e1;

    .line 164
    .line 165
    sget-object v6, Lcom/google/protobuf/j;->b:Lcom/google/protobuf/i;

    .line 166
    .line 167
    if-eqz v6, :cond_7

    .line 168
    .line 169
    sget-object v7, Lcom/google/protobuf/k0;->a:Lcom/google/protobuf/j0;

    .line 170
    .line 171
    invoke-static/range {v2 .. v7}, Lcom/google/protobuf/n0;->q(Lcom/google/protobuf/v0;Lcom/google/protobuf/p0;Lcom/google/protobuf/c0;Lcom/google/protobuf/e1;Lcom/google/protobuf/i;Lcom/google/protobuf/j0;)Lcom/google/protobuf/n0;

    .line 172
    .line 173
    .line 174
    move-result-object v2

    .line 175
    goto :goto_1

    .line 176
    :cond_7
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 177
    .line 178
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    throw p1

    .line 182
    :cond_8
    sget-object v3, Lcom/google/protobuf/q0;->a:Lcom/google/protobuf/p0;

    .line 183
    .line 184
    sget-object v4, Lcom/google/protobuf/c0;->a:Lcom/google/protobuf/a0;

    .line 185
    .line 186
    sget-object v5, Lcom/google/protobuf/x0;->b:Lcom/google/protobuf/e1;

    .line 187
    .line 188
    const/4 v6, 0x0

    .line 189
    sget-object v7, Lcom/google/protobuf/k0;->a:Lcom/google/protobuf/j0;

    .line 190
    .line 191
    invoke-static/range {v2 .. v7}, Lcom/google/protobuf/n0;->q(Lcom/google/protobuf/v0;Lcom/google/protobuf/p0;Lcom/google/protobuf/c0;Lcom/google/protobuf/e1;Lcom/google/protobuf/i;Lcom/google/protobuf/j0;)Lcom/google/protobuf/n0;

    .line 192
    .line 193
    .line 194
    move-result-object v2

    .line 195
    :goto_1
    invoke-virtual {v0, p1, v2}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    check-cast p0, Lcom/google/protobuf/w0;

    .line 200
    .line 201
    if-eqz p0, :cond_9

    .line 202
    .line 203
    return-object p0

    .line 204
    :cond_9
    return-object v2

    .line 205
    :cond_a
    return-object v1

    .line 206
    :cond_b
    new-instance p0, Ljava/lang/NullPointerException;

    .line 207
    .line 208
    const-string p1, "messageType"

    .line 209
    .line 210
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    throw p0
.end method
