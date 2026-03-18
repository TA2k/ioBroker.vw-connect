.class public final Lcom/google/crypto/tink/shaded/protobuf/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lcom/google/crypto/tink/shaded/protobuf/x0;


# instance fields
.field public final a:Lcom/google/crypto/tink/shaded/protobuf/m;

.field public final b:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/x0;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/crypto/tink/shaded/protobuf/x0;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/crypto/tink/shaded/protobuf/x0;->c:Lcom/google/crypto/tink/shaded/protobuf/x0;

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
    iput-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/x0;->b:Ljava/util/concurrent/ConcurrentHashMap;

    .line 10
    .line 11
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/m;

    .line 12
    .line 13
    invoke-direct {v0}, Lcom/google/crypto/tink/shaded/protobuf/m;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/x0;->a:Lcom/google/crypto/tink/shaded/protobuf/m;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/a1;
    .locals 8

    .line 1
    const-string v0, "messageType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/b0;->a(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/x0;->b:Ljava/util/concurrent/ConcurrentHashMap;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 13
    .line 14
    if-nez v1, :cond_a

    .line 15
    .line 16
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/x0;->a:Lcom/google/crypto/tink/shaded/protobuf/m;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 22
    .line 23
    const-class v1, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 24
    .line 25
    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-nez v2, :cond_1

    .line 30
    .line 31
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 32
    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    invoke-virtual {v2, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 43
    .line 44
    const-string p1, "Message classes must extend GeneratedMessage or GeneratedMessageLite"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_1
    :goto_0
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/l0;

    .line 53
    .line 54
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/l0;->a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/z0;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    iget p0, v2, Lcom/google/crypto/tink/shaded/protobuf/z0;->d:I

    .line 59
    .line 60
    iget-object v3, v2, Lcom/google/crypto/tink/shaded/protobuf/z0;->a:Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 61
    .line 62
    const/4 v4, 0x2

    .line 63
    and-int/2addr p0, v4

    .line 64
    const-string v5, "Protobuf runtime is not correctly loaded."

    .line 65
    .line 66
    if-ne p0, v4, :cond_4

    .line 67
    .line 68
    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    if-eqz p0, :cond_2

    .line 73
    .line 74
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/b1;->d:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 75
    .line 76
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/r;->a:Lcom/google/crypto/tink/shaded/protobuf/q;

    .line 77
    .line 78
    new-instance v2, Lcom/google/crypto/tink/shaded/protobuf/s0;

    .line 79
    .line 80
    invoke-direct {v2, p0, v1, v3}, Lcom/google/crypto/tink/shaded/protobuf/s0;-><init>(Lcom/google/crypto/tink/shaded/protobuf/d1;Lcom/google/crypto/tink/shaded/protobuf/q;Lcom/google/crypto/tink/shaded/protobuf/a;)V

    .line 81
    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_2
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/b1;->b:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 85
    .line 86
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/r;->b:Lcom/google/crypto/tink/shaded/protobuf/q;

    .line 87
    .line 88
    if-eqz v1, :cond_3

    .line 89
    .line 90
    new-instance v2, Lcom/google/crypto/tink/shaded/protobuf/s0;

    .line 91
    .line 92
    invoke-direct {v2, p0, v1, v3}, Lcom/google/crypto/tink/shaded/protobuf/s0;-><init>(Lcom/google/crypto/tink/shaded/protobuf/d1;Lcom/google/crypto/tink/shaded/protobuf/q;Lcom/google/crypto/tink/shaded/protobuf/a;)V

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
    iget p0, v2, Lcom/google/crypto/tink/shaded/protobuf/z0;->d:I

    .line 110
    .line 111
    and-int/2addr p0, v1

    .line 112
    if-ne p0, v1, :cond_5

    .line 113
    .line 114
    sget-object v3, Lcom/google/crypto/tink/shaded/protobuf/u0;->b:Lcom/google/crypto/tink/shaded/protobuf/t0;

    .line 115
    .line 116
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/j0;->b:Lcom/google/crypto/tink/shaded/protobuf/i0;

    .line 117
    .line 118
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/b1;->d:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 119
    .line 120
    sget-object v6, Lcom/google/crypto/tink/shaded/protobuf/r;->a:Lcom/google/crypto/tink/shaded/protobuf/q;

    .line 121
    .line 122
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/o0;->b:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 123
    .line 124
    invoke-static/range {v2 .. v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->x(Lcom/google/crypto/tink/shaded/protobuf/z0;Lcom/google/crypto/tink/shaded/protobuf/t0;Lcom/google/crypto/tink/shaded/protobuf/j0;Lcom/google/crypto/tink/shaded/protobuf/d1;Lcom/google/crypto/tink/shaded/protobuf/q;Lcom/google/crypto/tink/shaded/protobuf/n0;)Lcom/google/crypto/tink/shaded/protobuf/r0;

    .line 125
    .line 126
    .line 127
    move-result-object v2

    .line 128
    goto :goto_1

    .line 129
    :cond_5
    sget-object v3, Lcom/google/crypto/tink/shaded/protobuf/u0;->b:Lcom/google/crypto/tink/shaded/protobuf/t0;

    .line 130
    .line 131
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/j0;->b:Lcom/google/crypto/tink/shaded/protobuf/i0;

    .line 132
    .line 133
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/b1;->d:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 134
    .line 135
    const/4 v6, 0x0

    .line 136
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/o0;->b:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 137
    .line 138
    invoke-static/range {v2 .. v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->x(Lcom/google/crypto/tink/shaded/protobuf/z0;Lcom/google/crypto/tink/shaded/protobuf/t0;Lcom/google/crypto/tink/shaded/protobuf/j0;Lcom/google/crypto/tink/shaded/protobuf/d1;Lcom/google/crypto/tink/shaded/protobuf/q;Lcom/google/crypto/tink/shaded/protobuf/n0;)Lcom/google/crypto/tink/shaded/protobuf/r0;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    goto :goto_1

    .line 143
    :cond_6
    iget p0, v2, Lcom/google/crypto/tink/shaded/protobuf/z0;->d:I

    .line 144
    .line 145
    and-int/2addr p0, v1

    .line 146
    if-ne p0, v1, :cond_8

    .line 147
    .line 148
    sget-object v3, Lcom/google/crypto/tink/shaded/protobuf/u0;->a:Lcom/google/crypto/tink/shaded/protobuf/t0;

    .line 149
    .line 150
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/j0;->a:Lcom/google/crypto/tink/shaded/protobuf/h0;

    .line 151
    .line 152
    move-object p0, v5

    .line 153
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/b1;->b:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 154
    .line 155
    sget-object v6, Lcom/google/crypto/tink/shaded/protobuf/r;->b:Lcom/google/crypto/tink/shaded/protobuf/q;

    .line 156
    .line 157
    if-eqz v6, :cond_7

    .line 158
    .line 159
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/o0;->a:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 160
    .line 161
    invoke-static/range {v2 .. v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->x(Lcom/google/crypto/tink/shaded/protobuf/z0;Lcom/google/crypto/tink/shaded/protobuf/t0;Lcom/google/crypto/tink/shaded/protobuf/j0;Lcom/google/crypto/tink/shaded/protobuf/d1;Lcom/google/crypto/tink/shaded/protobuf/q;Lcom/google/crypto/tink/shaded/protobuf/n0;)Lcom/google/crypto/tink/shaded/protobuf/r0;

    .line 162
    .line 163
    .line 164
    move-result-object v2

    .line 165
    goto :goto_1

    .line 166
    :cond_7
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 167
    .line 168
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    throw p1

    .line 172
    :cond_8
    sget-object v3, Lcom/google/crypto/tink/shaded/protobuf/u0;->a:Lcom/google/crypto/tink/shaded/protobuf/t0;

    .line 173
    .line 174
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/j0;->a:Lcom/google/crypto/tink/shaded/protobuf/h0;

    .line 175
    .line 176
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/b1;->c:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 177
    .line 178
    const/4 v6, 0x0

    .line 179
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/o0;->a:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 180
    .line 181
    invoke-static/range {v2 .. v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->x(Lcom/google/crypto/tink/shaded/protobuf/z0;Lcom/google/crypto/tink/shaded/protobuf/t0;Lcom/google/crypto/tink/shaded/protobuf/j0;Lcom/google/crypto/tink/shaded/protobuf/d1;Lcom/google/crypto/tink/shaded/protobuf/q;Lcom/google/crypto/tink/shaded/protobuf/n0;)Lcom/google/crypto/tink/shaded/protobuf/r0;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    :goto_1
    invoke-virtual {v0, p1, v2}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object p0

    .line 189
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 190
    .line 191
    if-eqz p0, :cond_9

    .line 192
    .line 193
    return-object p0

    .line 194
    :cond_9
    return-object v2

    .line 195
    :cond_a
    return-object v1
.end method
