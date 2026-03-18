.class Lcom/squareup/moshi/StandardJsonAdapters$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/squareup/moshi/JsonAdapter$Factory;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/squareup/moshi/StandardJsonAdapters;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/reflect/Type;Ljava/util/Set;Lcom/squareup/moshi/Moshi;)Lcom/squareup/moshi/JsonAdapter;
    .locals 0

    .line 1
    invoke-interface {p2}, Ljava/util/Set;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    goto/16 :goto_0

    .line 8
    .line 9
    :cond_0
    sget-object p0, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 10
    .line 11
    if-ne p1, p0, :cond_1

    .line 12
    .line 13
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->b:Lcom/squareup/moshi/JsonAdapter;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_1
    sget-object p0, Ljava/lang/Byte;->TYPE:Ljava/lang/Class;

    .line 17
    .line 18
    if-ne p1, p0, :cond_2

    .line 19
    .line 20
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->c:Lcom/squareup/moshi/JsonAdapter;

    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_2
    sget-object p0, Ljava/lang/Character;->TYPE:Ljava/lang/Class;

    .line 24
    .line 25
    if-ne p1, p0, :cond_3

    .line 26
    .line 27
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->d:Lcom/squareup/moshi/JsonAdapter;

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_3
    sget-object p0, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    .line 31
    .line 32
    if-ne p1, p0, :cond_4

    .line 33
    .line 34
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->e:Lcom/squareup/moshi/JsonAdapter;

    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_4
    sget-object p0, Ljava/lang/Float;->TYPE:Ljava/lang/Class;

    .line 38
    .line 39
    if-ne p1, p0, :cond_5

    .line 40
    .line 41
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->f:Lcom/squareup/moshi/JsonAdapter;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_5
    sget-object p0, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 45
    .line 46
    if-ne p1, p0, :cond_6

    .line 47
    .line 48
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->g:Lcom/squareup/moshi/JsonAdapter;

    .line 49
    .line 50
    return-object p0

    .line 51
    :cond_6
    sget-object p0, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 52
    .line 53
    if-ne p1, p0, :cond_7

    .line 54
    .line 55
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->h:Lcom/squareup/moshi/JsonAdapter;

    .line 56
    .line 57
    return-object p0

    .line 58
    :cond_7
    sget-object p0, Ljava/lang/Short;->TYPE:Ljava/lang/Class;

    .line 59
    .line 60
    if-ne p1, p0, :cond_8

    .line 61
    .line 62
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->i:Lcom/squareup/moshi/JsonAdapter;

    .line 63
    .line 64
    return-object p0

    .line 65
    :cond_8
    const-class p0, Ljava/lang/Boolean;

    .line 66
    .line 67
    if-ne p1, p0, :cond_9

    .line 68
    .line 69
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->b:Lcom/squareup/moshi/JsonAdapter;

    .line 70
    .line 71
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    return-object p0

    .line 76
    :cond_9
    const-class p0, Ljava/lang/Byte;

    .line 77
    .line 78
    if-ne p1, p0, :cond_a

    .line 79
    .line 80
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->c:Lcom/squareup/moshi/JsonAdapter;

    .line 81
    .line 82
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    return-object p0

    .line 87
    :cond_a
    const-class p0, Ljava/lang/Character;

    .line 88
    .line 89
    if-ne p1, p0, :cond_b

    .line 90
    .line 91
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->d:Lcom/squareup/moshi/JsonAdapter;

    .line 92
    .line 93
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    return-object p0

    .line 98
    :cond_b
    const-class p0, Ljava/lang/Double;

    .line 99
    .line 100
    if-ne p1, p0, :cond_c

    .line 101
    .line 102
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->e:Lcom/squareup/moshi/JsonAdapter;

    .line 103
    .line 104
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    return-object p0

    .line 109
    :cond_c
    const-class p0, Ljava/lang/Float;

    .line 110
    .line 111
    if-ne p1, p0, :cond_d

    .line 112
    .line 113
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->f:Lcom/squareup/moshi/JsonAdapter;

    .line 114
    .line 115
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    return-object p0

    .line 120
    :cond_d
    const-class p0, Ljava/lang/Integer;

    .line 121
    .line 122
    if-ne p1, p0, :cond_e

    .line 123
    .line 124
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->g:Lcom/squareup/moshi/JsonAdapter;

    .line 125
    .line 126
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    return-object p0

    .line 131
    :cond_e
    const-class p0, Ljava/lang/Long;

    .line 132
    .line 133
    if-ne p1, p0, :cond_f

    .line 134
    .line 135
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->h:Lcom/squareup/moshi/JsonAdapter;

    .line 136
    .line 137
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    return-object p0

    .line 142
    :cond_f
    const-class p0, Ljava/lang/Short;

    .line 143
    .line 144
    if-ne p1, p0, :cond_10

    .line 145
    .line 146
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->i:Lcom/squareup/moshi/JsonAdapter;

    .line 147
    .line 148
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    return-object p0

    .line 153
    :cond_10
    const-class p0, Ljava/lang/String;

    .line 154
    .line 155
    if-ne p1, p0, :cond_11

    .line 156
    .line 157
    sget-object p0, Lcom/squareup/moshi/StandardJsonAdapters;->j:Lcom/squareup/moshi/JsonAdapter;

    .line 158
    .line 159
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    return-object p0

    .line 164
    :cond_11
    const-class p0, Ljava/lang/Object;

    .line 165
    .line 166
    if-ne p1, p0, :cond_12

    .line 167
    .line 168
    new-instance p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;

    .line 169
    .line 170
    invoke-direct {p0, p3}, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;-><init>(Lcom/squareup/moshi/Moshi;)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    return-object p0

    .line 178
    :cond_12
    invoke-static {p1}, Lcom/squareup/moshi/Types;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 179
    .line 180
    .line 181
    move-result-object p0

    .line 182
    invoke-static {p3, p1, p0}, Lax/b;->c(Lcom/squareup/moshi/Moshi;Ljava/lang/reflect/Type;Ljava/lang/Class;)Lax/a;

    .line 183
    .line 184
    .line 185
    move-result-object p1

    .line 186
    if-eqz p1, :cond_13

    .line 187
    .line 188
    return-object p1

    .line 189
    :cond_13
    invoke-virtual {p0}, Ljava/lang/Class;->isEnum()Z

    .line 190
    .line 191
    .line 192
    move-result p1

    .line 193
    if-eqz p1, :cond_14

    .line 194
    .line 195
    new-instance p1, Lcom/squareup/moshi/StandardJsonAdapters$EnumJsonAdapter;

    .line 196
    .line 197
    invoke-direct {p1, p0}, Lcom/squareup/moshi/StandardJsonAdapters$EnumJsonAdapter;-><init>(Ljava/lang/Class;)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    return-object p0

    .line 205
    :cond_14
    :goto_0
    const/4 p0, 0x0

    .line 206
    return-object p0
.end method
