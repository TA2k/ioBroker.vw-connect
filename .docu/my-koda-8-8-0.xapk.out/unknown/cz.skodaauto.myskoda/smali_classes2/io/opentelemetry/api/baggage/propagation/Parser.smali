.class Lio/opentelemetry/api/baggage/propagation/Parser;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/api/baggage/propagation/Parser$State;
    }
.end annotation


# instance fields
.field private final baggageHeader:Ljava/lang/String;

.field private final key:Lio/opentelemetry/api/baggage/propagation/Element;

.field private meta:Ljava/lang/String;

.field private metaStart:I

.field private skipToNext:Z

.field private state:Lio/opentelemetry/api/baggage/propagation/Parser$State;

.field private final value:Lio/opentelemetry/api/baggage/propagation/Element;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lio/opentelemetry/api/baggage/propagation/Element;->createKeyElement()Lio/opentelemetry/api/baggage/propagation/Element;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->key:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 9
    .line 10
    invoke-static {}, Lio/opentelemetry/api/baggage/propagation/Element;->createValueElement()Lio/opentelemetry/api/baggage/propagation/Element;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->value:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 15
    .line 16
    iput-object p1, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->baggageHeader:Ljava/lang/String;

    .line 17
    .line 18
    const/4 p1, 0x0

    .line 19
    invoke-direct {p0, p1}, Lio/opentelemetry/api/baggage/propagation/Parser;->reset(I)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method private static decodeValue(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .param p0    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 6
    .line 7
    invoke-static {p0, v0}, Lio/opentelemetry/api/baggage/propagation/BaggageCodec;->decode(Ljava/lang/String;Ljava/nio/charset/Charset;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static putBaggage(Lio/opentelemetry/api/baggage/BaggageBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-static {p2}, Lio/opentelemetry/api/baggage/propagation/Parser;->decodeValue(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    invoke-static {p3}, Lio/opentelemetry/api/baggage/propagation/Parser;->decodeValue(Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p3

    .line 9
    if-eqz p3, :cond_0

    .line 10
    .line 11
    invoke-static {p3}, Lio/opentelemetry/api/baggage/BaggageEntryMetadata;->create(Ljava/lang/String;)Lio/opentelemetry/api/baggage/BaggageEntryMetadata;

    .line 12
    .line 13
    .line 14
    move-result-object p3

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-static {}, Lio/opentelemetry/api/baggage/BaggageEntryMetadata;->empty()Lio/opentelemetry/api/baggage/BaggageEntryMetadata;

    .line 17
    .line 18
    .line 19
    move-result-object p3

    .line 20
    :goto_0
    if-eqz p1, :cond_1

    .line 21
    .line 22
    if-eqz p2, :cond_1

    .line 23
    .line 24
    invoke-interface {p0, p1, p2, p3}, Lio/opentelemetry/api/baggage/BaggageBuilder;->put(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntryMetadata;)Lio/opentelemetry/api/baggage/BaggageBuilder;

    .line 25
    .line 26
    .line 27
    :cond_1
    return-void
.end method

.method private reset(I)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->skipToNext:Z

    .line 3
    .line 4
    sget-object v1, Lio/opentelemetry/api/baggage/propagation/Parser$State;->KEY:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 5
    .line 6
    iput-object v1, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->state:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->key:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 9
    .line 10
    invoke-virtual {v1, p1}, Lio/opentelemetry/api/baggage/propagation/Element;->reset(I)V

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->value:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 14
    .line 15
    invoke-virtual {v1, p1}, Lio/opentelemetry/api/baggage/propagation/Element;->reset(I)V

    .line 16
    .line 17
    .line 18
    const-string p1, ""

    .line 19
    .line 20
    iput-object p1, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->meta:Ljava/lang/String;

    .line 21
    .line 22
    iput v0, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->metaStart:I

    .line 23
    .line 24
    return-void
.end method

.method private setState(Lio/opentelemetry/api/baggage/propagation/Parser$State;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->state:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 2
    .line 3
    iput p2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->metaStart:I

    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public parseInto(Lio/opentelemetry/api/baggage/BaggageBuilder;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->baggageHeader:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    :goto_0
    const/4 v2, 0x2

    .line 9
    const/4 v3, 0x1

    .line 10
    if-ge v1, v0, :cond_b

    .line 11
    .line 12
    iget-object v4, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->baggageHeader:Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {v4, v1}, Ljava/lang/String;->charAt(I)C

    .line 15
    .line 16
    .line 17
    move-result v4

    .line 18
    iget-boolean v5, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->skipToNext:Z

    .line 19
    .line 20
    const/16 v6, 0x2c

    .line 21
    .line 22
    if-eqz v5, :cond_0

    .line 23
    .line 24
    if-ne v4, v6, :cond_a

    .line 25
    .line 26
    add-int/lit8 v2, v1, 0x1

    .line 27
    .line 28
    invoke-direct {p0, v2}, Lio/opentelemetry/api/baggage/propagation/Parser;->reset(I)V

    .line 29
    .line 30
    .line 31
    goto/16 :goto_2

    .line 32
    .line 33
    :cond_0
    if-eq v4, v6, :cond_7

    .line 34
    .line 35
    const/16 v2, 0x3b

    .line 36
    .line 37
    if-eq v4, v2, :cond_6

    .line 38
    .line 39
    const/16 v2, 0x3d

    .line 40
    .line 41
    if-eq v4, v2, :cond_3

    .line 42
    .line 43
    iget-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->state:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 44
    .line 45
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-eqz v2, :cond_2

    .line 50
    .line 51
    if-eq v2, v3, :cond_1

    .line 52
    .line 53
    goto/16 :goto_2

    .line 54
    .line 55
    :cond_1
    iget-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->value:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 56
    .line 57
    invoke-virtual {v2, v4, v1}, Lio/opentelemetry/api/baggage/propagation/Element;->tryNextChar(CI)Z

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    xor-int/2addr v2, v3

    .line 62
    iput-boolean v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->skipToNext:Z

    .line 63
    .line 64
    goto/16 :goto_2

    .line 65
    .line 66
    :cond_2
    iget-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->key:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 67
    .line 68
    invoke-virtual {v2, v4, v1}, Lio/opentelemetry/api/baggage/propagation/Element;->tryNextChar(CI)Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    xor-int/2addr v2, v3

    .line 73
    iput-boolean v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->skipToNext:Z

    .line 74
    .line 75
    goto/16 :goto_2

    .line 76
    .line 77
    :cond_3
    iget-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->state:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 78
    .line 79
    sget-object v5, Lio/opentelemetry/api/baggage/propagation/Parser$State;->KEY:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 80
    .line 81
    if-ne v2, v5, :cond_5

    .line 82
    .line 83
    iget-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->key:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 84
    .line 85
    iget-object v4, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->baggageHeader:Ljava/lang/String;

    .line 86
    .line 87
    invoke-virtual {v2, v1, v4}, Lio/opentelemetry/api/baggage/propagation/Element;->tryTerminating(ILjava/lang/String;)Z

    .line 88
    .line 89
    .line 90
    move-result v2

    .line 91
    if-eqz v2, :cond_4

    .line 92
    .line 93
    sget-object v2, Lio/opentelemetry/api/baggage/propagation/Parser$State;->VALUE:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 94
    .line 95
    add-int/lit8 v3, v1, 0x1

    .line 96
    .line 97
    invoke-direct {p0, v2, v3}, Lio/opentelemetry/api/baggage/propagation/Parser;->setState(Lio/opentelemetry/api/baggage/propagation/Parser$State;I)V

    .line 98
    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_4
    iput-boolean v3, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->skipToNext:Z

    .line 102
    .line 103
    goto :goto_2

    .line 104
    :cond_5
    sget-object v5, Lio/opentelemetry/api/baggage/propagation/Parser$State;->VALUE:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 105
    .line 106
    if-ne v2, v5, :cond_a

    .line 107
    .line 108
    iget-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->value:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 109
    .line 110
    invoke-virtual {v2, v4, v1}, Lio/opentelemetry/api/baggage/propagation/Element;->tryNextChar(CI)Z

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    xor-int/2addr v2, v3

    .line 115
    iput-boolean v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->skipToNext:Z

    .line 116
    .line 117
    goto :goto_2

    .line 118
    :cond_6
    iget-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->state:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 119
    .line 120
    sget-object v4, Lio/opentelemetry/api/baggage/propagation/Parser$State;->VALUE:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 121
    .line 122
    if-ne v2, v4, :cond_a

    .line 123
    .line 124
    iget-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->value:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 125
    .line 126
    iget-object v4, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->baggageHeader:Ljava/lang/String;

    .line 127
    .line 128
    invoke-virtual {v2, v1, v4}, Lio/opentelemetry/api/baggage/propagation/Element;->tryTerminating(ILjava/lang/String;)Z

    .line 129
    .line 130
    .line 131
    move-result v2

    .line 132
    xor-int/2addr v2, v3

    .line 133
    iput-boolean v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->skipToNext:Z

    .line 134
    .line 135
    sget-object v2, Lio/opentelemetry/api/baggage/propagation/Parser$State;->META:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 136
    .line 137
    add-int/lit8 v3, v1, 0x1

    .line 138
    .line 139
    invoke-direct {p0, v2, v3}, Lio/opentelemetry/api/baggage/propagation/Parser;->setState(Lio/opentelemetry/api/baggage/propagation/Parser$State;I)V

    .line 140
    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_7
    iget-object v4, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->state:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 144
    .line 145
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 146
    .line 147
    .line 148
    move-result v4

    .line 149
    if-eq v4, v3, :cond_9

    .line 150
    .line 151
    if-eq v4, v2, :cond_8

    .line 152
    .line 153
    goto :goto_1

    .line 154
    :cond_8
    iget-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->baggageHeader:Ljava/lang/String;

    .line 155
    .line 156
    iget v3, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->metaStart:I

    .line 157
    .line 158
    invoke-virtual {v2, v3, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v2

    .line 162
    invoke-virtual {v2}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object v2

    .line 166
    iput-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->meta:Ljava/lang/String;

    .line 167
    .line 168
    goto :goto_1

    .line 169
    :cond_9
    iget-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->value:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 170
    .line 171
    iget-object v3, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->baggageHeader:Ljava/lang/String;

    .line 172
    .line 173
    invoke-virtual {v2, v1, v3}, Lio/opentelemetry/api/baggage/propagation/Element;->tryTerminating(ILjava/lang/String;)Z

    .line 174
    .line 175
    .line 176
    :goto_1
    iget-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->key:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 177
    .line 178
    invoke-virtual {v2}, Lio/opentelemetry/api/baggage/propagation/Element;->getValue()Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v2

    .line 182
    iget-object v3, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->value:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 183
    .line 184
    invoke-virtual {v3}, Lio/opentelemetry/api/baggage/propagation/Element;->getValue()Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v3

    .line 188
    iget-object v4, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->meta:Ljava/lang/String;

    .line 189
    .line 190
    invoke-static {p1, v2, v3, v4}, Lio/opentelemetry/api/baggage/propagation/Parser;->putBaggage(Lio/opentelemetry/api/baggage/BaggageBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    add-int/lit8 v2, v1, 0x1

    .line 194
    .line 195
    invoke-direct {p0, v2}, Lio/opentelemetry/api/baggage/propagation/Parser;->reset(I)V

    .line 196
    .line 197
    .line 198
    :cond_a
    :goto_2
    add-int/lit8 v1, v1, 0x1

    .line 199
    .line 200
    goto/16 :goto_0

    .line 201
    .line 202
    :cond_b
    iget-object v0, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->state:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 203
    .line 204
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 205
    .line 206
    .line 207
    move-result v0

    .line 208
    if-eq v0, v3, :cond_d

    .line 209
    .line 210
    if-eq v0, v2, :cond_c

    .line 211
    .line 212
    goto :goto_3

    .line 213
    :cond_c
    iget-object v0, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->baggageHeader:Ljava/lang/String;

    .line 214
    .line 215
    iget v1, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->metaStart:I

    .line 216
    .line 217
    invoke-virtual {v0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object v0

    .line 221
    invoke-virtual {v0}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object v0

    .line 225
    iget-object v1, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->key:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 226
    .line 227
    invoke-virtual {v1}, Lio/opentelemetry/api/baggage/propagation/Element;->getValue()Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object v1

    .line 231
    iget-object p0, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->value:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 232
    .line 233
    invoke-virtual {p0}, Lio/opentelemetry/api/baggage/propagation/Element;->getValue()Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    invoke-static {p1, v1, p0, v0}, Lio/opentelemetry/api/baggage/propagation/Parser;->putBaggage(Lio/opentelemetry/api/baggage/BaggageBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 238
    .line 239
    .line 240
    return-void

    .line 241
    :cond_d
    iget-boolean v0, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->skipToNext:Z

    .line 242
    .line 243
    if-nez v0, :cond_e

    .line 244
    .line 245
    iget-object v0, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->value:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 246
    .line 247
    iget-object v1, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->baggageHeader:Ljava/lang/String;

    .line 248
    .line 249
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 250
    .line 251
    .line 252
    move-result v1

    .line 253
    iget-object v2, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->baggageHeader:Ljava/lang/String;

    .line 254
    .line 255
    invoke-virtual {v0, v1, v2}, Lio/opentelemetry/api/baggage/propagation/Element;->tryTerminating(ILjava/lang/String;)Z

    .line 256
    .line 257
    .line 258
    iget-object v0, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->key:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 259
    .line 260
    invoke-virtual {v0}, Lio/opentelemetry/api/baggage/propagation/Element;->getValue()Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v0

    .line 264
    iget-object p0, p0, Lio/opentelemetry/api/baggage/propagation/Parser;->value:Lio/opentelemetry/api/baggage/propagation/Element;

    .line 265
    .line 266
    invoke-virtual {p0}, Lio/opentelemetry/api/baggage/propagation/Element;->getValue()Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object p0

    .line 270
    const/4 v1, 0x0

    .line 271
    invoke-static {p1, v0, p0, v1}, Lio/opentelemetry/api/baggage/propagation/Parser;->putBaggage(Lio/opentelemetry/api/baggage/BaggageBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    :cond_e
    :goto_3
    return-void
.end method
