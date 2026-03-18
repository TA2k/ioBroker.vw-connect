.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final ASSIGNED_CLIENT_IDENTIFIER_IDENTIFIER:B = 0x12t

.field public static final AUTH_DATA_IDENTIFIER:B = 0x16t

.field public static final AUTH_METHOD_IDENTIFIER:B = 0x15t

.field public static final CONTENT_TYPE_IDENTIFIER:B = 0x3t

.field public static final CORRELATION_DATA_IDENTIFIER:B = 0x9t

.field public static final MAXIMUM_PACKET_SIZE_IDENTIFIER:B = 0x27t

.field public static final MAXIMUM_QOS_IDENTIFIER:B = 0x24t

.field public static final MESSAGE_EXPIRY_INTERVAL_IDENTIFIER:B = 0x2t

.field public static final PAYLOAD_FORMAT_INDICATOR_IDENTIFIER:B = 0x1t

.field public static final REASON_STRING_IDENTIFIER:B = 0x1ft

.field public static final RECEIVE_MAXIMUM_IDENTIFIER:B = 0x21t

.field public static final REQUEST_PROBLEM_INFO_IDENTIFIER:B = 0x17t

.field public static final REQUEST_RESPONSE_INFO_IDENTIFIER:B = 0x19t

.field public static final RESPONSE_INFO_IDENTIFIER:B = 0x1at

.field public static final RESPONSE_TOPIC_IDENTIFIER:B = 0x8t

.field public static final RETAIN_AVAILABLE_IDENTIFIER:B = 0x25t

.field public static final SERVER_KEEP_ALIVE_IDENTIFIER:B = 0x13t

.field public static final SERVER_REFERENCE_IDENTIFIER:B = 0x1ct

.field public static final SESSION_EXPIRY_INTERVAL_IDENTIFIER:B = 0x11t

.field public static final SHARED_SUBSCRIPTION_AVAILABLE_IDENTIFIER:B = 0x2at

.field public static final SUBSCRIPTION_AVAILABLE_IDENTIFIER:B = 0x29t

.field public static final SUBSCRIPTION_IDENTIFIER:B = 0xbt

.field public static final SUBSCRIPTION_IDENTIFIER_MULTI:B = 0x7et

.field public static final SUBSCRIPTION_IDENTIFIER_SINGLE:B = 0x7ft

.field public static final TOPIC_ALIAS_IDENTIFIER:B = 0x23t

.field public static final TOPIC_ALIAS_MAXIMUM_IDENTIFIER:B = 0x22t

.field public static final USER_DEFINED_PAIR_IDENTIFIER:B = 0x26t

.field public static final WILDCARD_SUB_AVAILABLE_IDENTIFIER:B = 0x28t

.field public static final WILL_DELAY_INTERVAL_IDENTIFIER:B = 0x18t


# instance fields
.field private assignedClientIdentifier:Ljava/lang/String;

.field private authenticationData:[B

.field private authenticationMethod:Ljava/lang/String;

.field private contentType:Ljava/lang/String;

.field private correlationData:[B

.field private maximumPacketSize:Ljava/lang/Long;

.field private maximumQoS:Ljava/lang/Integer;

.field private messageExpiryInterval:Ljava/lang/Long;

.field private payloadFormat:Ljava/lang/Boolean;

.field private publishSubscriptionIdentifiers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field private reasonString:Ljava/lang/String;

.field private receiveMaximum:Ljava/lang/Integer;

.field private requestProblemInfo:Ljava/lang/Boolean;

.field private requestResponseInfo:Ljava/lang/Boolean;

.field private responseInfo:Ljava/lang/String;

.field private responseTopic:Ljava/lang/String;

.field private retainAvailable:Ljava/lang/Boolean;

.field private serverKeepAlive:Ljava/lang/Integer;

.field private serverReference:Ljava/lang/String;

.field private sessionExpiryInterval:Ljava/lang/Long;

.field private sharedSubscriptionAvailable:Ljava/lang/Boolean;

.field private subscribeSubscriptionIdentifier:Ljava/lang/Integer;

.field private subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

.field private topicAlias:Ljava/lang/Integer;

.field private topicAliasMaximum:Ljava/lang/Integer;

.field private userProperties:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;",
            ">;"
        }
    .end annotation
.end field

.field private validProperties:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Byte;",
            ">;"
        }
    .end annotation
.end field

.field private wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

.field private willDelayInterval:Ljava/lang/Long;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->payloadFormat:Ljava/lang/Boolean;

    const/4 v0, 0x0

    .line 3
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->retainAvailable:Ljava/lang/Boolean;

    .line 4
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 5
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

    .line 6
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sharedSubscriptionAvailable:Ljava/lang/Boolean;

    .line 7
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->userProperties:Ljava/util/List;

    .line 8
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->publishSubscriptionIdentifiers:Ljava/util/List;

    return-void
.end method

.method public constructor <init>([Ljava/lang/Byte;)V
    .locals 1

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->payloadFormat:Ljava/lang/Boolean;

    const/4 v0, 0x0

    .line 11
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->retainAvailable:Ljava/lang/Boolean;

    .line 12
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 13
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

    .line 14
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sharedSubscriptionAvailable:Ljava/lang/Boolean;

    .line 15
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->userProperties:Ljava/util/List;

    .line 16
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->publishSubscriptionIdentifiers:Ljava/util/List;

    .line 17
    invoke-static {p1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public decodeProperties(Ljava/io/DataInputStream;)V
    .locals 8

    .line 1
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->readVariableByteInteger(Ljava/io/DataInputStream;)Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;->getValue()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-lez v0, :cond_22

    .line 10
    .line 11
    new-array v1, v0, [B

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-virtual {p1, v1, v2, v0}, Ljava/io/DataInputStream;->read([BII)I

    .line 15
    .line 16
    .line 17
    new-instance p1, Ljava/io/ByteArrayInputStream;

    .line 18
    .line 19
    invoke-direct {p1, v1}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 20
    .line 21
    .line 22
    new-instance v0, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 25
    .line 26
    .line 27
    new-instance v1, Ljava/io/DataInputStream;

    .line 28
    .line 29
    invoke-direct {v1, p1}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V

    .line 30
    .line 31
    .line 32
    :goto_0
    invoke-virtual {v1}, Ljava/io/InputStream;->available()I

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    if-gtz p1, :cond_0

    .line 37
    .line 38
    goto/16 :goto_4

    .line 39
    .line 40
    :cond_0
    invoke-virtual {v1}, Ljava/io/DataInputStream;->readByte()B

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 45
    .line 46
    invoke-static {p1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    invoke-interface {v3, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    const v4, 0xc350

    .line 55
    .line 56
    .line 57
    if-eqz v3, :cond_21

    .line 58
    .line 59
    invoke-static {p1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    const/16 v5, 0x26

    .line 68
    .line 69
    const/16 v6, 0xb

    .line 70
    .line 71
    if-nez v3, :cond_1

    .line 72
    .line 73
    invoke-static {p1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_1
    if-eq p1, v6, :cond_3

    .line 82
    .line 83
    if-ne p1, v5, :cond_2

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_2
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 87
    .line 88
    const p1, 0xc355

    .line 89
    .line 90
    .line 91
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 92
    .line 93
    .line 94
    throw p0

    .line 95
    :cond_3
    :goto_1
    const/4 v3, 0x1

    .line 96
    if-ne p1, v3, :cond_4

    .line 97
    .line 98
    invoke-virtual {v1}, Ljava/io/DataInputStream;->readBoolean()Z

    .line 99
    .line 100
    .line 101
    move-result p1

    .line 102
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->payloadFormat:Ljava/lang/Boolean;

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_4
    const/4 v7, 0x2

    .line 110
    if-ne p1, v7, :cond_5

    .line 111
    .line 112
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->readUnsignedFourByteInt(Ljava/io/DataInputStream;)Ljava/lang/Long;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->messageExpiryInterval:Ljava/lang/Long;

    .line 117
    .line 118
    goto :goto_0

    .line 119
    :cond_5
    const/4 v7, 0x3

    .line 120
    if-ne p1, v7, :cond_6

    .line 121
    .line 122
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->contentType:Ljava/lang/String;

    .line 127
    .line 128
    goto :goto_0

    .line 129
    :cond_6
    const/16 v7, 0x8

    .line 130
    .line 131
    if-ne p1, v7, :cond_7

    .line 132
    .line 133
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseTopic:Ljava/lang/String;

    .line 138
    .line 139
    goto :goto_0

    .line 140
    :cond_7
    const/16 v7, 0x9

    .line 141
    .line 142
    if-ne p1, v7, :cond_8

    .line 143
    .line 144
    invoke-virtual {v1}, Ljava/io/DataInputStream;->readShort()S

    .line 145
    .line 146
    .line 147
    move-result p1

    .line 148
    new-array v3, p1, [B

    .line 149
    .line 150
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->correlationData:[B

    .line 151
    .line 152
    invoke-virtual {v1, v3, v2, p1}, Ljava/io/DataInputStream;->read([BII)I

    .line 153
    .line 154
    .line 155
    goto :goto_0

    .line 156
    :cond_8
    if-ne p1, v6, :cond_9

    .line 157
    .line 158
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->readVariableByteInteger(Ljava/io/DataInputStream;)Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;

    .line 159
    .line 160
    .line 161
    move-result-object p1

    .line 162
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;->getValue()I

    .line 163
    .line 164
    .line 165
    move-result p1

    .line 166
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->publishSubscriptionIdentifiers:Ljava/util/List;

    .line 167
    .line 168
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 169
    .line 170
    .line 171
    move-result-object v4

    .line 172
    invoke-interface {v3, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 176
    .line 177
    .line 178
    move-result-object p1

    .line 179
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscribeSubscriptionIdentifier:Ljava/lang/Integer;

    .line 180
    .line 181
    goto/16 :goto_0

    .line 182
    .line 183
    :cond_9
    const/16 v6, 0x11

    .line 184
    .line 185
    if-ne p1, v6, :cond_a

    .line 186
    .line 187
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->readUnsignedFourByteInt(Ljava/io/DataInputStream;)Ljava/lang/Long;

    .line 188
    .line 189
    .line 190
    move-result-object p1

    .line 191
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sessionExpiryInterval:Ljava/lang/Long;

    .line 192
    .line 193
    goto/16 :goto_0

    .line 194
    .line 195
    :cond_a
    const/16 v6, 0x12

    .line 196
    .line 197
    if-ne p1, v6, :cond_b

    .line 198
    .line 199
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->assignedClientIdentifier:Ljava/lang/String;

    .line 204
    .line 205
    goto/16 :goto_0

    .line 206
    .line 207
    :cond_b
    const/16 v6, 0x13

    .line 208
    .line 209
    if-ne p1, v6, :cond_c

    .line 210
    .line 211
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->readUnsignedTwoByteInt(Ljava/io/DataInputStream;)I

    .line 212
    .line 213
    .line 214
    move-result p1

    .line 215
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 216
    .line 217
    .line 218
    move-result-object p1

    .line 219
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverKeepAlive:Ljava/lang/Integer;

    .line 220
    .line 221
    goto/16 :goto_0

    .line 222
    .line 223
    :cond_c
    const/16 v6, 0x15

    .line 224
    .line 225
    if-ne p1, v6, :cond_d

    .line 226
    .line 227
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object p1

    .line 231
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationMethod:Ljava/lang/String;

    .line 232
    .line 233
    goto/16 :goto_0

    .line 234
    .line 235
    :cond_d
    const/16 v6, 0x16

    .line 236
    .line 237
    if-ne p1, v6, :cond_e

    .line 238
    .line 239
    invoke-virtual {v1}, Ljava/io/DataInputStream;->readShort()S

    .line 240
    .line 241
    .line 242
    move-result p1

    .line 243
    new-array v3, p1, [B

    .line 244
    .line 245
    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationData:[B

    .line 246
    .line 247
    invoke-virtual {v1, v3, v2, p1}, Ljava/io/DataInputStream;->read([BII)I

    .line 248
    .line 249
    .line 250
    goto/16 :goto_0

    .line 251
    .line 252
    :cond_e
    const/16 v6, 0x17

    .line 253
    .line 254
    if-ne p1, v6, :cond_10

    .line 255
    .line 256
    invoke-virtual {v1}, Ljava/io/InputStream;->read()I

    .line 257
    .line 258
    .line 259
    move-result p1

    .line 260
    if-eqz p1, :cond_f

    .line 261
    .line 262
    goto :goto_2

    .line 263
    :cond_f
    move v3, v2

    .line 264
    :goto_2
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 265
    .line 266
    .line 267
    move-result-object p1

    .line 268
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestProblemInfo:Ljava/lang/Boolean;

    .line 269
    .line 270
    goto/16 :goto_0

    .line 271
    .line 272
    :cond_10
    const/16 v6, 0x18

    .line 273
    .line 274
    if-ne p1, v6, :cond_11

    .line 275
    .line 276
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->readUnsignedFourByteInt(Ljava/io/DataInputStream;)Ljava/lang/Long;

    .line 277
    .line 278
    .line 279
    move-result-object p1

    .line 280
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->willDelayInterval:Ljava/lang/Long;

    .line 281
    .line 282
    goto/16 :goto_0

    .line 283
    .line 284
    :cond_11
    const/16 v6, 0x19

    .line 285
    .line 286
    if-ne p1, v6, :cond_13

    .line 287
    .line 288
    invoke-virtual {v1}, Ljava/io/InputStream;->read()I

    .line 289
    .line 290
    .line 291
    move-result p1

    .line 292
    if-eqz p1, :cond_12

    .line 293
    .line 294
    goto :goto_3

    .line 295
    :cond_12
    move v3, v2

    .line 296
    :goto_3
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 297
    .line 298
    .line 299
    move-result-object p1

    .line 300
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestResponseInfo:Ljava/lang/Boolean;

    .line 301
    .line 302
    goto/16 :goto_0

    .line 303
    .line 304
    :cond_13
    const/16 v3, 0x1a

    .line 305
    .line 306
    if-ne p1, v3, :cond_14

    .line 307
    .line 308
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object p1

    .line 312
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseInfo:Ljava/lang/String;

    .line 313
    .line 314
    goto/16 :goto_0

    .line 315
    .line 316
    :cond_14
    const/16 v3, 0x1c

    .line 317
    .line 318
    if-ne p1, v3, :cond_15

    .line 319
    .line 320
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object p1

    .line 324
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverReference:Ljava/lang/String;

    .line 325
    .line 326
    goto/16 :goto_0

    .line 327
    .line 328
    :cond_15
    const/16 v3, 0x1f

    .line 329
    .line 330
    if-ne p1, v3, :cond_16

    .line 331
    .line 332
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    .line 333
    .line 334
    .line 335
    move-result-object p1

    .line 336
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->reasonString:Ljava/lang/String;

    .line 337
    .line 338
    goto/16 :goto_0

    .line 339
    .line 340
    :cond_16
    const/16 v3, 0x21

    .line 341
    .line 342
    if-ne p1, v3, :cond_17

    .line 343
    .line 344
    invoke-virtual {v1}, Ljava/io/DataInputStream;->readShort()S

    .line 345
    .line 346
    .line 347
    move-result p1

    .line 348
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 349
    .line 350
    .line 351
    move-result-object p1

    .line 352
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->receiveMaximum:Ljava/lang/Integer;

    .line 353
    .line 354
    goto/16 :goto_0

    .line 355
    .line 356
    :cond_17
    const/16 v3, 0x22

    .line 357
    .line 358
    if-ne p1, v3, :cond_18

    .line 359
    .line 360
    invoke-virtual {v1}, Ljava/io/DataInputStream;->readShort()S

    .line 361
    .line 362
    .line 363
    move-result p1

    .line 364
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 365
    .line 366
    .line 367
    move-result-object p1

    .line 368
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAliasMaximum:Ljava/lang/Integer;

    .line 369
    .line 370
    goto/16 :goto_0

    .line 371
    .line 372
    :cond_18
    const/16 v3, 0x23

    .line 373
    .line 374
    if-ne p1, v3, :cond_19

    .line 375
    .line 376
    invoke-virtual {v1}, Ljava/io/DataInputStream;->readShort()S

    .line 377
    .line 378
    .line 379
    move-result p1

    .line 380
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 381
    .line 382
    .line 383
    move-result-object p1

    .line 384
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAlias:Ljava/lang/Integer;

    .line 385
    .line 386
    goto/16 :goto_0

    .line 387
    .line 388
    :cond_19
    const/16 v3, 0x24

    .line 389
    .line 390
    if-ne p1, v3, :cond_1a

    .line 391
    .line 392
    invoke-virtual {v1}, Ljava/io/InputStream;->read()I

    .line 393
    .line 394
    .line 395
    move-result p1

    .line 396
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 397
    .line 398
    .line 399
    move-result-object p1

    .line 400
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumQoS:Ljava/lang/Integer;

    .line 401
    .line 402
    goto/16 :goto_0

    .line 403
    .line 404
    :cond_1a
    const/16 v3, 0x25

    .line 405
    .line 406
    if-ne p1, v3, :cond_1b

    .line 407
    .line 408
    invoke-virtual {v1}, Ljava/io/DataInputStream;->readBoolean()Z

    .line 409
    .line 410
    .line 411
    move-result p1

    .line 412
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 413
    .line 414
    .line 415
    move-result-object p1

    .line 416
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->retainAvailable:Ljava/lang/Boolean;

    .line 417
    .line 418
    goto/16 :goto_0

    .line 419
    .line 420
    :cond_1b
    if-ne p1, v5, :cond_1c

    .line 421
    .line 422
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    .line 423
    .line 424
    .line 425
    move-result-object p1

    .line 426
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;

    .line 427
    .line 428
    .line 429
    move-result-object v3

    .line 430
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->userProperties:Ljava/util/List;

    .line 431
    .line 432
    new-instance v5, Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

    .line 433
    .line 434
    invoke-direct {v5, p1, v3}, Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 435
    .line 436
    .line 437
    invoke-interface {v4, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 438
    .line 439
    .line 440
    goto/16 :goto_0

    .line 441
    .line 442
    :cond_1c
    const/16 v3, 0x27

    .line 443
    .line 444
    if-ne p1, v3, :cond_1d

    .line 445
    .line 446
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->readUnsignedFourByteInt(Ljava/io/DataInputStream;)Ljava/lang/Long;

    .line 447
    .line 448
    .line 449
    move-result-object p1

    .line 450
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumPacketSize:Ljava/lang/Long;

    .line 451
    .line 452
    goto/16 :goto_0

    .line 453
    .line 454
    :cond_1d
    const/16 v3, 0x28

    .line 455
    .line 456
    if-ne p1, v3, :cond_1e

    .line 457
    .line 458
    invoke-virtual {v1}, Ljava/io/DataInputStream;->readBoolean()Z

    .line 459
    .line 460
    .line 461
    move-result p1

    .line 462
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 463
    .line 464
    .line 465
    move-result-object p1

    .line 466
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 467
    .line 468
    goto/16 :goto_0

    .line 469
    .line 470
    :cond_1e
    const/16 v3, 0x29

    .line 471
    .line 472
    if-ne p1, v3, :cond_1f

    .line 473
    .line 474
    invoke-virtual {v1}, Ljava/io/DataInputStream;->readBoolean()Z

    .line 475
    .line 476
    .line 477
    move-result p1

    .line 478
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 479
    .line 480
    .line 481
    move-result-object p1

    .line 482
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

    .line 483
    .line 484
    goto/16 :goto_0

    .line 485
    .line 486
    :cond_1f
    const/16 v3, 0x2a

    .line 487
    .line 488
    if-ne p1, v3, :cond_20

    .line 489
    .line 490
    invoke-virtual {v1}, Ljava/io/DataInputStream;->readBoolean()Z

    .line 491
    .line 492
    .line 493
    move-result p1

    .line 494
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 495
    .line 496
    .line 497
    move-result-object p1

    .line 498
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sharedSubscriptionAvailable:Ljava/lang/Boolean;

    .line 499
    .line 500
    goto/16 :goto_0

    .line 501
    .line 502
    :cond_20
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V

    .line 503
    .line 504
    .line 505
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 506
    .line 507
    invoke-direct {p0, v4}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 508
    .line 509
    .line 510
    throw p0

    .line 511
    :cond_21
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V

    .line 512
    .line 513
    .line 514
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 515
    .line 516
    invoke-direct {p0, v4}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 517
    .line 518
    .line 519
    throw p0

    .line 520
    :cond_22
    :goto_4
    return-void
.end method

.method public encodeProperties()[B
    .locals 5

    .line 1
    :try_start_0
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/io/DataOutputStream;

    .line 7
    .line 8
    invoke-direct {v1, v0}, Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 9
    .line 10
    .line 11
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->payloadFormat:Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 20
    .line 21
    const/4 v3, 0x1

    .line 22
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_0

    .line 31
    .line 32
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 36
    .line 37
    .line 38
    :cond_0
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->messageExpiryInterval:Ljava/lang/Long;

    .line 39
    .line 40
    if-eqz v2, :cond_1

    .line 41
    .line 42
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 43
    .line 44
    const/4 v3, 0x2

    .line 45
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    if-eqz v2, :cond_1

    .line 54
    .line 55
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 56
    .line 57
    .line 58
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->messageExpiryInterval:Ljava/lang/Long;

    .line 59
    .line 60
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 61
    .line 62
    .line 63
    move-result-wide v2

    .line 64
    invoke-static {v2, v3, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->writeUnsignedFourByteInt(JLjava/io/DataOutputStream;)V

    .line 65
    .line 66
    .line 67
    :cond_1
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->contentType:Ljava/lang/String;

    .line 68
    .line 69
    if-eqz v2, :cond_2

    .line 70
    .line 71
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 72
    .line 73
    const/4 v3, 0x3

    .line 74
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    if-eqz v2, :cond_2

    .line 83
    .line 84
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 85
    .line 86
    .line 87
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->contentType:Ljava/lang/String;

    .line 88
    .line 89
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    :cond_2
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseTopic:Ljava/lang/String;

    .line 93
    .line 94
    if-eqz v2, :cond_3

    .line 95
    .line 96
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 97
    .line 98
    const/16 v3, 0x8

    .line 99
    .line 100
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v2

    .line 108
    if-eqz v2, :cond_3

    .line 109
    .line 110
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 111
    .line 112
    .line 113
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseTopic:Ljava/lang/String;

    .line 114
    .line 115
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    :cond_3
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->correlationData:[B

    .line 119
    .line 120
    if-eqz v2, :cond_4

    .line 121
    .line 122
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 123
    .line 124
    const/16 v3, 0x9

    .line 125
    .line 126
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 127
    .line 128
    .line 129
    move-result-object v4

    .line 130
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v2

    .line 134
    if-eqz v2, :cond_4

    .line 135
    .line 136
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 137
    .line 138
    .line 139
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->correlationData:[B

    .line 140
    .line 141
    array-length v2, v2

    .line 142
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 143
    .line 144
    .line 145
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->correlationData:[B

    .line 146
    .line 147
    invoke-virtual {v1, v2}, Ljava/io/OutputStream;->write([B)V

    .line 148
    .line 149
    .line 150
    :cond_4
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->publishSubscriptionIdentifiers:Ljava/util/List;

    .line 151
    .line 152
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 153
    .line 154
    .line 155
    move-result v2

    .line 156
    const/16 v3, 0xb

    .line 157
    .line 158
    if-nez v2, :cond_6

    .line 159
    .line 160
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 161
    .line 162
    const/16 v4, 0x7e

    .line 163
    .line 164
    invoke-static {v4}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 165
    .line 166
    .line 167
    move-result-object v4

    .line 168
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v2

    .line 172
    if-eqz v2, :cond_6

    .line 173
    .line 174
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->publishSubscriptionIdentifiers:Ljava/util/List;

    .line 175
    .line 176
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 177
    .line 178
    .line 179
    move-result-object v2

    .line 180
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 181
    .line 182
    .line 183
    move-result v4

    .line 184
    if-nez v4, :cond_5

    .line 185
    .line 186
    goto :goto_1

    .line 187
    :cond_5
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v4

    .line 191
    check-cast v4, Ljava/lang/Integer;

    .line 192
    .line 193
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 197
    .line 198
    .line 199
    move-result v4

    .line 200
    invoke-static {v4}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeVariableByteInteger(I)[B

    .line 201
    .line 202
    .line 203
    move-result-object v4

    .line 204
    invoke-virtual {v1, v4}, Ljava/io/OutputStream;->write([B)V

    .line 205
    .line 206
    .line 207
    goto :goto_0

    .line 208
    :cond_6
    :goto_1
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscribeSubscriptionIdentifier:Ljava/lang/Integer;

    .line 209
    .line 210
    if-eqz v2, :cond_7

    .line 211
    .line 212
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 213
    .line 214
    const/16 v4, 0x7f

    .line 215
    .line 216
    invoke-static {v4}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 217
    .line 218
    .line 219
    move-result-object v4

    .line 220
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    move-result v2

    .line 224
    if-eqz v2, :cond_7

    .line 225
    .line 226
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 227
    .line 228
    .line 229
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscribeSubscriptionIdentifier:Ljava/lang/Integer;

    .line 230
    .line 231
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 232
    .line 233
    .line 234
    move-result v2

    .line 235
    invoke-static {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeVariableByteInteger(I)[B

    .line 236
    .line 237
    .line 238
    move-result-object v2

    .line 239
    invoke-virtual {v1, v2}, Ljava/io/OutputStream;->write([B)V

    .line 240
    .line 241
    .line 242
    :cond_7
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sessionExpiryInterval:Ljava/lang/Long;

    .line 243
    .line 244
    if-eqz v2, :cond_8

    .line 245
    .line 246
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 247
    .line 248
    const/16 v3, 0x11

    .line 249
    .line 250
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 251
    .line 252
    .line 253
    move-result-object v4

    .line 254
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 255
    .line 256
    .line 257
    move-result v2

    .line 258
    if-eqz v2, :cond_8

    .line 259
    .line 260
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 261
    .line 262
    .line 263
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sessionExpiryInterval:Ljava/lang/Long;

    .line 264
    .line 265
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 266
    .line 267
    .line 268
    move-result-wide v2

    .line 269
    invoke-static {v2, v3, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->writeUnsignedFourByteInt(JLjava/io/DataOutputStream;)V

    .line 270
    .line 271
    .line 272
    :cond_8
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->assignedClientIdentifier:Ljava/lang/String;

    .line 273
    .line 274
    if-eqz v2, :cond_9

    .line 275
    .line 276
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 277
    .line 278
    const/16 v3, 0x12

    .line 279
    .line 280
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 281
    .line 282
    .line 283
    move-result-object v4

    .line 284
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 285
    .line 286
    .line 287
    move-result v2

    .line 288
    if-eqz v2, :cond_9

    .line 289
    .line 290
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 291
    .line 292
    .line 293
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->assignedClientIdentifier:Ljava/lang/String;

    .line 294
    .line 295
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    :cond_9
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverKeepAlive:Ljava/lang/Integer;

    .line 299
    .line 300
    if-eqz v2, :cond_a

    .line 301
    .line 302
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 303
    .line 304
    const/16 v3, 0x13

    .line 305
    .line 306
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 307
    .line 308
    .line 309
    move-result-object v4

    .line 310
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 311
    .line 312
    .line 313
    move-result v2

    .line 314
    if-eqz v2, :cond_a

    .line 315
    .line 316
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 317
    .line 318
    .line 319
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverKeepAlive:Ljava/lang/Integer;

    .line 320
    .line 321
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 322
    .line 323
    .line 324
    move-result v2

    .line 325
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 326
    .line 327
    .line 328
    :cond_a
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationMethod:Ljava/lang/String;

    .line 329
    .line 330
    if-eqz v2, :cond_b

    .line 331
    .line 332
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 333
    .line 334
    const/16 v3, 0x15

    .line 335
    .line 336
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 337
    .line 338
    .line 339
    move-result-object v4

    .line 340
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 341
    .line 342
    .line 343
    move-result v2

    .line 344
    if-eqz v2, :cond_b

    .line 345
    .line 346
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 347
    .line 348
    .line 349
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationMethod:Ljava/lang/String;

    .line 350
    .line 351
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 352
    .line 353
    .line 354
    :cond_b
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationData:[B

    .line 355
    .line 356
    if-eqz v2, :cond_c

    .line 357
    .line 358
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 359
    .line 360
    const/16 v3, 0x16

    .line 361
    .line 362
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 363
    .line 364
    .line 365
    move-result-object v4

    .line 366
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 367
    .line 368
    .line 369
    move-result v2

    .line 370
    if-eqz v2, :cond_c

    .line 371
    .line 372
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 373
    .line 374
    .line 375
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationData:[B

    .line 376
    .line 377
    array-length v2, v2

    .line 378
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 379
    .line 380
    .line 381
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationData:[B

    .line 382
    .line 383
    invoke-virtual {v1, v2}, Ljava/io/OutputStream;->write([B)V

    .line 384
    .line 385
    .line 386
    :cond_c
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestProblemInfo:Ljava/lang/Boolean;

    .line 387
    .line 388
    if-eqz v2, :cond_d

    .line 389
    .line 390
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 391
    .line 392
    const/16 v3, 0x17

    .line 393
    .line 394
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 395
    .line 396
    .line 397
    move-result-object v4

    .line 398
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 399
    .line 400
    .line 401
    move-result v2

    .line 402
    if-eqz v2, :cond_d

    .line 403
    .line 404
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 405
    .line 406
    .line 407
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestProblemInfo:Ljava/lang/Boolean;

    .line 408
    .line 409
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 410
    .line 411
    .line 412
    move-result v2

    .line 413
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->write(I)V

    .line 414
    .line 415
    .line 416
    :cond_d
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->willDelayInterval:Ljava/lang/Long;

    .line 417
    .line 418
    if-eqz v2, :cond_e

    .line 419
    .line 420
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 421
    .line 422
    const/16 v3, 0x18

    .line 423
    .line 424
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 425
    .line 426
    .line 427
    move-result-object v4

    .line 428
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 429
    .line 430
    .line 431
    move-result v2

    .line 432
    if-eqz v2, :cond_e

    .line 433
    .line 434
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 435
    .line 436
    .line 437
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->willDelayInterval:Ljava/lang/Long;

    .line 438
    .line 439
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 440
    .line 441
    .line 442
    move-result-wide v2

    .line 443
    invoke-static {v2, v3, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->writeUnsignedFourByteInt(JLjava/io/DataOutputStream;)V

    .line 444
    .line 445
    .line 446
    :cond_e
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestResponseInfo:Ljava/lang/Boolean;

    .line 447
    .line 448
    if-eqz v2, :cond_f

    .line 449
    .line 450
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 451
    .line 452
    const/16 v3, 0x19

    .line 453
    .line 454
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 455
    .line 456
    .line 457
    move-result-object v4

    .line 458
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 459
    .line 460
    .line 461
    move-result v2

    .line 462
    if-eqz v2, :cond_f

    .line 463
    .line 464
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 465
    .line 466
    .line 467
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestResponseInfo:Ljava/lang/Boolean;

    .line 468
    .line 469
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 470
    .line 471
    .line 472
    move-result v2

    .line 473
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->write(I)V

    .line 474
    .line 475
    .line 476
    :cond_f
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseInfo:Ljava/lang/String;

    .line 477
    .line 478
    if-eqz v2, :cond_10

    .line 479
    .line 480
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 481
    .line 482
    const/16 v3, 0x1a

    .line 483
    .line 484
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 485
    .line 486
    .line 487
    move-result-object v4

    .line 488
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 489
    .line 490
    .line 491
    move-result v2

    .line 492
    if-eqz v2, :cond_10

    .line 493
    .line 494
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 495
    .line 496
    .line 497
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseInfo:Ljava/lang/String;

    .line 498
    .line 499
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 500
    .line 501
    .line 502
    :cond_10
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverReference:Ljava/lang/String;

    .line 503
    .line 504
    if-eqz v2, :cond_11

    .line 505
    .line 506
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 507
    .line 508
    const/16 v3, 0x1c

    .line 509
    .line 510
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 511
    .line 512
    .line 513
    move-result-object v4

    .line 514
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 515
    .line 516
    .line 517
    move-result v2

    .line 518
    if-eqz v2, :cond_11

    .line 519
    .line 520
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 521
    .line 522
    .line 523
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverReference:Ljava/lang/String;

    .line 524
    .line 525
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 526
    .line 527
    .line 528
    :cond_11
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->reasonString:Ljava/lang/String;

    .line 529
    .line 530
    if-eqz v2, :cond_12

    .line 531
    .line 532
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 533
    .line 534
    const/16 v3, 0x1f

    .line 535
    .line 536
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 537
    .line 538
    .line 539
    move-result-object v4

    .line 540
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 541
    .line 542
    .line 543
    move-result v2

    .line 544
    if-eqz v2, :cond_12

    .line 545
    .line 546
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 547
    .line 548
    .line 549
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->reasonString:Ljava/lang/String;

    .line 550
    .line 551
    invoke-static {v1, v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 552
    .line 553
    .line 554
    :cond_12
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->receiveMaximum:Ljava/lang/Integer;

    .line 555
    .line 556
    if-eqz v2, :cond_13

    .line 557
    .line 558
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 559
    .line 560
    const/16 v3, 0x21

    .line 561
    .line 562
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 563
    .line 564
    .line 565
    move-result-object v4

    .line 566
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 567
    .line 568
    .line 569
    move-result v2

    .line 570
    if-eqz v2, :cond_13

    .line 571
    .line 572
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 573
    .line 574
    .line 575
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->receiveMaximum:Ljava/lang/Integer;

    .line 576
    .line 577
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 578
    .line 579
    .line 580
    move-result v2

    .line 581
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 582
    .line 583
    .line 584
    :cond_13
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAliasMaximum:Ljava/lang/Integer;

    .line 585
    .line 586
    if-eqz v2, :cond_14

    .line 587
    .line 588
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 589
    .line 590
    const/16 v3, 0x22

    .line 591
    .line 592
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 593
    .line 594
    .line 595
    move-result-object v4

    .line 596
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 597
    .line 598
    .line 599
    move-result v2

    .line 600
    if-eqz v2, :cond_14

    .line 601
    .line 602
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 603
    .line 604
    .line 605
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAliasMaximum:Ljava/lang/Integer;

    .line 606
    .line 607
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 608
    .line 609
    .line 610
    move-result v2

    .line 611
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 612
    .line 613
    .line 614
    :cond_14
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAlias:Ljava/lang/Integer;

    .line 615
    .line 616
    if-eqz v2, :cond_15

    .line 617
    .line 618
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 619
    .line 620
    const/16 v3, 0x23

    .line 621
    .line 622
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 623
    .line 624
    .line 625
    move-result-object v4

    .line 626
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 627
    .line 628
    .line 629
    move-result v2

    .line 630
    if-eqz v2, :cond_15

    .line 631
    .line 632
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 633
    .line 634
    .line 635
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAlias:Ljava/lang/Integer;

    .line 636
    .line 637
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 638
    .line 639
    .line 640
    move-result v2

    .line 641
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 642
    .line 643
    .line 644
    :cond_15
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumQoS:Ljava/lang/Integer;

    .line 645
    .line 646
    if-eqz v2, :cond_16

    .line 647
    .line 648
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 649
    .line 650
    const/16 v3, 0x24

    .line 651
    .line 652
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 653
    .line 654
    .line 655
    move-result-object v4

    .line 656
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 657
    .line 658
    .line 659
    move-result v2

    .line 660
    if-eqz v2, :cond_16

    .line 661
    .line 662
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 663
    .line 664
    .line 665
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumQoS:Ljava/lang/Integer;

    .line 666
    .line 667
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 668
    .line 669
    .line 670
    move-result v2

    .line 671
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 672
    .line 673
    .line 674
    :cond_16
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->retainAvailable:Ljava/lang/Boolean;

    .line 675
    .line 676
    if-eqz v2, :cond_17

    .line 677
    .line 678
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 679
    .line 680
    const/16 v3, 0x25

    .line 681
    .line 682
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 683
    .line 684
    .line 685
    move-result-object v4

    .line 686
    invoke-interface {v2, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 687
    .line 688
    .line 689
    move-result v2

    .line 690
    if-eqz v2, :cond_17

    .line 691
    .line 692
    invoke-virtual {v1, v3}, Ljava/io/DataOutputStream;->write(I)V

    .line 693
    .line 694
    .line 695
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->retainAvailable:Ljava/lang/Boolean;

    .line 696
    .line 697
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 698
    .line 699
    .line 700
    move-result v2

    .line 701
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeBoolean(Z)V

    .line 702
    .line 703
    .line 704
    :cond_17
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->userProperties:Ljava/util/List;

    .line 705
    .line 706
    if-eqz v2, :cond_19

    .line 707
    .line 708
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 709
    .line 710
    .line 711
    move-result v2

    .line 712
    if-nez v2, :cond_19

    .line 713
    .line 714
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 715
    .line 716
    const/16 v3, 0x26

    .line 717
    .line 718
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 719
    .line 720
    .line 721
    move-result-object v3

    .line 722
    invoke-interface {v2, v3}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 723
    .line 724
    .line 725
    move-result v2

    .line 726
    if-eqz v2, :cond_19

    .line 727
    .line 728
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->userProperties:Ljava/util/List;

    .line 729
    .line 730
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 731
    .line 732
    .line 733
    move-result-object v2

    .line 734
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 735
    .line 736
    .line 737
    move-result v3

    .line 738
    if-nez v3, :cond_18

    .line 739
    .line 740
    goto :goto_3

    .line 741
    :cond_18
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 742
    .line 743
    .line 744
    move-result-object v3

    .line 745
    check-cast v3, Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

    .line 746
    .line 747
    const/16 v4, 0x26

    .line 748
    .line 749
    invoke-virtual {v1, v4}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 750
    .line 751
    .line 752
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;->getKey()Ljava/lang/String;

    .line 753
    .line 754
    .line 755
    move-result-object v4

    .line 756
    invoke-static {v1, v4}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 757
    .line 758
    .line 759
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;->getValue()Ljava/lang/String;

    .line 760
    .line 761
    .line 762
    move-result-object v3

    .line 763
    invoke-static {v1, v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V

    .line 764
    .line 765
    .line 766
    goto :goto_2

    .line 767
    :cond_19
    :goto_3
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumPacketSize:Ljava/lang/Long;

    .line 768
    .line 769
    if-eqz v2, :cond_1a

    .line 770
    .line 771
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 772
    .line 773
    const/16 v3, 0x27

    .line 774
    .line 775
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 776
    .line 777
    .line 778
    move-result-object v3

    .line 779
    invoke-interface {v2, v3}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 780
    .line 781
    .line 782
    move-result v2

    .line 783
    if-eqz v2, :cond_1a

    .line 784
    .line 785
    const/16 v2, 0x27

    .line 786
    .line 787
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->write(I)V

    .line 788
    .line 789
    .line 790
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumPacketSize:Ljava/lang/Long;

    .line 791
    .line 792
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 793
    .line 794
    .line 795
    move-result-wide v2

    .line 796
    invoke-static {v2, v3, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->writeUnsignedFourByteInt(JLjava/io/DataOutputStream;)V

    .line 797
    .line 798
    .line 799
    :cond_1a
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 800
    .line 801
    if-eqz v2, :cond_1b

    .line 802
    .line 803
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 804
    .line 805
    const/16 v3, 0x28

    .line 806
    .line 807
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 808
    .line 809
    .line 810
    move-result-object v3

    .line 811
    invoke-interface {v2, v3}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 812
    .line 813
    .line 814
    move-result v2

    .line 815
    if-eqz v2, :cond_1b

    .line 816
    .line 817
    const/16 v2, 0x28

    .line 818
    .line 819
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->write(I)V

    .line 820
    .line 821
    .line 822
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 823
    .line 824
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 825
    .line 826
    .line 827
    move-result v2

    .line 828
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeBoolean(Z)V

    .line 829
    .line 830
    .line 831
    :cond_1b
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

    .line 832
    .line 833
    if-eqz v2, :cond_1c

    .line 834
    .line 835
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 836
    .line 837
    const/16 v3, 0x29

    .line 838
    .line 839
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 840
    .line 841
    .line 842
    move-result-object v3

    .line 843
    invoke-interface {v2, v3}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 844
    .line 845
    .line 846
    move-result v2

    .line 847
    if-eqz v2, :cond_1c

    .line 848
    .line 849
    const/16 v2, 0x29

    .line 850
    .line 851
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->write(I)V

    .line 852
    .line 853
    .line 854
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

    .line 855
    .line 856
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 857
    .line 858
    .line 859
    move-result v2

    .line 860
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeBoolean(Z)V

    .line 861
    .line 862
    .line 863
    :cond_1c
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sharedSubscriptionAvailable:Ljava/lang/Boolean;

    .line 864
    .line 865
    if-eqz v2, :cond_1d

    .line 866
    .line 867
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 868
    .line 869
    const/16 v3, 0x2a

    .line 870
    .line 871
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 872
    .line 873
    .line 874
    move-result-object v3

    .line 875
    invoke-interface {v2, v3}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 876
    .line 877
    .line 878
    move-result v2

    .line 879
    if-eqz v2, :cond_1d

    .line 880
    .line 881
    const/16 v2, 0x2a

    .line 882
    .line 883
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->write(I)V

    .line 884
    .line 885
    .line 886
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sharedSubscriptionAvailable:Ljava/lang/Boolean;

    .line 887
    .line 888
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 889
    .line 890
    .line 891
    move-result p0

    .line 892
    invoke-virtual {v1, p0}, Ljava/io/DataOutputStream;->writeBoolean(Z)V

    .line 893
    .line 894
    .line 895
    :cond_1d
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->size()I

    .line 896
    .line 897
    .line 898
    move-result p0

    .line 899
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    .line 900
    .line 901
    .line 902
    new-instance v1, Ljava/io/ByteArrayOutputStream;

    .line 903
    .line 904
    invoke-direct {v1}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 905
    .line 906
    .line 907
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->encodeVariableByteInteger(I)[B

    .line 908
    .line 909
    .line 910
    move-result-object p0

    .line 911
    invoke-virtual {v1, p0}, Ljava/io/OutputStream;->write([B)V

    .line 912
    .line 913
    .line 914
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 915
    .line 916
    .line 917
    move-result-object p0

    .line 918
    invoke-virtual {v1, p0}, Ljava/io/OutputStream;->write([B)V

    .line 919
    .line 920
    .line 921
    invoke-virtual {v1}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 922
    .line 923
    .line 924
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 925
    return-object p0

    .line 926
    :catch_0
    move-exception p0

    .line 927
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 928
    .line 929
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 930
    .line 931
    .line 932
    throw v0
.end method

.method public getAssignedClientIdentifier()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->assignedClientIdentifier:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getAuthenticationData()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationData:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public getAuthenticationMethod()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationMethod:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getContentType()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->contentType:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCorrelationData()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->correlationData:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public getMaximumPacketSize()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumPacketSize:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMaximumQoS()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumQoS:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMessageExpiryInterval()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->messageExpiryInterval:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public getPayloadFormat()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->payloadFormat:Ljava/lang/Boolean;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getReasonString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->reasonString:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReceiveMaximum()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->receiveMaximum:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getResponseInfo()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseInfo:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getResponseTopic()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseTopic:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getServerKeepAlive()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverKeepAlive:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getServerReference()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverReference:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSessionExpiryInterval()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sessionExpiryInterval:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSubscriptionIdentifier()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscribeSubscriptionIdentifier:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSubscriptionIdentifiers()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->publishSubscriptionIdentifiers:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTopicAlias()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAlias:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTopicAliasMaximum()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAliasMaximum:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getUserProperties()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->userProperties:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getValidProperties()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/Byte;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getWillDelayInterval()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->willDelayInterval:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public isRetainAvailable()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->retainAvailable:Ljava/lang/Boolean;

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_1
    :goto_0
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 16
    .line 17
    return-object p0
.end method

.method public isSharedSubscriptionAvailable()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sharedSubscriptionAvailable:Ljava/lang/Boolean;

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 15
    return p0
.end method

.method public isSubscriptionIdentifiersAvailable()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 15
    return p0
.end method

.method public isWildcardSubscriptionsAvailable()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 15
    return p0
.end method

.method public requestProblemInfo()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestProblemInfo:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public requestResponseInfo()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestResponseInfo:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public setAssignedClientIdentifier(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->assignedClientIdentifier:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setAuthenticationData([B)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationData:[B

    .line 2
    .line 3
    return-void
.end method

.method public setAuthenticationMethod(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationMethod:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setContentType(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->contentType:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setCorrelationData([B)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->correlationData:[B

    .line 2
    .line 3
    return-void
.end method

.method public setMaximumPacketSize(Ljava/lang/Long;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateFourByteInt(Ljava/lang/Long;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumPacketSize:Ljava/lang/Long;

    .line 5
    .line 6
    return-void
.end method

.method public setMaximumQoS(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumQoS:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public setMessageExpiryInterval(Ljava/lang/Long;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateFourByteInt(Ljava/lang/Long;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->messageExpiryInterval:Ljava/lang/Long;

    .line 5
    .line 6
    return-void
.end method

.method public setPayloadFormat(Z)V
    .locals 0

    .line 1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->payloadFormat:Ljava/lang/Boolean;

    .line 6
    .line 7
    return-void
.end method

.method public setReasonString(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->reasonString:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setReceiveMaximum(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateTwoByteInt(Ljava/lang/Integer;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->receiveMaximum:Ljava/lang/Integer;

    .line 5
    .line 6
    return-void
.end method

.method public setRequestProblemInfo(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestProblemInfo:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-void
.end method

.method public setRequestResponseInfo(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestResponseInfo:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-void
.end method

.method public setResponseInfo(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseInfo:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setResponseTopic(Ljava/lang/String;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const/4 v1, 0x1

    .line 5
    invoke-static {p1, v0, v1}, Lorg/eclipse/paho/mqttv5/common/util/MqttTopicValidator;->validate(Ljava/lang/String;ZZ)V

    .line 6
    .line 7
    .line 8
    :cond_0
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseTopic:Ljava/lang/String;

    .line 9
    .line 10
    return-void
.end method

.method public setRetainAvailable(Z)V
    .locals 0

    .line 1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->retainAvailable:Ljava/lang/Boolean;

    .line 6
    .line 7
    return-void
.end method

.method public setServerKeepAlive(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateTwoByteInt(Ljava/lang/Integer;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverKeepAlive:Ljava/lang/Integer;

    .line 5
    .line 6
    return-void
.end method

.method public setServerReference(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverReference:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setSessionExpiryInterval(Ljava/lang/Long;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateFourByteInt(Ljava/lang/Long;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sessionExpiryInterval:Ljava/lang/Long;

    .line 5
    .line 6
    return-void
.end method

.method public setSharedSubscriptionAvailable(Z)V
    .locals 0

    .line 1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sharedSubscriptionAvailable:Ljava/lang/Boolean;

    .line 6
    .line 7
    return-void
.end method

.method public setSubscriptionIdentifier(Ljava/lang/Integer;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateVariableByteInt(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscribeSubscriptionIdentifier:Ljava/lang/Integer;

    .line 9
    .line 10
    return-void
.end method

.method public setSubscriptionIdentifiers(Ljava/util/List;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/Integer;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->publishSubscriptionIdentifiers:Ljava/util/List;

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    check-cast v1, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateVariableByteInt(I)V

    .line 25
    .line 26
    .line 27
    goto :goto_0
.end method

.method public setSubscriptionIdentifiersAvailable(Z)V
    .locals 0

    .line 1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

    .line 6
    .line 7
    return-void
.end method

.method public setTopicAlias(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateTwoByteInt(Ljava/lang/Integer;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAlias:Ljava/lang/Integer;

    .line 5
    .line 6
    return-void
.end method

.method public setTopicAliasMaximum(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateTwoByteInt(Ljava/lang/Integer;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAliasMaximum:Ljava/lang/Integer;

    .line 5
    .line 6
    return-void
.end method

.method public setUserProperties(Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->userProperties:Ljava/util/List;

    .line 2
    .line 3
    return-void
.end method

.method public setValidProperties([Ljava/lang/Byte;)V
    .locals 0

    .line 1
    invoke-static {p1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 6
    .line 7
    return-void
.end method

.method public setWildcardSubscriptionsAvailable(Z)V
    .locals 0

    .line 1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 6
    .line 7
    return-void
.end method

.method public setWillDelayInterval(Ljava/lang/Long;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateFourByteInt(Ljava/lang/Long;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->willDelayInterval:Ljava/lang/Long;

    .line 5
    .line 6
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    const-string v2, "MqttProperties [validProperties="

    .line 9
    .line 10
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->validProperties:Ljava/util/List;

    .line 14
    .line 15
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestResponseInfo:Ljava/lang/Boolean;

    .line 26
    .line 27
    if-eqz v1, :cond_0

    .line 28
    .line 29
    new-instance v1, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    const-string v2, ", requestResponseInfo="

    .line 32
    .line 33
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestResponseInfo:Ljava/lang/Boolean;

    .line 37
    .line 38
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    :cond_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestProblemInfo:Ljava/lang/Boolean;

    .line 49
    .line 50
    if-eqz v1, :cond_1

    .line 51
    .line 52
    new-instance v1, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    const-string v2, ", requestProblemInfo="

    .line 55
    .line 56
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->requestProblemInfo:Ljava/lang/Boolean;

    .line 60
    .line 61
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    :cond_1
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->willDelayInterval:Ljava/lang/Long;

    .line 72
    .line 73
    if-eqz v1, :cond_2

    .line 74
    .line 75
    new-instance v1, Ljava/lang/StringBuilder;

    .line 76
    .line 77
    const-string v2, ", willDelayInterval="

    .line 78
    .line 79
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->willDelayInterval:Ljava/lang/Long;

    .line 83
    .line 84
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    :cond_2
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->receiveMaximum:Ljava/lang/Integer;

    .line 95
    .line 96
    if-eqz v1, :cond_3

    .line 97
    .line 98
    new-instance v1, Ljava/lang/StringBuilder;

    .line 99
    .line 100
    const-string v2, ", receiveMaximum="

    .line 101
    .line 102
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->receiveMaximum:Ljava/lang/Integer;

    .line 106
    .line 107
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    :cond_3
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumQoS:Ljava/lang/Integer;

    .line 118
    .line 119
    if-eqz v1, :cond_4

    .line 120
    .line 121
    new-instance v1, Ljava/lang/StringBuilder;

    .line 122
    .line 123
    const-string v2, ", maximumQoS="

    .line 124
    .line 125
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumQoS:Ljava/lang/Integer;

    .line 129
    .line 130
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v1

    .line 137
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    :cond_4
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumPacketSize:Ljava/lang/Long;

    .line 141
    .line 142
    if-eqz v1, :cond_5

    .line 143
    .line 144
    new-instance v1, Ljava/lang/StringBuilder;

    .line 145
    .line 146
    const-string v2, ", maximumPacketSize="

    .line 147
    .line 148
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->maximumPacketSize:Ljava/lang/Long;

    .line 152
    .line 153
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    :cond_5
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->retainAvailable:Ljava/lang/Boolean;

    .line 164
    .line 165
    if-eqz v1, :cond_6

    .line 166
    .line 167
    new-instance v1, Ljava/lang/StringBuilder;

    .line 168
    .line 169
    const-string v2, ", retainAvailable="

    .line 170
    .line 171
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->retainAvailable:Ljava/lang/Boolean;

    .line 175
    .line 176
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 177
    .line 178
    .line 179
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object v1

    .line 183
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    :cond_6
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->assignedClientIdentifier:Ljava/lang/String;

    .line 187
    .line 188
    if-eqz v1, :cond_7

    .line 189
    .line 190
    new-instance v1, Ljava/lang/StringBuilder;

    .line 191
    .line 192
    const-string v2, ", assignedClientIdentifier="

    .line 193
    .line 194
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->assignedClientIdentifier:Ljava/lang/String;

    .line 198
    .line 199
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 200
    .line 201
    .line 202
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v1

    .line 206
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 207
    .line 208
    .line 209
    :cond_7
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAliasMaximum:Ljava/lang/Integer;

    .line 210
    .line 211
    if-eqz v1, :cond_8

    .line 212
    .line 213
    new-instance v1, Ljava/lang/StringBuilder;

    .line 214
    .line 215
    const-string v2, ", topicAliasMaximum="

    .line 216
    .line 217
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAliasMaximum:Ljava/lang/Integer;

    .line 221
    .line 222
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 223
    .line 224
    .line 225
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v1

    .line 229
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 230
    .line 231
    .line 232
    :cond_8
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAlias:Ljava/lang/Integer;

    .line 233
    .line 234
    if-eqz v1, :cond_9

    .line 235
    .line 236
    new-instance v1, Ljava/lang/StringBuilder;

    .line 237
    .line 238
    const-string v2, ", topicAlias="

    .line 239
    .line 240
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->topicAlias:Ljava/lang/Integer;

    .line 244
    .line 245
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 246
    .line 247
    .line 248
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 249
    .line 250
    .line 251
    move-result-object v1

    .line 252
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 253
    .line 254
    .line 255
    :cond_9
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverKeepAlive:Ljava/lang/Integer;

    .line 256
    .line 257
    if-eqz v1, :cond_a

    .line 258
    .line 259
    new-instance v1, Ljava/lang/StringBuilder;

    .line 260
    .line 261
    const-string v2, ", serverKeepAlive="

    .line 262
    .line 263
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverKeepAlive:Ljava/lang/Integer;

    .line 267
    .line 268
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 269
    .line 270
    .line 271
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 276
    .line 277
    .line 278
    :cond_a
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseInfo:Ljava/lang/String;

    .line 279
    .line 280
    if-eqz v1, :cond_b

    .line 281
    .line 282
    new-instance v1, Ljava/lang/StringBuilder;

    .line 283
    .line 284
    const-string v2, ", responseInfo="

    .line 285
    .line 286
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseInfo:Ljava/lang/String;

    .line 290
    .line 291
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 292
    .line 293
    .line 294
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object v1

    .line 298
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 299
    .line 300
    .line 301
    :cond_b
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverReference:Ljava/lang/String;

    .line 302
    .line 303
    if-eqz v1, :cond_c

    .line 304
    .line 305
    new-instance v1, Ljava/lang/StringBuilder;

    .line 306
    .line 307
    const-string v2, ", serverReference="

    .line 308
    .line 309
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->serverReference:Ljava/lang/String;

    .line 313
    .line 314
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 315
    .line 316
    .line 317
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 318
    .line 319
    .line 320
    move-result-object v1

    .line 321
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 322
    .line 323
    .line 324
    :cond_c
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 325
    .line 326
    if-eqz v1, :cond_d

    .line 327
    .line 328
    new-instance v1, Ljava/lang/StringBuilder;

    .line 329
    .line 330
    const-string v2, ", wildcardSubscriptionsAvailable="

    .line 331
    .line 332
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 333
    .line 334
    .line 335
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->wildcardSubscriptionsAvailable:Ljava/lang/Boolean;

    .line 336
    .line 337
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 338
    .line 339
    .line 340
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v1

    .line 344
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 345
    .line 346
    .line 347
    :cond_d
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

    .line 348
    .line 349
    if-eqz v1, :cond_e

    .line 350
    .line 351
    new-instance v1, Ljava/lang/StringBuilder;

    .line 352
    .line 353
    const-string v2, ", subscriptionIdentifiersAvailable="

    .line 354
    .line 355
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->subscriptionIdentifiersAvailable:Ljava/lang/Boolean;

    .line 359
    .line 360
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 361
    .line 362
    .line 363
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 364
    .line 365
    .line 366
    move-result-object v1

    .line 367
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 368
    .line 369
    .line 370
    :cond_e
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sharedSubscriptionAvailable:Ljava/lang/Boolean;

    .line 371
    .line 372
    if-eqz v1, :cond_f

    .line 373
    .line 374
    new-instance v1, Ljava/lang/StringBuilder;

    .line 375
    .line 376
    const-string v2, ", sharedSubscriptionAvailable="

    .line 377
    .line 378
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 379
    .line 380
    .line 381
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sharedSubscriptionAvailable:Ljava/lang/Boolean;

    .line 382
    .line 383
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 384
    .line 385
    .line 386
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 387
    .line 388
    .line 389
    move-result-object v1

    .line 390
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 391
    .line 392
    .line 393
    :cond_f
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sessionExpiryInterval:Ljava/lang/Long;

    .line 394
    .line 395
    if-eqz v1, :cond_10

    .line 396
    .line 397
    new-instance v1, Ljava/lang/StringBuilder;

    .line 398
    .line 399
    const-string v2, ", sessionExpiryInterval="

    .line 400
    .line 401
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 402
    .line 403
    .line 404
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->sessionExpiryInterval:Ljava/lang/Long;

    .line 405
    .line 406
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 407
    .line 408
    .line 409
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 410
    .line 411
    .line 412
    move-result-object v1

    .line 413
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 414
    .line 415
    .line 416
    :cond_10
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationMethod:Ljava/lang/String;

    .line 417
    .line 418
    if-eqz v1, :cond_11

    .line 419
    .line 420
    new-instance v1, Ljava/lang/StringBuilder;

    .line 421
    .line 422
    const-string v2, ", authenticationMethod="

    .line 423
    .line 424
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 425
    .line 426
    .line 427
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationMethod:Ljava/lang/String;

    .line 428
    .line 429
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 430
    .line 431
    .line 432
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 433
    .line 434
    .line 435
    move-result-object v1

    .line 436
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 437
    .line 438
    .line 439
    :cond_11
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationData:[B

    .line 440
    .line 441
    if-eqz v1, :cond_12

    .line 442
    .line 443
    new-instance v1, Ljava/lang/StringBuilder;

    .line 444
    .line 445
    const-string v2, ", authenticationData="

    .line 446
    .line 447
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 448
    .line 449
    .line 450
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->authenticationData:[B

    .line 451
    .line 452
    invoke-static {v2}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;

    .line 453
    .line 454
    .line 455
    move-result-object v2

    .line 456
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 457
    .line 458
    .line 459
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 460
    .line 461
    .line 462
    move-result-object v1

    .line 463
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 464
    .line 465
    .line 466
    :cond_12
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->reasonString:Ljava/lang/String;

    .line 467
    .line 468
    if-eqz v1, :cond_13

    .line 469
    .line 470
    new-instance v1, Ljava/lang/StringBuilder;

    .line 471
    .line 472
    const-string v2, ", reasonString="

    .line 473
    .line 474
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 475
    .line 476
    .line 477
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->reasonString:Ljava/lang/String;

    .line 478
    .line 479
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 480
    .line 481
    .line 482
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 483
    .line 484
    .line 485
    move-result-object v1

    .line 486
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 487
    .line 488
    .line 489
    :cond_13
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->userProperties:Ljava/util/List;

    .line 490
    .line 491
    if-eqz v1, :cond_14

    .line 492
    .line 493
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 494
    .line 495
    .line 496
    move-result v1

    .line 497
    if-eqz v1, :cond_14

    .line 498
    .line 499
    new-instance v1, Ljava/lang/StringBuilder;

    .line 500
    .line 501
    const-string v2, ", userProperties="

    .line 502
    .line 503
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 504
    .line 505
    .line 506
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->userProperties:Ljava/util/List;

    .line 507
    .line 508
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 509
    .line 510
    .line 511
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 512
    .line 513
    .line 514
    move-result-object v1

    .line 515
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 516
    .line 517
    .line 518
    :cond_14
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->payloadFormat:Ljava/lang/Boolean;

    .line 519
    .line 520
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 521
    .line 522
    .line 523
    move-result v1

    .line 524
    if-eqz v1, :cond_15

    .line 525
    .line 526
    new-instance v1, Ljava/lang/StringBuilder;

    .line 527
    .line 528
    const-string v2, ", isUTF8="

    .line 529
    .line 530
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 531
    .line 532
    .line 533
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->payloadFormat:Ljava/lang/Boolean;

    .line 534
    .line 535
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 536
    .line 537
    .line 538
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 539
    .line 540
    .line 541
    move-result-object v1

    .line 542
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 543
    .line 544
    .line 545
    :cond_15
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->messageExpiryInterval:Ljava/lang/Long;

    .line 546
    .line 547
    if-eqz v1, :cond_16

    .line 548
    .line 549
    new-instance v1, Ljava/lang/StringBuilder;

    .line 550
    .line 551
    const-string v2, ", messageExpiryInterval="

    .line 552
    .line 553
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 554
    .line 555
    .line 556
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->messageExpiryInterval:Ljava/lang/Long;

    .line 557
    .line 558
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 559
    .line 560
    .line 561
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 562
    .line 563
    .line 564
    move-result-object v1

    .line 565
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 566
    .line 567
    .line 568
    :cond_16
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->contentType:Ljava/lang/String;

    .line 569
    .line 570
    if-eqz v1, :cond_17

    .line 571
    .line 572
    new-instance v1, Ljava/lang/StringBuilder;

    .line 573
    .line 574
    const-string v2, ", contentType="

    .line 575
    .line 576
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 577
    .line 578
    .line 579
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->contentType:Ljava/lang/String;

    .line 580
    .line 581
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 582
    .line 583
    .line 584
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 585
    .line 586
    .line 587
    move-result-object v1

    .line 588
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 589
    .line 590
    .line 591
    :cond_17
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseTopic:Ljava/lang/String;

    .line 592
    .line 593
    if-eqz v1, :cond_18

    .line 594
    .line 595
    new-instance v1, Ljava/lang/StringBuilder;

    .line 596
    .line 597
    const-string v2, ", responseTopic="

    .line 598
    .line 599
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 600
    .line 601
    .line 602
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->responseTopic:Ljava/lang/String;

    .line 603
    .line 604
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 605
    .line 606
    .line 607
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 608
    .line 609
    .line 610
    move-result-object v1

    .line 611
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 612
    .line 613
    .line 614
    :cond_18
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->correlationData:[B

    .line 615
    .line 616
    if-eqz v1, :cond_19

    .line 617
    .line 618
    new-instance v1, Ljava/lang/StringBuilder;

    .line 619
    .line 620
    const-string v2, ", correlationData="

    .line 621
    .line 622
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 623
    .line 624
    .line 625
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->correlationData:[B

    .line 626
    .line 627
    invoke-static {v2}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;

    .line 628
    .line 629
    .line 630
    move-result-object v2

    .line 631
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 632
    .line 633
    .line 634
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 635
    .line 636
    .line 637
    move-result-object v1

    .line 638
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 639
    .line 640
    .line 641
    :cond_19
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->publishSubscriptionIdentifiers:Ljava/util/List;

    .line 642
    .line 643
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 644
    .line 645
    .line 646
    move-result v1

    .line 647
    if-eqz v1, :cond_1a

    .line 648
    .line 649
    new-instance v1, Ljava/lang/StringBuilder;

    .line 650
    .line 651
    const-string v2, ", subscriptionIdentifiers="

    .line 652
    .line 653
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 654
    .line 655
    .line 656
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->publishSubscriptionIdentifiers:Ljava/util/List;

    .line 657
    .line 658
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 659
    .line 660
    .line 661
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 662
    .line 663
    .line 664
    move-result-object p0

    .line 665
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 666
    .line 667
    .line 668
    :cond_1a
    const-string p0, "]"

    .line 669
    .line 670
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 671
    .line 672
    .line 673
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 674
    .line 675
    .line 676
    move-result-object p0

    .line 677
    return-object p0
.end method
