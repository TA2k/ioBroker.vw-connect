.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000L\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\r\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\t\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u0000 ,2\u00020\u0001:\u0001,BC\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0006\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0008\u0012\u0008\u0008\u0002\u0010\t\u001a\u00020\n\u0012\u0008\u0008\u0002\u0010\u000b\u001a\u00020\u000c\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u0008\u0010\u001d\u001a\u00020\u001eH\u0016J\t\u0010\u001f\u001a\u00020\u0003H\u00c6\u0003J\t\u0010 \u001a\u00020\u0003H\u00c6\u0003J\t\u0010!\u001a\u00020\u0006H\u00c6\u0003J\t\u0010\"\u001a\u00020\u0008H\u00c6\u0003J\t\u0010#\u001a\u00020\nH\u00c6\u0003J\t\u0010$\u001a\u00020\u000cH\u00c6\u0003JE\u0010%\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00062\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u00082\u0008\u0008\u0002\u0010\t\u001a\u00020\n2\u0008\u0008\u0002\u0010\u000b\u001a\u00020\u000cH\u00c6\u0001J\u0013\u0010&\u001a\u00020\n2\u0008\u0010\'\u001a\u0004\u0018\u00010(H\u00d6\u0003J\t\u0010)\u001a\u00020\u0003H\u00d6\u0001J\t\u0010*\u001a\u00020+H\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\u0010R\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u0010R\u0011\u0010\u0005\u001a\u00020\u0006\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0012\u0010\u0013R\u0011\u0010\u0007\u001a\u00020\u0008\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0014\u0010\u0015R\u0011\u0010\t\u001a\u00020\n\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\t\u0010\u0016R\u0011\u0010\u000b\u001a\u00020\u000c\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0017\u0010\u0018R\u0014\u0010\u0019\u001a\u00020\u001aX\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001b\u0010\u001c\u00a8\u0006-"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;",
        "aliveCounter",
        "",
        "aliveAcknowledge",
        "functionStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;",
        "obstacleArea",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;",
        "isTouchDiagnosisRequest",
        "",
        "stoppingReasonStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;",
        "<init>",
        "(IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;)V",
        "getAliveCounter",
        "()I",
        "getAliveAcknowledge",
        "getFunctionStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;",
        "getObstacleArea",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;",
        "()Z",
        "getStoppingReasonStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;",
        "definition",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "getDefinition",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "toBytes",
        "",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "component6",
        "copy",
        "equals",
        "other",
        "",
        "hashCode",
        "toString",
        "",
        "Companion",
        "remoteparkassistcoremeb_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field private static final ALIVE_ACKNOWLEDGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ALIVE_COUNTER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE$Companion;

.field private static final FUNCTION_STATUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_10:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_11:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_12:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_13:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_14:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_15:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_16:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_2:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_3:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_4:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_5:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_6:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_7:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_8:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final OBSTACLE_AREA_Object_9:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final STOPPING_REASON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final TOUCH_DIAGNOSIS_REQUEST:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final address:J

.field private static final byteLength:I

.field private static final messageID:B

.field private static final priority:B

.field private static final requiresQueuing:Z


# instance fields
.field private final aliveAcknowledge:I

.field private final aliveCounter:I

.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

.field private final functionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

.field private final isTouchDiagnosisRequest:Z

.field private final obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

.field private final stoppingReasonStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE$Companion;

    .line 8
    .line 9
    const/16 v0, 0x21

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->messageID:B

    .line 12
    .line 13
    const-wide v1, 0x5250400101000000L    # 3.232604083940867E88

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->address:J

    .line 19
    .line 20
    const/4 v1, 0x3

    .line 21
    sput-byte v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->priority:B

    .line 22
    .line 23
    const/4 v1, 0x1

    .line 24
    sput-boolean v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->requiresQueuing:Z

    .line 25
    .line 26
    const/4 v2, 0x6

    .line 27
    sput v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->byteLength:I

    .line 28
    .line 29
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 30
    .line 31
    const/4 v4, 0x0

    .line 32
    const/16 v5, 0x8

    .line 33
    .line 34
    invoke-direct {v3, v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 35
    .line 36
    .line 37
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->ALIVE_COUNTER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 38
    .line 39
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 40
    .line 41
    invoke-direct {v3, v5, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 42
    .line 43
    .line 44
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->ALIVE_ACKNOWLEDGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 45
    .line 46
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 47
    .line 48
    const/16 v4, 0x10

    .line 49
    .line 50
    const/4 v5, 0x4

    .line 51
    invoke-direct {v3, v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 52
    .line 53
    .line 54
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->FUNCTION_STATUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 55
    .line 56
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 57
    .line 58
    const/16 v4, 0x14

    .line 59
    .line 60
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 61
    .line 62
    .line 63
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 64
    .line 65
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 66
    .line 67
    const/16 v4, 0x15

    .line 68
    .line 69
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 70
    .line 71
    .line 72
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_2:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 73
    .line 74
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 75
    .line 76
    const/16 v4, 0x16

    .line 77
    .line 78
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 79
    .line 80
    .line 81
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_3:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 82
    .line 83
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 84
    .line 85
    const/16 v4, 0x17

    .line 86
    .line 87
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 88
    .line 89
    .line 90
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_4:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 91
    .line 92
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 93
    .line 94
    const/16 v4, 0x18

    .line 95
    .line 96
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 97
    .line 98
    .line 99
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_5:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 100
    .line 101
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 102
    .line 103
    const/16 v4, 0x19

    .line 104
    .line 105
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 106
    .line 107
    .line 108
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_6:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 109
    .line 110
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 111
    .line 112
    const/16 v4, 0x1a

    .line 113
    .line 114
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 115
    .line 116
    .line 117
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_7:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 118
    .line 119
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 120
    .line 121
    const/16 v4, 0x1b

    .line 122
    .line 123
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 124
    .line 125
    .line 126
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_8:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 127
    .line 128
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 129
    .line 130
    const/16 v4, 0x1c

    .line 131
    .line 132
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 133
    .line 134
    .line 135
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_9:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 136
    .line 137
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 138
    .line 139
    const/16 v4, 0x1d

    .line 140
    .line 141
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 142
    .line 143
    .line 144
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_10:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 145
    .line 146
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 147
    .line 148
    const/16 v4, 0x1e

    .line 149
    .line 150
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 151
    .line 152
    .line 153
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_11:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 154
    .line 155
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 156
    .line 157
    const/16 v4, 0x1f

    .line 158
    .line 159
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 160
    .line 161
    .line 162
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_12:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 163
    .line 164
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 165
    .line 166
    const/16 v4, 0x20

    .line 167
    .line 168
    invoke-direct {v3, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 169
    .line 170
    .line 171
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_13:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 172
    .line 173
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 174
    .line 175
    invoke-direct {v3, v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 176
    .line 177
    .line 178
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_14:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 179
    .line 180
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 181
    .line 182
    const/16 v3, 0x22

    .line 183
    .line 184
    invoke-direct {v0, v3, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 185
    .line 186
    .line 187
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_15:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 188
    .line 189
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 190
    .line 191
    const/16 v3, 0x23

    .line 192
    .line 193
    invoke-direct {v0, v3, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 194
    .line 195
    .line 196
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_16:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 197
    .line 198
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 199
    .line 200
    const/16 v3, 0x24

    .line 201
    .line 202
    invoke-direct {v0, v3, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 203
    .line 204
    .line 205
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->TOUCH_DIAGNOSIS_REQUEST:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 206
    .line 207
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 208
    .line 209
    const/16 v1, 0x25

    .line 210
    .line 211
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 212
    .line 213
    .line 214
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->STOPPING_REASON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 215
    .line 216
    return-void
.end method

.method public constructor <init>()V
    .locals 9

    .line 1
    const/16 v7, 0x3f

    const/4 v8, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;-><init>(IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;)V
    .locals 1

    const-string v0, "functionStatus"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "obstacleArea"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "stoppingReasonStatus"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveCounter:I

    .line 4
    iput p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveAcknowledge:I

    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->functionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 6
    iput-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 7
    iput-boolean p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->isTouchDiagnosisRequest:Z

    .line 8
    iput-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->stoppingReasonStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 9
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE$Companion;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    return-void
.end method

.method public synthetic constructor <init>(IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;ILkotlin/jvm/internal/g;)V
    .locals 24

    and-int/lit8 v0, p7, 0x1

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move v0, v1

    goto :goto_0

    :cond_0
    move/from16 v0, p1

    :goto_0
    and-int/lit8 v2, p7, 0x2

    if-eqz v2, :cond_1

    move v2, v1

    goto :goto_1

    :cond_1
    move/from16 v2, p2

    :goto_1
    and-int/lit8 v3, p7, 0x4

    if-eqz v3, :cond_2

    .line 10
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    goto :goto_2

    :cond_2
    move-object/from16 v3, p3

    :goto_2
    and-int/lit8 v4, p7, 0x8

    if-eqz v4, :cond_3

    .line 11
    new-instance v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    const v22, 0xffff

    const/16 v23, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    invoke-direct/range {v5 .. v23}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;-><init>(ZZZZZZZZZZZZZZZZILkotlin/jvm/internal/g;)V

    goto :goto_3

    :cond_3
    move-object/from16 v5, p4

    :goto_3
    and-int/lit8 v4, p7, 0x10

    if-eqz v4, :cond_4

    goto :goto_4

    :cond_4
    move/from16 v1, p5

    :goto_4
    and-int/lit8 v4, p7, 0x20

    if-eqz v4, :cond_5

    .line 12
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->NO_REASON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    move-object/from16 p7, v4

    :goto_5
    move-object/from16 p1, p0

    move/from16 p2, v0

    move/from16 p6, v1

    move/from16 p3, v2

    move-object/from16 p4, v3

    move-object/from16 p5, v5

    goto :goto_6

    :cond_5
    move-object/from16 p7, p6

    goto :goto_5

    .line 13
    :goto_6
    invoke-direct/range {p1 .. p7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;-><init>(IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;)V

    return-void
.end method

.method public static final synthetic access$getALIVE_ACKNOWLEDGE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->ALIVE_ACKNOWLEDGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getALIVE_COUNTER$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->ALIVE_COUNTER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getFUNCTION_STATUS$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->FUNCTION_STATUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_1$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_10$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_10:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_11$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_11:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_12$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_12:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_13$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_13:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_14$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_14:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_15$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_15:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_16$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_16:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_2$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_2:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_3$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_3:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_4$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_4:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_5$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_5:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_6$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_6:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_7$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_7:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_8$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_8:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOBSTACLE_AREA_Object_9$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_9:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getSTOPPING_REASON$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->STOPPING_REASON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getTOUCH_DIAGNOSIS_REQUEST$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->TOUCH_DIAGNOSIS_REQUEST:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;
    .locals 0

    .line 1
    and-int/lit8 p8, p7, 0x1

    .line 2
    .line 3
    if-eqz p8, :cond_0

    .line 4
    .line 5
    iget p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveCounter:I

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p8, p7, 0x2

    .line 8
    .line 9
    if-eqz p8, :cond_1

    .line 10
    .line 11
    iget p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveAcknowledge:I

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p8, p7, 0x4

    .line 14
    .line 15
    if-eqz p8, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->functionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p8, p7, 0x8

    .line 20
    .line 21
    if-eqz p8, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p8, p7, 0x10

    .line 26
    .line 27
    if-eqz p8, :cond_4

    .line 28
    .line 29
    iget-boolean p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->isTouchDiagnosisRequest:Z

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p7, p7, 0x20

    .line 32
    .line 33
    if-eqz p7, :cond_5

    .line 34
    .line 35
    iget-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->stoppingReasonStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 36
    .line 37
    :cond_5
    move p7, p5

    .line 38
    move-object p8, p6

    .line 39
    move-object p5, p3

    .line 40
    move-object p6, p4

    .line 41
    move p3, p1

    .line 42
    move p4, p2

    .line 43
    move-object p2, p0

    .line 44
    invoke-virtual/range {p2 .. p8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->copy(IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveCounter:I

    .line 2
    .line 3
    return p0
.end method

.method public final component2()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveAcknowledge:I

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->functionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->isTouchDiagnosisRequest:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component6()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->stoppingReasonStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;
    .locals 7

    .line 1
    const-string p0, "functionStatus"

    .line 2
    .line 3
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "obstacleArea"

    .line 7
    .line 8
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "stoppingReasonStatus"

    .line 12
    .line 13
    invoke-static {p6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 17
    .line 18
    move v1, p1

    .line 19
    move v2, p2

    .line 20
    move-object v3, p3

    .line 21
    move-object v4, p4

    .line 22
    move v5, p5

    .line 23
    move-object v6, p6

    .line 24
    invoke-direct/range {v0 .. v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;-><init>(IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;)V

    .line 25
    .line 26
    .line 27
    return-object v0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 12
    .line 13
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveCounter:I

    .line 14
    .line 15
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveCounter:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveAcknowledge:I

    .line 21
    .line 22
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveAcknowledge:I

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->functionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 28
    .line 29
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->functionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 35
    .line 36
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 37
    .line 38
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-nez v1, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->isTouchDiagnosisRequest:Z

    .line 46
    .line 47
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->isTouchDiagnosisRequest:Z

    .line 48
    .line 49
    if-eq v1, v3, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->stoppingReasonStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 53
    .line 54
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->stoppingReasonStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 55
    .line 56
    if-eq p0, p1, :cond_7

    .line 57
    .line 58
    return v2

    .line 59
    :cond_7
    return v0
.end method

.method public final getAliveAcknowledge()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveAcknowledge:I

    .line 2
    .line 3
    return p0
.end method

.method public final getAliveCounter()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveCounter:I

    .line 2
    .line 3
    return p0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->functionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getObstacleArea()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getStoppingReasonStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->stoppingReasonStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveCounter:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveAcknowledge:I

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->functionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 25
    .line 26
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->hashCode()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    add-int/2addr v0, v2

    .line 31
    mul-int/2addr v0, v1

    .line 32
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->isTouchDiagnosisRequest:Z

    .line 33
    .line 34
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->stoppingReasonStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    add-int/2addr p0, v0

    .line 45
    return p0
.end method

.method public final isTouchDiagnosisRequest()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->isTouchDiagnosisRequest:Z

    .line 2
    .line 3
    return p0
.end method

.method public toBytes()[B
    .locals 3

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->byteLength:I

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveCounter:I

    .line 6
    .line 7
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->ALIVE_COUNTER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 8
    .line 9
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 10
    .line 11
    .line 12
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveAcknowledge:I

    .line 13
    .line 14
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->ALIVE_ACKNOWLEDGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 17
    .line 18
    .line 19
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->functionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->FUNCTION_STATUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 26
    .line 27
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 28
    .line 29
    .line 30
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 31
    .line 32
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea1()Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 37
    .line 38
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 39
    .line 40
    .line 41
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 42
    .line 43
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea2()Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_2:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 48
    .line 49
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 50
    .line 51
    .line 52
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 53
    .line 54
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea3()Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_3:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 59
    .line 60
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 61
    .line 62
    .line 63
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 64
    .line 65
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea4()Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_4:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 70
    .line 71
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 72
    .line 73
    .line 74
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 75
    .line 76
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea5()Z

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_5:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 81
    .line 82
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 83
    .line 84
    .line 85
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 86
    .line 87
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea6()Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_6:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 92
    .line 93
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 94
    .line 95
    .line 96
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 97
    .line 98
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea7()Z

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_7:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 103
    .line 104
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 105
    .line 106
    .line 107
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 108
    .line 109
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea8()Z

    .line 110
    .line 111
    .line 112
    move-result v1

    .line 113
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_8:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 114
    .line 115
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 116
    .line 117
    .line 118
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 119
    .line 120
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea9()Z

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_9:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 125
    .line 126
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 127
    .line 128
    .line 129
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 130
    .line 131
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea10()Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_10:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 136
    .line 137
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 138
    .line 139
    .line 140
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 141
    .line 142
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea11()Z

    .line 143
    .line 144
    .line 145
    move-result v1

    .line 146
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_11:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 147
    .line 148
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 149
    .line 150
    .line 151
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 152
    .line 153
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea12()Z

    .line 154
    .line 155
    .line 156
    move-result v1

    .line 157
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_12:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 158
    .line 159
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 160
    .line 161
    .line 162
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 163
    .line 164
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea13()Z

    .line 165
    .line 166
    .line 167
    move-result v1

    .line 168
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_13:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 169
    .line 170
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 171
    .line 172
    .line 173
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 174
    .line 175
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea14()Z

    .line 176
    .line 177
    .line 178
    move-result v1

    .line 179
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_14:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 180
    .line 181
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 182
    .line 183
    .line 184
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 185
    .line 186
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea15()Z

    .line 187
    .line 188
    .line 189
    move-result v1

    .line 190
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_15:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 191
    .line 192
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 193
    .line 194
    .line 195
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 196
    .line 197
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;->getObjectInArea16()Z

    .line 198
    .line 199
    .line 200
    move-result v1

    .line 201
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->OBSTACLE_AREA_Object_16:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 202
    .line 203
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 204
    .line 205
    .line 206
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->isTouchDiagnosisRequest:Z

    .line 207
    .line 208
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->TOUCH_DIAGNOSIS_REQUEST:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 209
    .line 210
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 211
    .line 212
    .line 213
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->stoppingReasonStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 214
    .line 215
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 216
    .line 217
    .line 218
    move-result p0

    .line 219
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->STOPPING_REASON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 220
    .line 221
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 222
    .line 223
    .line 224
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 225
    .line 226
    .line 227
    move-result-object p0

    .line 228
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 8

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveCounter:I

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->aliveAcknowledge:I

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->functionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 6
    .line 7
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->obstacleArea:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 8
    .line 9
    iget-boolean v4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->isTouchDiagnosisRequest:Z

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->stoppingReasonStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 12
    .line 13
    const-string v5, ", aliveAcknowledge="

    .line 14
    .line 15
    const-string v6, ", functionStatus="

    .line 16
    .line 17
    const-string v7, "C2PHighPrioMessagePPE(aliveCounter="

    .line 18
    .line 19
    invoke-static {v0, v1, v7, v5, v6}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    const-string v1, ", obstacleArea="

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string v1, ", isTouchDiagnosisRequest="

    .line 35
    .line 36
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v1, ", stoppingReasonStatus="

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string p0, ")"

    .line 51
    .line 52
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0
.end method
