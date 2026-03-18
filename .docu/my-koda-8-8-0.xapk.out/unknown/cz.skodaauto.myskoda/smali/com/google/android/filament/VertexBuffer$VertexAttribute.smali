.class public final enum Lcom/google/android/filament/VertexBuffer$VertexAttribute;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/VertexBuffer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "VertexAttribute"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/google/android/filament/VertexBuffer$VertexAttribute;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum BONE_INDICES:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum BONE_WEIGHTS:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum COLOR:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum CUSTOM0:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum CUSTOM1:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum CUSTOM2:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum CUSTOM3:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum CUSTOM4:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum CUSTOM5:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum CUSTOM6:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum CUSTOM7:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum POSITION:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum TANGENTS:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum UNUSED:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum UV0:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field public static final enum UV1:Lcom/google/android/filament/VertexBuffer$VertexAttribute;


# direct methods
.method private static synthetic $values()[Lcom/google/android/filament/VertexBuffer$VertexAttribute;
    .locals 17

    .line 1
    sget-object v1, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->POSITION:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 2
    .line 3
    sget-object v2, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->TANGENTS:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 4
    .line 5
    sget-object v3, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->COLOR:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 6
    .line 7
    sget-object v4, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->UV0:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 8
    .line 9
    sget-object v5, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->UV1:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 10
    .line 11
    sget-object v6, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->BONE_INDICES:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 12
    .line 13
    sget-object v7, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->BONE_WEIGHTS:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 14
    .line 15
    sget-object v8, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->UNUSED:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 16
    .line 17
    sget-object v9, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM0:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 18
    .line 19
    sget-object v10, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM1:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 20
    .line 21
    sget-object v11, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM2:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 22
    .line 23
    sget-object v12, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM3:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 24
    .line 25
    sget-object v13, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM4:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 26
    .line 27
    sget-object v14, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM5:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 28
    .line 29
    sget-object v15, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM6:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 30
    .line 31
    sget-object v16, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM7:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 32
    .line 33
    filled-new-array/range {v1 .. v16}, [Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 2
    .line 3
    const-string v1, "POSITION"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->POSITION:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 10
    .line 11
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 12
    .line 13
    const-string v1, "TANGENTS"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->TANGENTS:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 20
    .line 21
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 22
    .line 23
    const-string v1, "COLOR"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->COLOR:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 30
    .line 31
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 32
    .line 33
    const-string v1, "UV0"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->UV0:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 40
    .line 41
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 42
    .line 43
    const-string v1, "UV1"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->UV1:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 50
    .line 51
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 52
    .line 53
    const-string v1, "BONE_INDICES"

    .line 54
    .line 55
    const/4 v2, 0x5

    .line 56
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->BONE_INDICES:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 60
    .line 61
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 62
    .line 63
    const-string v1, "BONE_WEIGHTS"

    .line 64
    .line 65
    const/4 v2, 0x6

    .line 66
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 67
    .line 68
    .line 69
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->BONE_WEIGHTS:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 70
    .line 71
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 72
    .line 73
    const-string v1, "UNUSED"

    .line 74
    .line 75
    const/4 v2, 0x7

    .line 76
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 77
    .line 78
    .line 79
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->UNUSED:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 80
    .line 81
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 82
    .line 83
    const-string v1, "CUSTOM0"

    .line 84
    .line 85
    const/16 v2, 0x8

    .line 86
    .line 87
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM0:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 91
    .line 92
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 93
    .line 94
    const-string v1, "CUSTOM1"

    .line 95
    .line 96
    const/16 v2, 0x9

    .line 97
    .line 98
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 99
    .line 100
    .line 101
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM1:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 102
    .line 103
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 104
    .line 105
    const-string v1, "CUSTOM2"

    .line 106
    .line 107
    const/16 v2, 0xa

    .line 108
    .line 109
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 110
    .line 111
    .line 112
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM2:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 113
    .line 114
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 115
    .line 116
    const-string v1, "CUSTOM3"

    .line 117
    .line 118
    const/16 v2, 0xb

    .line 119
    .line 120
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 121
    .line 122
    .line 123
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM3:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 124
    .line 125
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 126
    .line 127
    const-string v1, "CUSTOM4"

    .line 128
    .line 129
    const/16 v2, 0xc

    .line 130
    .line 131
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 132
    .line 133
    .line 134
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM4:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 135
    .line 136
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 137
    .line 138
    const-string v1, "CUSTOM5"

    .line 139
    .line 140
    const/16 v2, 0xd

    .line 141
    .line 142
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 143
    .line 144
    .line 145
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM5:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 146
    .line 147
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 148
    .line 149
    const-string v1, "CUSTOM6"

    .line 150
    .line 151
    const/16 v2, 0xe

    .line 152
    .line 153
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 154
    .line 155
    .line 156
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM6:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 157
    .line 158
    new-instance v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 159
    .line 160
    const-string v1, "CUSTOM7"

    .line 161
    .line 162
    const/16 v2, 0xf

    .line 163
    .line 164
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;-><init>(Ljava/lang/String;I)V

    .line 165
    .line 166
    .line 167
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->CUSTOM7:Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 168
    .line 169
    invoke-static {}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->$values()[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    sput-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->$VALUES:[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 174
    .line 175
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/google/android/filament/VertexBuffer$VertexAttribute;
    .locals 1

    .line 1
    const-class v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/google/android/filament/VertexBuffer$VertexAttribute;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->$VALUES:[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/google/android/filament/VertexBuffer$VertexAttribute;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 8
    .line 9
    return-object v0
.end method
