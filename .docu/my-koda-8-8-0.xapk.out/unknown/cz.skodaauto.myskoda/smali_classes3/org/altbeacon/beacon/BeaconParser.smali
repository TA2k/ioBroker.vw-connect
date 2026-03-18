.class public Lorg/altbeacon/beacon/BeaconParser;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;
    }
.end annotation


# static fields
.field public static final ALTBEACON_LAYOUT:Ljava/lang/String; = "m:2-3=beac,i:4-19,i:20-21,i:22-23,p:24-24,d:25-25"

.field private static final D_PATTERN:Ljava/util/regex/Pattern;

.field public static final EDDYSTONE_TLM_LAYOUT:Ljava/lang/String; = "x,s:0-1=feaa,m:2-2=20,d:3-3,d:4-5,d:6-7,d:8-11,d:12-15"

.field public static final EDDYSTONE_UID_LAYOUT:Ljava/lang/String; = "s:0-1=feaa,m:2-2=00,p:3-3:-41,i:4-13,i:14-19"

.field public static final EDDYSTONE_URL_LAYOUT:Ljava/lang/String; = "s:0-1=feaa,m:2-2=10,p:3-3:-41,i:4-21v"

.field private static final HEX_ARRAY:[C

.field private static final I_PATTERN:Ljava/util/regex/Pattern;

.field private static final LITTLE_ENDIAN_SUFFIX:Ljava/lang/String; = "l"

.field private static final M_PATTERN:Ljava/util/regex/Pattern;

.field private static final P_PATTERN:Ljava/util/regex/Pattern;

.field private static final S_PATTERN:Ljava/util/regex/Pattern;

.field private static final TAG:Ljava/lang/String; = "BeaconParser"

.field public static final URI_BEACON_LAYOUT:Ljava/lang/String; = "s:0-1=fed8,m:2-2=00,p:3-3:-41,i:4-21v"

.field private static final VARIABLE_LENGTH_SUFFIX:Ljava/lang/String; = "v"

.field private static final X_PATTERN:Ljava/util/regex/Pattern;


# instance fields
.field protected extraParsers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/BeaconParser;",
            ">;"
        }
    .end annotation
.end field

.field protected mAllowPduOverflow:Ljava/lang/Boolean;

.field protected mBeaconLayout:Ljava/lang/String;

.field protected mDBmCorrection:Ljava/lang/Integer;

.field protected final mDataEndOffsets:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field protected final mDataLittleEndianFlags:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation
.end field

.field protected final mDataStartOffsets:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field protected mExtraFrame:Ljava/lang/Boolean;

.field protected mHardwareAssistManufacturers:[I

.field protected mIdentifier:Ljava/lang/String;

.field protected final mIdentifierEndOffsets:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field protected final mIdentifierLittleEndianFlags:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation
.end field

.field protected final mIdentifierStartOffsets:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field protected final mIdentifierVariableLengthFlags:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation
.end field

.field protected mLayoutSize:Ljava/lang/Integer;

.field private mMatchingBeaconTypeCode:Ljava/lang/Long;

.field protected mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

.field protected mMatchingBeaconTypeCodeStartOffset:Ljava/lang/Integer;

.field protected mPowerEndOffset:Ljava/lang/Integer;

.field protected mPowerStartOffset:Ljava/lang/Integer;

.field protected mServiceUuid:Ljava/lang/Long;

.field protected mServiceUuid128Bit:[B

.field protected mServiceUuidEndOffset:Ljava/lang/Integer;

.field protected mServiceUuidStartOffset:Ljava/lang/Integer;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "i\\:(\\d+)\\-(\\d+)([blv]*)?"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lorg/altbeacon/beacon/BeaconParser;->I_PATTERN:Ljava/util/regex/Pattern;

    .line 8
    .line 9
    const-string v0, "m\\:(\\d+)-(\\d+)\\=([0-9A-Fa-f]+)"

    .line 10
    .line 11
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lorg/altbeacon/beacon/BeaconParser;->M_PATTERN:Ljava/util/regex/Pattern;

    .line 16
    .line 17
    const-string v0, "s\\:(\\d+)-(\\d+)\\=([0-9A-Fa-f\\-]+)"

    .line 18
    .line 19
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lorg/altbeacon/beacon/BeaconParser;->S_PATTERN:Ljava/util/regex/Pattern;

    .line 24
    .line 25
    const-string v0, "d\\:(\\d+)\\-(\\d+)([bl]*)?"

    .line 26
    .line 27
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lorg/altbeacon/beacon/BeaconParser;->D_PATTERN:Ljava/util/regex/Pattern;

    .line 32
    .line 33
    const-string v0, "p\\:(\\d+)?\\-(\\d+)?\\:?([\\-\\d]+)?"

    .line 34
    .line 35
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    sput-object v0, Lorg/altbeacon/beacon/BeaconParser;->P_PATTERN:Ljava/util/regex/Pattern;

    .line 40
    .line 41
    const-string v0, "x"

    .line 42
    .line 43
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Lorg/altbeacon/beacon/BeaconParser;->X_PATTERN:Ljava/util/regex/Pattern;

    .line 48
    .line 49
    const/16 v0, 0x10

    .line 50
    .line 51
    new-array v0, v0, [C

    .line 52
    .line 53
    fill-array-data v0, :array_0

    .line 54
    .line 55
    .line 56
    sput-object v0, Lorg/altbeacon/beacon/BeaconParser;->HEX_ARRAY:[C

    .line 57
    .line 58
    return-void

    .line 59
    :array_0
    .array-data 2
        0x30s
        0x31s
        0x32s
        0x33s
        0x34s
        0x35s
        0x36s
        0x37s
        0x38s
        0x39s
        0x61s
        0x62s
        0x63s
        0x64s
        0x65s
        0x66s
    .end array-data
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    .line 3
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    .line 4
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierLittleEndianFlags:Ljava/util/List;

    .line 5
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataStartOffsets:Ljava/util/List;

    .line 6
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataEndOffsets:Ljava/util/List;

    .line 7
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataLittleEndianFlags:Ljava/util/List;

    .line 8
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierVariableLengthFlags:Ljava/util/List;

    const/4 v0, 0x0

    .line 9
    new-array v0, v0, [B

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid128Bit:[B

    .line 10
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mAllowPduOverflow:Ljava/lang/Boolean;

    const/16 v0, 0x4c

    .line 11
    filled-new-array {v0}, [I

    move-result-object v0

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mHardwareAssistManufacturers:[I

    .line 12
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->extraParsers:Ljava/util/List;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    .line 15
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    .line 16
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierLittleEndianFlags:Ljava/util/List;

    .line 17
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataStartOffsets:Ljava/util/List;

    .line 18
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataEndOffsets:Ljava/util/List;

    .line 19
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataLittleEndianFlags:Ljava/util/List;

    .line 20
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierVariableLengthFlags:Ljava/util/List;

    const/4 v0, 0x0

    .line 21
    new-array v0, v0, [B

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid128Bit:[B

    .line 22
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mAllowPduOverflow:Ljava/lang/Boolean;

    const/16 v0, 0x4c

    .line 23
    filled-new-array {v0}, [I

    move-result-object v0

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mHardwareAssistManufacturers:[I

    .line 24
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->extraParsers:Ljava/util/List;

    .line 25
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifier:Ljava/lang/String;

    return-void
.end method

.method private byteArrayToFormattedString([BIIZ)Ljava/lang/String;
    .locals 6

    .line 1
    sub-int/2addr p3, p2

    .line 2
    add-int/lit8 p0, p3, 0x1

    .line 3
    .line 4
    new-array v0, p0, [B

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-eqz p4, :cond_0

    .line 8
    .line 9
    move p4, v1

    .line 10
    :goto_0
    if-gt p4, p3, :cond_1

    .line 11
    .line 12
    add-int v2, p2, p0

    .line 13
    .line 14
    add-int/lit8 v2, v2, -0x1

    .line 15
    .line 16
    sub-int/2addr v2, p4

    .line 17
    aget-byte v2, p1, v2

    .line 18
    .line 19
    aput-byte v2, v0, p4

    .line 20
    .line 21
    add-int/lit8 p4, p4, 0x1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move p4, v1

    .line 25
    :goto_1
    if-gt p4, p3, :cond_1

    .line 26
    .line 27
    add-int v2, p2, p4

    .line 28
    .line 29
    aget-byte v2, p1, v2

    .line 30
    .line 31
    aput-byte v2, v0, p4

    .line 32
    .line 33
    add-int/lit8 p4, p4, 0x1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/4 p1, 0x5

    .line 37
    if-ge p0, p1, :cond_3

    .line 38
    .line 39
    const-wide/16 p1, 0x0

    .line 40
    .line 41
    :goto_2
    if-ge v1, p0, :cond_2

    .line 42
    .line 43
    sub-int p3, p0, v1

    .line 44
    .line 45
    add-int/lit8 p3, p3, -0x1

    .line 46
    .line 47
    aget-byte p3, v0, p3

    .line 48
    .line 49
    and-int/lit16 p3, p3, 0xff

    .line 50
    .line 51
    int-to-long p3, p3

    .line 52
    int-to-double v2, v1

    .line 53
    const-wide/high16 v4, 0x3ff0000000000000L    # 1.0

    .line 54
    .line 55
    mul-double/2addr v2, v4

    .line 56
    const-wide/high16 v4, 0x4070000000000000L    # 256.0

    .line 57
    .line 58
    invoke-static {v4, v5, v2, v3}, Ljava/lang/Math;->pow(DD)D

    .line 59
    .line 60
    .line 61
    move-result-wide v2

    .line 62
    double-to-long v2, v2

    .line 63
    mul-long/2addr p3, v2

    .line 64
    add-long/2addr p1, p3

    .line 65
    add-int/lit8 v1, v1, 0x1

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_2
    invoke-static {p1, p2}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0

    .line 73
    :cond_3
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconParser;->bytesToHex([B)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    const/16 p2, 0x10

    .line 78
    .line 79
    if-ne p0, p2, :cond_4

    .line 80
    .line 81
    new-instance p0, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 84
    .line 85
    .line 86
    const/16 p3, 0x8

    .line 87
    .line 88
    invoke-virtual {p1, v1, p3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p4

    .line 92
    invoke-virtual {p0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string p4, "-"

    .line 96
    .line 97
    invoke-virtual {p0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    const/16 v0, 0xc

    .line 101
    .line 102
    invoke-virtual {p1, p3, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p3

    .line 106
    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    invoke-virtual {p0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {p1, v0, p2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p3

    .line 116
    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    invoke-virtual {p0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    const/16 p3, 0x14

    .line 123
    .line 124
    invoke-virtual {p1, p2, p3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p2

    .line 128
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    invoke-virtual {p0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    const/16 p2, 0x20

    .line 135
    .line 136
    invoke-virtual {p1, p3, p2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    return-object p0

    .line 148
    :cond_4
    const-string p0, "0x"

    .line 149
    .line 150
    invoke-static {p0, p1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    return-object p0
.end method

.method private byteArrayToString([B)Ljava/lang/String;
    .locals 3

    .line 1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    :goto_0
    array-length v1, p1

    .line 8
    if-ge v0, v1, :cond_0

    .line 9
    .line 10
    aget-byte v1, p1, v0

    .line 11
    .line 12
    invoke-static {v1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    const-string v2, "%02x"

    .line 21
    .line 22
    invoke-static {v2, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v1, " "

    .line 30
    .line 31
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    add-int/lit8 v0, v0, 0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {p0}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method

.method private byteArraysMatch([BI[B)Z
    .locals 4

    .line 1
    array-length p0, p3

    .line 2
    array-length v0, p1

    .line 3
    sub-int/2addr v0, p2

    .line 4
    const/4 v1, 0x0

    .line 5
    if-ge v0, p0, :cond_0

    .line 6
    .line 7
    return v1

    .line 8
    :cond_0
    move v0, v1

    .line 9
    :goto_0
    if-ge v0, p0, :cond_2

    .line 10
    .line 11
    add-int v2, p2, v0

    .line 12
    .line 13
    aget-byte v2, p1, v2

    .line 14
    .line 15
    aget-byte v3, p3, v0

    .line 16
    .line 17
    if-eq v2, v3, :cond_1

    .line 18
    .line 19
    return v1

    .line 20
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_2
    const/4 p0, 0x1

    .line 24
    return p0
.end method

.method public static bytesToHex([B)Ljava/lang/String;
    .locals 6

    .line 1
    array-length v0, p0

    .line 2
    mul-int/lit8 v0, v0, 0x2

    .line 3
    .line 4
    new-array v0, v0, [C

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    :goto_0
    array-length v2, p0

    .line 8
    if-ge v1, v2, :cond_0

    .line 9
    .line 10
    aget-byte v2, p0, v1

    .line 11
    .line 12
    and-int/lit16 v3, v2, 0xff

    .line 13
    .line 14
    mul-int/lit8 v4, v1, 0x2

    .line 15
    .line 16
    sget-object v5, Lorg/altbeacon/beacon/BeaconParser;->HEX_ARRAY:[C

    .line 17
    .line 18
    ushr-int/lit8 v3, v3, 0x4

    .line 19
    .line 20
    aget-char v3, v5, v3

    .line 21
    .line 22
    aput-char v3, v0, v4

    .line 23
    .line 24
    add-int/lit8 v4, v4, 0x1

    .line 25
    .line 26
    and-int/lit8 v2, v2, 0xf

    .line 27
    .line 28
    aget-char v2, v5, v2

    .line 29
    .line 30
    aput-char v2, v0, v4

    .line 31
    .line 32
    add-int/lit8 v1, v1, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    new-instance p0, Ljava/lang/String;

    .line 36
    .line 37
    invoke-direct {p0, v0}, Ljava/lang/String;-><init>([C)V

    .line 38
    .line 39
    .line 40
    return-object p0
.end method

.method private calculateLayoutSize()I
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_1

    .line 5
    .line 6
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    check-cast v2, Ljava/lang/Integer;

    .line 21
    .line 22
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-le v2, v1, :cond_0

    .line 27
    .line 28
    move v1, v2

    .line 29
    goto :goto_0

    .line 30
    :cond_1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataEndOffsets:Ljava/util/List;

    .line 31
    .line 32
    if-eqz v0, :cond_3

    .line 33
    .line 34
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    :cond_2
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    if-eqz v2, :cond_3

    .line 43
    .line 44
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    check-cast v2, Ljava/lang/Integer;

    .line 49
    .line 50
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    if-le v2, v1, :cond_2

    .line 55
    .line 56
    move v1, v2

    .line 57
    goto :goto_1

    .line 58
    :cond_3
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mPowerEndOffset:Ljava/lang/Integer;

    .line 59
    .line 60
    if-eqz v0, :cond_4

    .line 61
    .line 62
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-le v0, v1, :cond_4

    .line 67
    .line 68
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mPowerEndOffset:Ljava/lang/Integer;

    .line 69
    .line 70
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    :cond_4
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidEndOffset:Ljava/lang/Integer;

    .line 75
    .line 76
    if-eqz v0, :cond_5

    .line 77
    .line 78
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-le v0, v1, :cond_5

    .line 83
    .line 84
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidEndOffset:Ljava/lang/Integer;

    .line 85
    .line 86
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    :cond_5
    add-int/lit8 v1, v1, 0x1

    .line 91
    .line 92
    return v1
.end method

.method private ensureMaxSize([BI)[B
    .locals 0
    .annotation build Landroid/annotation/TargetApi;
        value = 0x9
    .end annotation

    .line 1
    array-length p0, p1

    .line 2
    if-lt p0, p2, :cond_0

    .line 3
    .line 4
    return-object p1

    .line 5
    :cond_0
    invoke-static {p1, p2}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static fromString(Ljava/lang/String;)Lorg/altbeacon/beacon/BeaconParser;
    .locals 3

    .line 1
    const-string v0, "~"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    array-length v1, v0

    .line 8
    const/4 v2, 0x2

    .line 9
    if-eq v1, v2, :cond_0

    .line 10
    .line 11
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser;

    .line 12
    .line 13
    invoke-direct {v0}, Lorg/altbeacon/beacon/BeaconParser;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p0}, Lorg/altbeacon/beacon/BeaconParser;->setBeaconLayout(Ljava/lang/String;)Lorg/altbeacon/beacon/BeaconParser;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    aget-object p0, v0, p0

    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    aget-object v0, v0, v1

    .line 26
    .line 27
    new-instance v1, Lorg/altbeacon/beacon/BeaconParser;

    .line 28
    .line 29
    invoke-direct {v1, p0}, Lorg/altbeacon/beacon/BeaconParser;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1, v0}, Lorg/altbeacon/beacon/BeaconParser;->setBeaconLayout(Ljava/lang/String;)Lorg/altbeacon/beacon/BeaconParser;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

.method public static longToByteArray(JI)[B
    .locals 1

    const/4 v0, 0x1

    .line 1
    invoke-static {p0, p1, p2, v0}, Lorg/altbeacon/beacon/BeaconParser;->longToByteArray(JIZ)[B

    move-result-object p0

    return-object p0
.end method

.method public static longToByteArray(JIZ)[B
    .locals 7

    .line 2
    new-array v0, p2, [B

    const/4 v1, 0x0

    :goto_0
    if-ge v1, p2, :cond_1

    if-eqz p3, :cond_0

    move v2, v1

    goto :goto_1

    :cond_0
    sub-int v2, p2, v1

    add-int/lit8 v2, v2, -0x1

    :goto_1
    sub-int v2, p2, v2

    add-int/lit8 v2, v2, -0x1

    mul-int/lit8 v2, v2, 0x8

    const-wide/16 v3, 0xff

    shl-long/2addr v3, v2

    int-to-long v5, v2

    and-long v2, p0, v3

    long-to-int v4, v5

    shr-long/2addr v2, v4

    long-to-int v2, v2

    int-to-byte v2, v2

    .line 3
    aput-byte v2, v0, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    return-object v0
.end method


# virtual methods
.method public addExtraDataParser(Lorg/altbeacon/beacon/BeaconParser;)Z
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p1, Lorg/altbeacon/beacon/BeaconParser;->mExtraFrame:Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->extraParsers:Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    :try_start_0
    check-cast p1, Lorg/altbeacon/beacon/BeaconParser;

    .line 2
    .line 3
    iget-object v0, p1, Lorg/altbeacon/beacon/BeaconParser;->mBeaconLayout:Ljava/lang/String;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconParser;->mBeaconLayout:Ljava/lang/String;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget-object p1, p1, Lorg/altbeacon/beacon/BeaconParser;->mIdentifier:Ljava/lang/String;

    .line 16
    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifier:Ljava/lang/String;

    .line 20
    .line 21
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0
    :try_end_0
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_0

    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    const/4 p0, 0x1

    .line 28
    return p0

    .line 29
    :catch_0
    :cond_0
    const/4 p0, 0x0

    .line 30
    return p0
.end method

.method public fromScanData([BILandroid/bluetooth/BluetoothDevice;)Lorg/altbeacon/beacon/Beacon;
    .locals 7
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v4

    new-instance v6, Lorg/altbeacon/beacon/Beacon;

    invoke-direct {v6}, Lorg/altbeacon/beacon/Beacon;-><init>()V

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v3, p3

    invoke-virtual/range {v0 .. v6}, Lorg/altbeacon/beacon/BeaconParser;->fromScanData([BILandroid/bluetooth/BluetoothDevice;JLorg/altbeacon/beacon/Beacon;)Lorg/altbeacon/beacon/Beacon;

    move-result-object p0

    return-object p0
.end method

.method public fromScanData([BILandroid/bluetooth/BluetoothDevice;J)Lorg/altbeacon/beacon/Beacon;
    .locals 7

    .line 2
    new-instance v6, Lorg/altbeacon/beacon/Beacon;

    invoke-direct {v6}, Lorg/altbeacon/beacon/Beacon;-><init>()V

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v3, p3

    move-wide v4, p4

    invoke-virtual/range {v0 .. v6}, Lorg/altbeacon/beacon/BeaconParser;->fromScanData([BILandroid/bluetooth/BluetoothDevice;JLorg/altbeacon/beacon/Beacon;)Lorg/altbeacon/beacon/Beacon;

    move-result-object p0

    return-object p0
.end method

.method public fromScanData([BILandroid/bluetooth/BluetoothDevice;JLorg/altbeacon/beacon/Beacon;)Lorg/altbeacon/beacon/Beacon;
    .locals 22

    move-object/from16 v0, p0

    move-wide/from16 v1, p4

    move-object/from16 v3, p6

    .line 3
    new-instance v4, Lorg/altbeacon/bluetooth/BleAdvertisement;

    move-object/from16 v5, p1

    invoke-direct {v4, v5}, Lorg/altbeacon/bluetooth/BleAdvertisement;-><init>([B)V

    .line 4
    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 5
    new-instance v7, Ljava/util/ArrayList;

    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 6
    new-instance v8, Ljava/util/ArrayList;

    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 7
    invoke-virtual {v4}, Lorg/altbeacon/bluetooth/BleAdvertisement;->getPdus()Ljava/util/List;

    move-result-object v4

    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_0
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    const/16 v13, 0x20

    const/16 v14, 0x21

    const/16 v15, 0x16

    const/16 v11, 0x10

    const-string v12, "BeaconParser"

    if-eqz v9, :cond_7

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Lorg/altbeacon/bluetooth/Pdu;

    .line 8
    invoke-virtual {v9}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v10

    if-ne v10, v15, :cond_1

    iget-object v10, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid:Ljava/lang/Long;

    if-nez v10, :cond_5

    .line 9
    :cond_1
    invoke-virtual {v9}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v10

    if-ne v10, v14, :cond_2

    iget-object v10, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid128Bit:[B

    array-length v10, v10

    if-eq v10, v11, :cond_5

    .line 10
    :cond_2
    invoke-virtual {v9}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v10

    if-ne v10, v13, :cond_3

    iget-object v10, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid128Bit:[B

    array-length v10, v10

    const/4 v13, 0x4

    if-eq v10, v13, :cond_5

    .line 11
    :cond_3
    invoke-virtual {v9}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v10

    const/4 v13, 0x7

    if-ne v10, v13, :cond_4

    iget-object v10, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid128Bit:[B

    array-length v10, v10

    if-eq v10, v11, :cond_5

    .line 12
    :cond_4
    invoke-virtual {v9}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v10

    const/4 v11, -0x1

    if-ne v10, v11, :cond_6

    .line 13
    :cond_5
    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 14
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    move-result v10

    if-eqz v10, :cond_0

    .line 15
    invoke-virtual {v9}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v10

    invoke-static {v10}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object v10

    invoke-static {v5}, Lorg/altbeacon/beacon/BeaconParser;->bytesToHex([B)Ljava/lang/String;

    move-result-object v11

    invoke-virtual {v9}, Lorg/altbeacon/bluetooth/Pdu;->getStartIndex()I

    move-result v13

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    invoke-virtual {v9}, Lorg/altbeacon/bluetooth/Pdu;->getEndIndex()I

    move-result v9

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    filled-new-array {v10, v11, v13, v9}, [Ljava/lang/Object;

    move-result-object v9

    const-string v10, "Processing pdu type %02X: %s with startIndex: %d, endIndex: %d"

    invoke-static {v12, v10, v9}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    .line 16
    :cond_6
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    move-result v10

    if-eqz v10, :cond_0

    .line 17
    invoke-virtual {v9}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v9

    invoke-static {v9}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object v9

    filled-new-array {v9}, [Ljava/lang/Object;

    move-result-object v9

    const-string v10, "Ignoring pdu type %02X"

    invoke-static {v12, v10, v9}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    goto/16 :goto_0

    .line 18
    :cond_7
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    move-result v4

    const/16 v17, 0x0

    const/4 v9, 0x0

    if-nez v4, :cond_9

    .line 19
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    move-result v4

    if-eqz v4, :cond_8

    .line 20
    const-string v4, "No PDUs to process in this packet."

    new-array v6, v9, [Ljava/lang/Object;

    invoke-static {v12, v4, v6}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_8
    move v4, v9

    move v6, v4

    move-object v13, v12

    const/16 v20, 0x1

    goto/16 :goto_12

    .line 21
    :cond_9
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v4

    move v6, v9

    move/from16 v18, v6

    move/from16 v19, v18

    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v20

    if-eqz v20, :cond_30

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Lorg/altbeacon/bluetooth/Pdu;

    const/16 v20, 0x1

    .line 22
    new-array v10, v9, [B

    .line 23
    iget-object v13, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    if-eqz v13, :cond_a

    iget-object v13, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeStartOffset:Ljava/lang/Integer;

    invoke-virtual {v13}, Ljava/lang/Integer;->intValue()I

    move-result v13

    if-ltz v13, :cond_a

    .line 24
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconParser;->getMatchingBeaconTypeCode()Ljava/lang/Long;

    move-result-object v10

    move-object v13, v12

    invoke-virtual {v10}, Ljava/lang/Long;->longValue()J

    move-result-wide v11

    iget-object v10, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    move-result v10

    iget-object v15, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeStartOffset:Ljava/lang/Integer;

    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    move-result v15

    sub-int/2addr v10, v15

    add-int/lit8 v10, v10, 0x1

    invoke-static {v11, v12, v10}, Lorg/altbeacon/beacon/BeaconParser;->longToByteArray(JI)[B

    move-result-object v10

    goto :goto_2

    :cond_a
    move-object v13, v12

    .line 25
    :goto_2
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconParser;->getServiceUuid128Bit()[B

    move-result-object v11

    .line 26
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconParser;->getServiceUuid()Ljava/lang/Long;

    move-result-object v12

    if-eqz v12, :cond_b

    .line 27
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconParser;->getServiceUuid()Ljava/lang/Long;

    move-result-object v11

    invoke-virtual {v11}, Ljava/lang/Long;->longValue()J

    move-result-wide v11

    iget-object v15, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidEndOffset:Ljava/lang/Integer;

    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    move-result v15

    iget-object v14, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidStartOffset:Ljava/lang/Integer;

    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    move-result v14

    sub-int/2addr v15, v14

    add-int/lit8 v15, v15, 0x1

    invoke-static {v11, v12, v15, v9}, Lorg/altbeacon/beacon/BeaconParser;->longToByteArray(JIZ)[B

    move-result-object v11

    .line 28
    :cond_b
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getStartIndex()I

    move-result v12

    .line 29
    array-length v14, v11

    if-nez v14, :cond_d

    .line 30
    iget-object v14, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    if-eqz v14, :cond_c

    .line 31
    iget-object v14, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeStartOffset:Ljava/lang/Integer;

    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    move-result v14

    add-int/2addr v14, v12

    invoke-direct {v0, v5, v14, v10}, Lorg/altbeacon/beacon/BeaconParser;->byteArraysMatch([BI[B)Z

    move-result v14

    if-eqz v14, :cond_c

    move/from16 v9, v20

    const/4 v14, 0x7

    const/4 v15, 0x4

    goto/16 :goto_8

    :cond_c
    const/4 v14, 0x7

    const/4 v15, 0x4

    goto/16 :goto_7

    .line 32
    :cond_d
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v14

    const/16 v15, 0x21

    if-ne v14, v15, :cond_e

    .line 33
    array-length v14, v11

    const/16 v15, 0x10

    if-ne v14, v15, :cond_f

    move/from16 v14, v20

    goto :goto_3

    :cond_e
    const/16 v15, 0x10

    :cond_f
    move v14, v9

    .line 34
    :goto_3
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v9

    const/4 v15, 0x7

    if-ne v9, v15, :cond_10

    .line 35
    array-length v9, v11

    const/16 v15, 0x10

    if-ne v9, v15, :cond_11

    move/from16 v14, v20

    goto :goto_4

    :cond_10
    const/16 v15, 0x10

    .line 36
    :cond_11
    :goto_4
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v9

    const/16 v15, 0x16

    if-ne v9, v15, :cond_12

    .line 37
    array-length v9, v11

    const/4 v15, 0x2

    if-ne v9, v15, :cond_12

    move/from16 v14, v20

    .line 38
    :cond_12
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v9

    const/16 v15, 0x20

    if-ne v9, v15, :cond_13

    .line 39
    array-length v9, v11

    const/4 v15, 0x4

    if-ne v9, v15, :cond_14

    move/from16 v14, v20

    goto :goto_5

    :cond_13
    const/4 v15, 0x4

    :cond_14
    :goto_5
    if-eqz v14, :cond_15

    .line 40
    iget-object v9, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidStartOffset:Ljava/lang/Integer;

    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    move-result v9

    add-int/2addr v9, v12

    invoke-direct {v0, v5, v9, v11}, Lorg/altbeacon/beacon/BeaconParser;->byteArraysMatch([BI[B)Z

    move-result v9

    if-eqz v9, :cond_15

    .line 41
    iget-object v9, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    if-eqz v9, :cond_16

    .line 42
    iget-object v9, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeStartOffset:Ljava/lang/Integer;

    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    move-result v9

    add-int/2addr v9, v12

    invoke-direct {v0, v5, v9, v10}, Lorg/altbeacon/beacon/BeaconParser;->byteArraysMatch([BI[B)Z

    move-result v9

    if-eqz v9, :cond_15

    move/from16 v9, v20

    const/4 v14, 0x7

    goto :goto_8

    :cond_15
    const/4 v14, 0x7

    goto :goto_7

    .line 43
    :cond_16
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v9

    const/16 v14, 0x16

    if-eq v9, v14, :cond_17

    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v9

    const/16 v14, 0x21

    if-eq v9, v14, :cond_17

    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v9

    const/16 v14, 0x20

    if-eq v9, v14, :cond_17

    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getType()B

    move-result v9

    const/4 v14, 0x7

    if-ne v9, v14, :cond_18

    goto :goto_6

    :cond_17
    const/4 v14, 0x7

    :goto_6
    move/from16 v9, v20

    goto :goto_8

    :cond_18
    :goto_7
    const/4 v9, 0x0

    :goto_8
    if-nez v9, :cond_1d

    .line 44
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconParser;->getServiceUuid()Ljava/lang/Long;

    move-result-object v16

    if-nez v16, :cond_1b

    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconParser;->getServiceUuid128Bit()[B

    move-result-object v14

    array-length v14, v14

    if-eqz v14, :cond_19

    goto :goto_9

    .line 45
    :cond_19
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    move-result v11

    if-eqz v11, :cond_1a

    .line 46
    invoke-direct {v0, v10}, Lorg/altbeacon/beacon/BeaconParser;->byteArrayToString([B)Ljava/lang/String;

    move-result-object v10

    .line 47
    invoke-static {v5}, Lorg/altbeacon/beacon/BeaconParser;->bytesToHex([B)Ljava/lang/String;

    move-result-object v11

    filled-new-array {v10, v11}, [Ljava/lang/Object;

    move-result-object v10

    .line 48
    const-string v11, "This is not a matching Beacon advertisement. (Was expecting %s.  The bytes I see are: %s"

    invoke-static {v13, v11, v10}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_1a
    move-object/from16 v21, v4

    goto :goto_b

    .line 49
    :cond_1b
    :goto_9
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    move-result v14

    if-eqz v14, :cond_1a

    .line 50
    iget-object v14, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeStartOffset:Ljava/lang/Integer;

    if-eqz v14, :cond_1c

    .line 51
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    move-result v14

    goto :goto_a

    :cond_1c
    const/4 v14, 0x0

    .line 52
    :goto_a
    invoke-direct {v0, v11}, Lorg/altbeacon/beacon/BeaconParser;->byteArrayToString([B)Ljava/lang/String;

    move-result-object v11

    iget-object v15, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidStartOffset:Ljava/lang/Integer;

    .line 53
    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    move-result v15

    add-int/2addr v15, v12

    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    .line 54
    invoke-direct {v0, v10}, Lorg/altbeacon/beacon/BeaconParser;->byteArrayToString([B)Ljava/lang/String;

    move-result-object v10

    add-int/2addr v14, v12

    .line 55
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    move-object/from16 v21, v4

    .line 56
    invoke-static {v5}, Lorg/altbeacon/beacon/BeaconParser;->bytesToHex([B)Ljava/lang/String;

    move-result-object v4

    filled-new-array {v11, v15, v10, v14, v4}, [Ljava/lang/Object;

    move-result-object v4

    .line 57
    const-string v10, "This is not a matching Beacon advertisement. Was expecting %s at offset %d and %s at offset %d.  The bytes I see are: %s"

    invoke-static {v13, v10, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_b

    :cond_1d
    move-object/from16 v21, v4

    .line 58
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    move-result v4

    if-eqz v4, :cond_1e

    .line 59
    invoke-direct {v0, v10}, Lorg/altbeacon/beacon/BeaconParser;->byteArrayToString([B)Ljava/lang/String;

    move-result-object v4

    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object v4

    .line 60
    const-string v10, "This is a recognized beacon advertisement -- %s seen"

    invoke-static {v13, v10, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 61
    invoke-static {v5}, Lorg/altbeacon/beacon/BeaconParser;->bytesToHex([B)Ljava/lang/String;

    move-result-object v4

    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object v4

    const-string v10, "Bytes are: %s"

    invoke-static {v13, v10, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_1e
    :goto_b
    if-eqz v9, :cond_2f

    .line 62
    array-length v4, v5

    iget-object v9, v0, Lorg/altbeacon/beacon/BeaconParser;->mLayoutSize:Ljava/lang/Integer;

    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    move-result v9

    add-int/2addr v9, v12

    if-gt v4, v9, :cond_20

    iget-object v4, v0, Lorg/altbeacon/beacon/BeaconParser;->mAllowPduOverflow:Ljava/lang/Boolean;

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    if-eqz v4, :cond_20

    .line 63
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    move-result v4

    if-eqz v4, :cond_1f

    .line 64
    new-instance v4, Ljava/lang/StringBuilder;

    const-string v9, "Expanding buffer because it is too short to parse: "

    invoke-direct {v4, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    array-length v9, v5

    invoke-virtual {v4, v9}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v9, ", needed: "

    invoke-virtual {v4, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v9, v0, Lorg/altbeacon/beacon/BeaconParser;->mLayoutSize:Ljava/lang/Integer;

    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    move-result v9

    add-int/2addr v9, v12

    invoke-virtual {v4, v9}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    const/4 v9, 0x0

    new-array v10, v9, [Ljava/lang/Object;

    invoke-static {v13, v4, v10}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 65
    :cond_1f
    iget-object v4, v0, Lorg/altbeacon/beacon/BeaconParser;->mLayoutSize:Ljava/lang/Integer;

    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v4

    add-int/2addr v4, v12

    invoke-direct {v0, v5, v4}, Lorg/altbeacon/beacon/BeaconParser;->ensureMaxSize([BI)[B

    move-result-object v4

    goto :goto_c

    :cond_20
    move-object v4, v5

    :goto_c
    const/4 v5, 0x0

    .line 66
    :goto_d
    iget-object v9, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    invoke-interface {v9}, Ljava/util/List;->size()I

    move-result v9

    const-string v10, " because PDU is too short.  endIndex: "

    const-string v11, " PDU endIndex: "

    if-ge v5, v9, :cond_26

    .line 67
    iget-object v9, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    invoke-interface {v9, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Integer;

    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    move-result v9

    add-int/2addr v9, v12

    .line 68
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getEndIndex()I

    move-result v14

    if-le v9, v14, :cond_23

    iget-object v14, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierVariableLengthFlags:Ljava/util/List;

    invoke-interface {v14, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Ljava/lang/Boolean;

    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v14

    if-eqz v14, :cond_23

    .line 69
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    move-result v10

    if-eqz v10, :cond_21

    .line 70
    new-instance v10, Ljava/lang/StringBuilder;

    const-string v11, "Need to truncate identifier by "

    invoke-direct {v10, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getEndIndex()I

    move-result v11

    sub-int/2addr v9, v11

    invoke-virtual {v10, v9}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v9

    const/4 v10, 0x0

    new-array v11, v10, [Ljava/lang/Object;

    invoke-static {v13, v9, v11}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 71
    :cond_21
    iget-object v9, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    invoke-interface {v9, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Integer;

    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    move-result v9

    add-int/2addr v9, v12

    .line 72
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getEndIndex()I

    move-result v10

    add-int/lit8 v10, v10, 0x1

    if-gt v10, v9, :cond_22

    .line 73
    const-string v0, "PDU is too short for identifer.  Packet is malformed"

    const/4 v9, 0x0

    new-array v1, v9, [Ljava/lang/Object;

    invoke-static {v13, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object v17

    .line 74
    :cond_22
    iget-object v11, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierLittleEndianFlags:Ljava/util/List;

    invoke-interface {v11, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Ljava/lang/Boolean;

    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v11

    invoke-static {v4, v9, v10, v11}, Lorg/altbeacon/beacon/Identifier;->fromBytes([BIIZ)Lorg/altbeacon/beacon/Identifier;

    move-result-object v9

    .line 75
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_e

    .line 76
    :cond_23
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getEndIndex()I

    move-result v14

    if-le v9, v14, :cond_25

    iget-object v14, v0, Lorg/altbeacon/beacon/BeaconParser;->mAllowPduOverflow:Ljava/lang/Boolean;

    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v14

    if-nez v14, :cond_25

    .line 77
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    move-result v14

    if-eqz v14, :cond_24

    .line 78
    const-string v14, "Cannot parse identifier "

    .line 79
    invoke-static {v5, v9, v14, v10, v11}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v9

    .line 80
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getEndIndex()I

    move-result v10

    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v9

    const/4 v10, 0x0

    new-array v11, v10, [Ljava/lang/Object;

    invoke-static {v13, v9, v11}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_24
    move/from16 v19, v20

    goto :goto_e

    .line 81
    :cond_25
    iget-object v10, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    invoke-interface {v10, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/lang/Integer;

    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    move-result v10

    add-int/2addr v10, v12

    add-int/lit8 v9, v9, 0x1

    iget-object v11, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierLittleEndianFlags:Ljava/util/List;

    invoke-interface {v11, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Ljava/lang/Boolean;

    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v11

    invoke-static {v4, v10, v9, v11}, Lorg/altbeacon/beacon/Identifier;->fromBytes([BIIZ)Lorg/altbeacon/beacon/Identifier;

    move-result-object v9

    .line 82
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_e
    add-int/lit8 v5, v5, 0x1

    goto/16 :goto_d

    :cond_26
    const/4 v5, 0x0

    .line 83
    :goto_f
    iget-object v9, v0, Lorg/altbeacon/beacon/BeaconParser;->mDataEndOffsets:Ljava/util/List;

    invoke-interface {v9}, Ljava/util/List;->size()I

    move-result v9

    if-ge v5, v9, :cond_29

    .line 84
    iget-object v9, v0, Lorg/altbeacon/beacon/BeaconParser;->mDataEndOffsets:Ljava/util/List;

    invoke-interface {v9, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Integer;

    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    move-result v9

    add-int/2addr v9, v12

    .line 85
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getEndIndex()I

    move-result v14

    if-le v9, v14, :cond_28

    iget-object v14, v0, Lorg/altbeacon/beacon/BeaconParser;->mAllowPduOverflow:Ljava/lang/Boolean;

    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v14

    if-nez v14, :cond_28

    .line 86
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    move-result v14

    if-eqz v14, :cond_27

    .line 87
    const-string v14, "Cannot parse data field "

    .line 88
    invoke-static {v5, v9, v14, v10, v11}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v9

    .line 89
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getEndIndex()I

    move-result v14

    invoke-virtual {v9, v14}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v14, ".  Setting value to 0"

    invoke-virtual {v9, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v9

    const/4 v14, 0x0

    new-array v15, v14, [Ljava/lang/Object;

    invoke-static {v13, v9, v15}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 90
    :cond_27
    new-instance v9, Ljava/lang/Long;

    const-wide/16 v14, 0x0

    invoke-direct {v9, v14, v15}, Ljava/lang/Long;-><init>(J)V

    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_10

    .line 91
    :cond_28
    iget-object v14, v0, Lorg/altbeacon/beacon/BeaconParser;->mDataStartOffsets:Ljava/util/List;

    invoke-interface {v14, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Ljava/lang/Integer;

    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    move-result v14

    add-int/2addr v14, v12

    iget-object v15, v0, Lorg/altbeacon/beacon/BeaconParser;->mDataLittleEndianFlags:Ljava/util/List;

    invoke-interface {v15, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Ljava/lang/Boolean;

    invoke-virtual {v15}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v15

    invoke-direct {v0, v4, v14, v9, v15}, Lorg/altbeacon/beacon/BeaconParser;->byteArrayToFormattedString([BIIZ)Ljava/lang/String;

    move-result-object v9

    .line 92
    invoke-static {v9}, Ljava/lang/Long;->decode(Ljava/lang/String;)Ljava/lang/Long;

    move-result-object v9

    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_10
    add-int/lit8 v5, v5, 0x1

    goto :goto_f

    .line 93
    :cond_29
    iget-object v5, v0, Lorg/altbeacon/beacon/BeaconParser;->mPowerStartOffset:Ljava/lang/Integer;

    if-eqz v5, :cond_2d

    .line 94
    iget-object v5, v0, Lorg/altbeacon/beacon/BeaconParser;->mPowerEndOffset:Ljava/lang/Integer;

    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    move-result v5

    add-int/2addr v5, v12

    .line 95
    :try_start_0
    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getEndIndex()I

    move-result v9

    if-le v5, v9, :cond_2b

    iget-object v9, v0, Lorg/altbeacon/beacon/BeaconParser;->mAllowPduOverflow:Ljava/lang/Boolean;

    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v9
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_1

    if-nez v9, :cond_2b

    .line 96
    :try_start_1
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    move-result v9

    if-eqz v9, :cond_2a

    .line 97
    new-instance v9, Ljava/lang/StringBuilder;

    invoke-direct {v9}, Ljava/lang/StringBuilder;-><init>()V

    const-string v10, "Cannot parse power field because PDU is too short.  endIndex: "

    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v9, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v9, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Lorg/altbeacon/bluetooth/Pdu;->getEndIndex()I

    move-result v5

    invoke-virtual {v9, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    const/4 v9, 0x0

    new-array v6, v9, [Ljava/lang/Object;

    invoke-static {v13, v5, v6}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/NullPointerException; {:try_start_1 .. :try_end_1} :catch_0

    :catch_0
    :cond_2a
    move/from16 v19, v20

    goto :goto_11

    .line 98
    :cond_2b
    :try_start_2
    iget-object v5, v0, Lorg/altbeacon/beacon/BeaconParser;->mPowerStartOffset:Ljava/lang/Integer;

    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    move-result v5

    add-int/2addr v5, v12

    iget-object v6, v0, Lorg/altbeacon/beacon/BeaconParser;->mPowerEndOffset:Ljava/lang/Integer;

    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    move-result v6

    add-int/2addr v6, v12

    const/4 v9, 0x0

    invoke-direct {v0, v4, v5, v6, v9}, Lorg/altbeacon/beacon/BeaconParser;->byteArrayToFormattedString([BIIZ)Ljava/lang/String;

    move-result-object v5

    .line 99
    invoke-static {v5}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v5

    iget-object v6, v0, Lorg/altbeacon/beacon/BeaconParser;->mDBmCorrection:Ljava/lang/Integer;

    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    move-result v6
    :try_end_2
    .catch Ljava/lang/NumberFormatException; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ljava/lang/NullPointerException; {:try_start_2 .. :try_end_2} :catch_1

    add-int/2addr v5, v6

    const/16 v6, 0x7f

    if-le v5, v6, :cond_2c

    add-int/lit16 v5, v5, -0x100

    :cond_2c
    move/from16 v18, v5

    goto :goto_11

    .line 100
    :cond_2d
    iget-object v5, v0, Lorg/altbeacon/beacon/BeaconParser;->mDBmCorrection:Ljava/lang/Integer;

    if-eqz v5, :cond_2e

    .line 101
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    move-result v18

    :catch_1
    :cond_2e
    :goto_11
    move-object v5, v4

    if-nez v19, :cond_2f

    move v6, v12

    move/from16 v9, v18

    move/from16 v4, v20

    goto :goto_12

    :cond_2f
    move v6, v12

    move-object v12, v13

    move-object/from16 v4, v21

    const/4 v9, 0x0

    const/16 v11, 0x10

    const/16 v13, 0x20

    const/16 v14, 0x21

    const/16 v15, 0x16

    goto/16 :goto_1

    :cond_30
    move-object v13, v12

    const/16 v20, 0x1

    move/from16 v9, v18

    const/4 v4, 0x0

    :goto_12
    if-eqz v4, :cond_36

    .line 102
    iget-object v4, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    if-eqz v4, :cond_31

    .line 103
    iget-object v4, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeStartOffset:Ljava/lang/Integer;

    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v4

    add-int/2addr v4, v6

    iget-object v10, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    move-result v10

    add-int/2addr v10, v6

    const/4 v14, 0x0

    invoke-direct {v0, v5, v4, v10, v14}, Lorg/altbeacon/beacon/BeaconParser;->byteArrayToFormattedString([BIIZ)Ljava/lang/String;

    move-result-object v4

    .line 104
    invoke-static {v4}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v11

    goto :goto_13

    :cond_31
    const/4 v11, -0x1

    :goto_13
    add-int/lit8 v4, v6, 0x1

    move/from16 v10, v20

    .line 105
    invoke-direct {v0, v5, v6, v4, v10}, Lorg/altbeacon/beacon/BeaconParser;->byteArrayToFormattedString([BIIZ)Ljava/lang/String;

    move-result-object v4

    .line 106
    invoke-static {v4}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v4

    if-eqz p3, :cond_32

    .line 107
    invoke-virtual/range {p3 .. p3}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    move-result-object v6

    .line 108
    :try_start_3
    invoke-virtual/range {p3 .. p3}, Landroid/bluetooth/BluetoothDevice;->getName()Ljava/lang/String;

    move-result-object v12
    :try_end_3
    .catch Ljava/lang/SecurityException; {:try_start_3 .. :try_end_3} :catch_2

    const/4 v14, 0x0

    goto :goto_14

    .line 109
    :catch_2
    const-string v12, "Cannot read device name without Manifest.permission.BLUETOOTH_CONNECT"

    const/4 v14, 0x0

    new-array v15, v14, [Ljava/lang/Object;

    invoke-static {v13, v12, v15}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    move-object/from16 v12, v17

    goto :goto_14

    :cond_32
    const/4 v14, 0x0

    move-object/from16 v6, v17

    move-object v12, v6

    .line 110
    :goto_14
    iput-object v7, v3, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 111
    iput-object v8, v3, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    move/from16 v7, p2

    .line 112
    iput v7, v3, Lorg/altbeacon/beacon/Beacon;->mRssi:I

    .line 113
    iput v11, v3, Lorg/altbeacon/beacon/Beacon;->mBeaconTypeCode:I

    .line 114
    iget-object v7, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid:Ljava/lang/Long;

    if-eqz v7, :cond_33

    .line 115
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    move-result-wide v7

    long-to-int v7, v7

    iput v7, v3, Lorg/altbeacon/beacon/Beacon;->mServiceUuid:I

    goto :goto_15

    :cond_33
    const/4 v11, -0x1

    .line 116
    iput v11, v3, Lorg/altbeacon/beacon/Beacon;->mServiceUuid:I

    .line 117
    :goto_15
    iput-object v6, v3, Lorg/altbeacon/beacon/Beacon;->mBluetoothAddress:Ljava/lang/String;

    .line 118
    iput-object v12, v3, Lorg/altbeacon/beacon/Beacon;->mBluetoothName:Ljava/lang/String;

    .line 119
    iput v4, v3, Lorg/altbeacon/beacon/Beacon;->mManufacturer:I

    .line 120
    iget-object v4, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifier:Ljava/lang/String;

    iput-object v4, v3, Lorg/altbeacon/beacon/Beacon;->mParserIdentifier:Ljava/lang/String;

    .line 121
    iget-object v4, v0, Lorg/altbeacon/beacon/BeaconParser;->extraParsers:Ljava/util/List;

    invoke-interface {v4}, Ljava/util/List;->size()I

    move-result v4

    if-gtz v4, :cond_35

    iget-object v0, v0, Lorg/altbeacon/beacon/BeaconParser;->mExtraFrame:Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_34

    goto :goto_16

    :cond_34
    move v10, v14

    :cond_35
    :goto_16
    iput-boolean v10, v3, Lorg/altbeacon/beacon/Beacon;->mMultiFrameBeacon:Z

    .line 122
    iput-wide v1, v3, Lorg/altbeacon/beacon/Beacon;->mFirstCycleDetectionTimestamp:J

    .line 123
    iput-wide v1, v3, Lorg/altbeacon/beacon/Beacon;->mLastCycleDetectionTimestamp:J

    .line 124
    iput-object v5, v3, Lorg/altbeacon/beacon/Beacon;->mLastPacketRawBytes:[B

    .line 125
    iput v9, v3, Lorg/altbeacon/beacon/Beacon;->mTxPower:I

    return-object v3

    :cond_36
    return-object v17
.end method

.method public getBeaconAdvertisementData(Lorg/altbeacon/beacon/Beacon;)[B
    .locals 14
    .annotation build Landroid/annotation/TargetApi;
        value = 0x9
    .end annotation

    .line 1
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Beacon;->getIdentifiers()Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifierCount()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-ne v0, v1, :cond_15

    .line 14
    .line 15
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    .line 16
    .line 17
    const/4 v1, -0x1

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-le v0, v1, :cond_0

    .line 25
    .line 26
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mPowerEndOffset:Ljava/lang/Integer;

    .line 33
    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-le v0, v1, :cond_1

    .line 41
    .line 42
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mPowerEndOffset:Ljava/lang/Integer;

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    :cond_1
    const/4 v0, 0x0

    .line 49
    move v2, v0

    .line 50
    :goto_0
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    .line 51
    .line 52
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    if-ge v2, v3, :cond_3

    .line 57
    .line 58
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    .line 59
    .line 60
    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    if-eqz v3, :cond_2

    .line 65
    .line 66
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    .line 67
    .line 68
    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    check-cast v3, Ljava/lang/Integer;

    .line 73
    .line 74
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    if-le v3, v1, :cond_2

    .line 79
    .line 80
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    .line 81
    .line 82
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    check-cast v1, Ljava/lang/Integer;

    .line 87
    .line 88
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_3
    move v2, v0

    .line 96
    :goto_1
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataEndOffsets:Ljava/util/List;

    .line 97
    .line 98
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 99
    .line 100
    .line 101
    move-result v3

    .line 102
    if-ge v2, v3, :cond_5

    .line 103
    .line 104
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataEndOffsets:Ljava/util/List;

    .line 105
    .line 106
    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    if-eqz v3, :cond_4

    .line 111
    .line 112
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataEndOffsets:Ljava/util/List;

    .line 113
    .line 114
    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    check-cast v3, Ljava/lang/Integer;

    .line 119
    .line 120
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    if-le v3, v1, :cond_4

    .line 125
    .line 126
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataEndOffsets:Ljava/util/List;

    .line 127
    .line 128
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    check-cast v1, Ljava/lang/Integer;

    .line 133
    .line 134
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 135
    .line 136
    .line 137
    move-result v1

    .line 138
    :cond_4
    add-int/lit8 v2, v2, 0x1

    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_5
    move v2, v0

    .line 142
    move v3, v2

    .line 143
    :goto_2
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    .line 144
    .line 145
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 146
    .line 147
    .line 148
    move-result v4

    .line 149
    if-ge v2, v4, :cond_7

    .line 150
    .line 151
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierVariableLengthFlags:Ljava/util/List;

    .line 152
    .line 153
    invoke-interface {v4, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v4

    .line 157
    check-cast v4, Ljava/lang/Boolean;

    .line 158
    .line 159
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 160
    .line 161
    .line 162
    move-result v4

    .line 163
    if-eqz v4, :cond_6

    .line 164
    .line 165
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    .line 166
    .line 167
    invoke-interface {v4, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v4

    .line 171
    check-cast v4, Ljava/lang/Integer;

    .line 172
    .line 173
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 174
    .line 175
    .line 176
    move-result v4

    .line 177
    iget-object v5, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    .line 178
    .line 179
    invoke-interface {v5, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v5

    .line 183
    check-cast v5, Ljava/lang/Integer;

    .line 184
    .line 185
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 186
    .line 187
    .line 188
    move-result v5

    .line 189
    sub-int/2addr v4, v5

    .line 190
    add-int/lit8 v4, v4, 0x1

    .line 191
    .line 192
    invoke-virtual {p1, v2}, Lorg/altbeacon/beacon/Beacon;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 193
    .line 194
    .line 195
    move-result-object v5

    .line 196
    invoke-virtual {v5}, Lorg/altbeacon/beacon/Identifier;->getByteCount()I

    .line 197
    .line 198
    .line 199
    move-result v5

    .line 200
    add-int/2addr v5, v3

    .line 201
    sub-int v3, v5, v4

    .line 202
    .line 203
    :cond_6
    add-int/lit8 v2, v2, 0x1

    .line 204
    .line 205
    goto :goto_2

    .line 206
    :cond_7
    add-int/2addr v1, v3

    .line 207
    iget-object v2, p0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid128Bit:[B

    .line 208
    .line 209
    const/4 v3, 0x2

    .line 210
    if-eqz v2, :cond_8

    .line 211
    .line 212
    array-length v2, v2

    .line 213
    if-lez v2, :cond_8

    .line 214
    .line 215
    iget-object v2, p0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidEndOffset:Ljava/lang/Integer;

    .line 216
    .line 217
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 218
    .line 219
    .line 220
    move-result v2

    .line 221
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidStartOffset:Ljava/lang/Integer;

    .line 222
    .line 223
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 224
    .line 225
    .line 226
    move-result v4

    .line 227
    sub-int/2addr v2, v4

    .line 228
    add-int/lit8 v2, v2, 0x1

    .line 229
    .line 230
    goto :goto_3

    .line 231
    :cond_8
    move v2, v3

    .line 232
    :goto_3
    add-int/lit8 v1, v1, 0x1

    .line 233
    .line 234
    sub-int/2addr v1, v2

    .line 235
    new-array v1, v1, [B

    .line 236
    .line 237
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    .line 238
    .line 239
    const-wide/16 v5, 0xff

    .line 240
    .line 241
    if-eqz v4, :cond_9

    .line 242
    .line 243
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconParser;->getMatchingBeaconTypeCode()Ljava/lang/Long;

    .line 244
    .line 245
    .line 246
    move-result-object v4

    .line 247
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 248
    .line 249
    .line 250
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeStartOffset:Ljava/lang/Integer;

    .line 251
    .line 252
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 253
    .line 254
    .line 255
    move-result v4

    .line 256
    :goto_4
    iget-object v7, p0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    .line 257
    .line 258
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 259
    .line 260
    .line 261
    move-result v7

    .line 262
    if-gt v4, v7, :cond_9

    .line 263
    .line 264
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconParser;->getMatchingBeaconTypeCode()Ljava/lang/Long;

    .line 265
    .line 266
    .line 267
    move-result-object v7

    .line 268
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 269
    .line 270
    .line 271
    move-result-wide v7

    .line 272
    iget-object v9, p0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    .line 273
    .line 274
    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    .line 275
    .line 276
    .line 277
    move-result v9

    .line 278
    sub-int/2addr v9, v4

    .line 279
    mul-int/lit8 v9, v9, 0x8

    .line 280
    .line 281
    shr-long/2addr v7, v9

    .line 282
    and-long/2addr v7, v5

    .line 283
    long-to-int v7, v7

    .line 284
    int-to-byte v7, v7

    .line 285
    sub-int v8, v4, v2

    .line 286
    .line 287
    aput-byte v7, v1, v8

    .line 288
    .line 289
    add-int/lit8 v4, v4, 0x1

    .line 290
    .line 291
    goto :goto_4

    .line 292
    :cond_9
    move v4, v0

    .line 293
    :goto_5
    iget-object v7, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    .line 294
    .line 295
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 296
    .line 297
    .line 298
    move-result v7

    .line 299
    if-ge v4, v7, :cond_10

    .line 300
    .line 301
    invoke-virtual {p1, v4}, Lorg/altbeacon/beacon/Beacon;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 302
    .line 303
    .line 304
    move-result-object v7

    .line 305
    iget-object v8, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierLittleEndianFlags:Ljava/util/List;

    .line 306
    .line 307
    invoke-interface {v8, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v8

    .line 311
    check-cast v8, Ljava/lang/Boolean;

    .line 312
    .line 313
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 314
    .line 315
    .line 316
    move-result v8

    .line 317
    xor-int/lit8 v8, v8, 0x1

    .line 318
    .line 319
    invoke-virtual {v7, v8}, Lorg/altbeacon/beacon/Identifier;->toByteArrayOfSpecifiedEndianness(Z)[B

    .line 320
    .line 321
    .line 322
    move-result-object v7

    .line 323
    array-length v8, v7

    .line 324
    invoke-virtual {p0, v4}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifierByteCount(I)I

    .line 325
    .line 326
    .line 327
    move-result v9

    .line 328
    const-string v10, "BeaconParser"

    .line 329
    .line 330
    if-ge v8, v9, :cond_c

    .line 331
    .line 332
    iget-object v8, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierVariableLengthFlags:Ljava/util/List;

    .line 333
    .line 334
    invoke-interface {v8, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object v8

    .line 338
    check-cast v8, Ljava/lang/Boolean;

    .line 339
    .line 340
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 341
    .line 342
    .line 343
    move-result v8

    .line 344
    if-nez v8, :cond_b

    .line 345
    .line 346
    iget-object v8, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierLittleEndianFlags:Ljava/util/List;

    .line 347
    .line 348
    invoke-interface {v8, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v8

    .line 352
    check-cast v8, Ljava/lang/Boolean;

    .line 353
    .line 354
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 355
    .line 356
    .line 357
    move-result v8

    .line 358
    if-eqz v8, :cond_a

    .line 359
    .line 360
    invoke-virtual {p0, v4}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifierByteCount(I)I

    .line 361
    .line 362
    .line 363
    move-result v8

    .line 364
    invoke-static {v7, v8}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 365
    .line 366
    .line 367
    move-result-object v7

    .line 368
    goto :goto_6

    .line 369
    :cond_a
    invoke-virtual {p0, v4}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifierByteCount(I)I

    .line 370
    .line 371
    .line 372
    move-result v8

    .line 373
    new-array v8, v8, [B

    .line 374
    .line 375
    invoke-virtual {p0, v4}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifierByteCount(I)I

    .line 376
    .line 377
    .line 378
    move-result v9

    .line 379
    array-length v11, v7

    .line 380
    sub-int/2addr v9, v11

    .line 381
    array-length v11, v7

    .line 382
    invoke-static {v7, v0, v8, v9, v11}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 383
    .line 384
    .line 385
    move-object v7, v8

    .line 386
    :cond_b
    :goto_6
    new-instance v8, Ljava/lang/StringBuilder;

    .line 387
    .line 388
    const-string v9, "Expanded identifier because it is too short.  It is now: "

    .line 389
    .line 390
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 391
    .line 392
    .line 393
    invoke-direct {p0, v7}, Lorg/altbeacon/beacon/BeaconParser;->byteArrayToString([B)Ljava/lang/String;

    .line 394
    .line 395
    .line 396
    move-result-object v9

    .line 397
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 398
    .line 399
    .line 400
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 401
    .line 402
    .line 403
    move-result-object v8

    .line 404
    new-array v9, v0, [Ljava/lang/Object;

    .line 405
    .line 406
    invoke-static {v10, v8, v9}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 407
    .line 408
    .line 409
    goto :goto_8

    .line 410
    :cond_c
    array-length v8, v7

    .line 411
    invoke-virtual {p0, v4}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifierByteCount(I)I

    .line 412
    .line 413
    .line 414
    move-result v9

    .line 415
    if-le v8, v9, :cond_e

    .line 416
    .line 417
    iget-object v8, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierLittleEndianFlags:Ljava/util/List;

    .line 418
    .line 419
    invoke-interface {v8, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 420
    .line 421
    .line 422
    move-result-object v8

    .line 423
    check-cast v8, Ljava/lang/Boolean;

    .line 424
    .line 425
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 426
    .line 427
    .line 428
    move-result v8

    .line 429
    if-eqz v8, :cond_d

    .line 430
    .line 431
    invoke-virtual {p0, v4}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifierByteCount(I)I

    .line 432
    .line 433
    .line 434
    move-result v8

    .line 435
    array-length v9, v7

    .line 436
    sub-int/2addr v8, v9

    .line 437
    invoke-virtual {p0, v4}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifierByteCount(I)I

    .line 438
    .line 439
    .line 440
    move-result v9

    .line 441
    invoke-static {v7, v8, v9}, Ljava/util/Arrays;->copyOfRange([BII)[B

    .line 442
    .line 443
    .line 444
    move-result-object v7

    .line 445
    goto :goto_7

    .line 446
    :cond_d
    invoke-virtual {p0, v4}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifierByteCount(I)I

    .line 447
    .line 448
    .line 449
    move-result v8

    .line 450
    invoke-static {v7, v8}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 451
    .line 452
    .line 453
    move-result-object v7

    .line 454
    :goto_7
    new-instance v8, Ljava/lang/StringBuilder;

    .line 455
    .line 456
    const-string v9, "Truncated identifier because it is too long.  It is now: "

    .line 457
    .line 458
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 459
    .line 460
    .line 461
    invoke-direct {p0, v7}, Lorg/altbeacon/beacon/BeaconParser;->byteArrayToString([B)Ljava/lang/String;

    .line 462
    .line 463
    .line 464
    move-result-object v9

    .line 465
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 466
    .line 467
    .line 468
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 469
    .line 470
    .line 471
    move-result-object v8

    .line 472
    new-array v9, v0, [Ljava/lang/Object;

    .line 473
    .line 474
    invoke-static {v10, v8, v9}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 475
    .line 476
    .line 477
    goto :goto_8

    .line 478
    :cond_e
    new-instance v8, Ljava/lang/StringBuilder;

    .line 479
    .line 480
    const-string v9, "Identifier size is just right: "

    .line 481
    .line 482
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 483
    .line 484
    .line 485
    invoke-direct {p0, v7}, Lorg/altbeacon/beacon/BeaconParser;->byteArrayToString([B)Ljava/lang/String;

    .line 486
    .line 487
    .line 488
    move-result-object v9

    .line 489
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 490
    .line 491
    .line 492
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 493
    .line 494
    .line 495
    move-result-object v8

    .line 496
    new-array v9, v0, [Ljava/lang/Object;

    .line 497
    .line 498
    invoke-static {v10, v8, v9}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 499
    .line 500
    .line 501
    :goto_8
    iget-object v8, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    .line 502
    .line 503
    invoke-interface {v8, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 504
    .line 505
    .line 506
    move-result-object v8

    .line 507
    check-cast v8, Ljava/lang/Integer;

    .line 508
    .line 509
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 510
    .line 511
    .line 512
    move-result v8

    .line 513
    :goto_9
    iget-object v9, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    .line 514
    .line 515
    invoke-interface {v9, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 516
    .line 517
    .line 518
    move-result-object v9

    .line 519
    check-cast v9, Ljava/lang/Integer;

    .line 520
    .line 521
    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    .line 522
    .line 523
    .line 524
    move-result v9

    .line 525
    array-length v10, v7

    .line 526
    add-int/2addr v9, v10

    .line 527
    add-int/lit8 v9, v9, -0x1

    .line 528
    .line 529
    if-gt v8, v9, :cond_f

    .line 530
    .line 531
    sub-int v9, v8, v2

    .line 532
    .line 533
    iget-object v10, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    .line 534
    .line 535
    invoke-interface {v10, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 536
    .line 537
    .line 538
    move-result-object v10

    .line 539
    check-cast v10, Ljava/lang/Integer;

    .line 540
    .line 541
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 542
    .line 543
    .line 544
    move-result v10

    .line 545
    sub-int v10, v8, v10

    .line 546
    .line 547
    aget-byte v10, v7, v10

    .line 548
    .line 549
    aput-byte v10, v1, v9

    .line 550
    .line 551
    add-int/lit8 v8, v8, 0x1

    .line 552
    .line 553
    goto :goto_9

    .line 554
    :cond_f
    add-int/lit8 v4, v4, 0x1

    .line 555
    .line 556
    goto/16 :goto_5

    .line 557
    .line 558
    :cond_10
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconParser;->mPowerStartOffset:Ljava/lang/Integer;

    .line 559
    .line 560
    if-eqz v4, :cond_11

    .line 561
    .line 562
    iget-object v7, p0, Lorg/altbeacon/beacon/BeaconParser;->mPowerEndOffset:Ljava/lang/Integer;

    .line 563
    .line 564
    if-eqz v7, :cond_11

    .line 565
    .line 566
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 567
    .line 568
    .line 569
    move-result v4

    .line 570
    if-lt v4, v3, :cond_11

    .line 571
    .line 572
    iget-object v3, p0, Lorg/altbeacon/beacon/BeaconParser;->mPowerStartOffset:Ljava/lang/Integer;

    .line 573
    .line 574
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 575
    .line 576
    .line 577
    move-result v3

    .line 578
    :goto_a
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconParser;->mPowerEndOffset:Ljava/lang/Integer;

    .line 579
    .line 580
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 581
    .line 582
    .line 583
    move-result v4

    .line 584
    if-gt v3, v4, :cond_11

    .line 585
    .line 586
    sub-int v4, v3, v2

    .line 587
    .line 588
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Beacon;->getTxPower()I

    .line 589
    .line 590
    .line 591
    move-result v7

    .line 592
    iget-object v8, p0, Lorg/altbeacon/beacon/BeaconParser;->mPowerStartOffset:Ljava/lang/Integer;

    .line 593
    .line 594
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 595
    .line 596
    .line 597
    move-result v8

    .line 598
    sub-int v8, v3, v8

    .line 599
    .line 600
    mul-int/lit8 v8, v8, 0x8

    .line 601
    .line 602
    shr-int/2addr v7, v8

    .line 603
    and-int/lit16 v7, v7, 0xff

    .line 604
    .line 605
    int-to-byte v7, v7

    .line 606
    aput-byte v7, v1, v4

    .line 607
    .line 608
    add-int/lit8 v3, v3, 0x1

    .line 609
    .line 610
    goto :goto_a

    .line 611
    :cond_11
    move v3, v0

    .line 612
    :goto_b
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataStartOffsets:Ljava/util/List;

    .line 613
    .line 614
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 615
    .line 616
    .line 617
    move-result v4

    .line 618
    if-ge v3, v4, :cond_14

    .line 619
    .line 620
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Beacon;->getDataFields()Ljava/util/List;

    .line 621
    .line 622
    .line 623
    move-result-object v4

    .line 624
    invoke-interface {v4, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 625
    .line 626
    .line 627
    move-result-object v4

    .line 628
    check-cast v4, Ljava/lang/Long;

    .line 629
    .line 630
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 631
    .line 632
    .line 633
    move-result-wide v7

    .line 634
    iget-object v4, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataEndOffsets:Ljava/util/List;

    .line 635
    .line 636
    invoke-interface {v4, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 637
    .line 638
    .line 639
    move-result-object v4

    .line 640
    check-cast v4, Ljava/lang/Integer;

    .line 641
    .line 642
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 643
    .line 644
    .line 645
    move-result v4

    .line 646
    iget-object v9, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataStartOffsets:Ljava/util/List;

    .line 647
    .line 648
    invoke-interface {v9, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 649
    .line 650
    .line 651
    move-result-object v9

    .line 652
    check-cast v9, Ljava/lang/Integer;

    .line 653
    .line 654
    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    .line 655
    .line 656
    .line 657
    move-result v9

    .line 658
    sub-int/2addr v4, v9

    .line 659
    move v9, v0

    .line 660
    :goto_c
    if-gt v9, v4, :cond_13

    .line 661
    .line 662
    iget-object v10, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataLittleEndianFlags:Ljava/util/List;

    .line 663
    .line 664
    invoke-interface {v10, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 665
    .line 666
    .line 667
    move-result-object v10

    .line 668
    check-cast v10, Ljava/lang/Boolean;

    .line 669
    .line 670
    invoke-virtual {v10}, Ljava/lang/Boolean;->booleanValue()Z

    .line 671
    .line 672
    .line 673
    move-result v10

    .line 674
    if-nez v10, :cond_12

    .line 675
    .line 676
    sub-int v10, v4, v9

    .line 677
    .line 678
    goto :goto_d

    .line 679
    :cond_12
    move v10, v9

    .line 680
    :goto_d
    iget-object v11, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataStartOffsets:Ljava/util/List;

    .line 681
    .line 682
    invoke-interface {v11, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 683
    .line 684
    .line 685
    move-result-object v11

    .line 686
    check-cast v11, Ljava/lang/Integer;

    .line 687
    .line 688
    invoke-virtual {v11}, Ljava/lang/Integer;->intValue()I

    .line 689
    .line 690
    .line 691
    move-result v11

    .line 692
    sub-int/2addr v11, v2

    .line 693
    add-int/2addr v11, v10

    .line 694
    mul-int/lit8 v10, v9, 0x8

    .line 695
    .line 696
    shr-long v12, v7, v10

    .line 697
    .line 698
    and-long/2addr v12, v5

    .line 699
    long-to-int v10, v12

    .line 700
    int-to-byte v10, v10

    .line 701
    aput-byte v10, v1, v11

    .line 702
    .line 703
    add-int/lit8 v9, v9, 0x1

    .line 704
    .line 705
    goto :goto_c

    .line 706
    :cond_13
    add-int/lit8 v3, v3, 0x1

    .line 707
    .line 708
    goto :goto_b

    .line 709
    :cond_14
    return-object v1

    .line 710
    :cond_15
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 711
    .line 712
    new-instance v1, Ljava/lang/StringBuilder;

    .line 713
    .line 714
    const-string v2, "Beacon has "

    .line 715
    .line 716
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 717
    .line 718
    .line 719
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Beacon;->getIdentifiers()Ljava/util/List;

    .line 720
    .line 721
    .line 722
    move-result-object p1

    .line 723
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 724
    .line 725
    .line 726
    move-result p1

    .line 727
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 728
    .line 729
    .line 730
    const-string p1, " identifiers but format requires "

    .line 731
    .line 732
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 733
    .line 734
    .line 735
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconParser;->getIdentifierCount()I

    .line 736
    .line 737
    .line 738
    move-result p0

    .line 739
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 740
    .line 741
    .line 742
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 743
    .line 744
    .line 745
    move-result-object p0

    .line 746
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 747
    .line 748
    .line 749
    throw v0
.end method

.method public getDataFieldCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mDataStartOffsets:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getExtraDataParsers()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/BeaconParser;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->extraParsers:Ljava/util/List;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public getHardwareAssistManufacturers()[I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mHardwareAssistManufacturers:[I

    .line 2
    .line 3
    return-object p0
.end method

.method public getIdentifier()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifier:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getIdentifierByteCount(I)I
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    sub-int/2addr v0, p0

    .line 26
    add-int/lit8 v0, v0, 0x1

    .line 27
    .line 28
    return v0
.end method

.method public getIdentifierCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getLayout()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mBeaconLayout:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMServiceUuidStartOffset()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidStartOffset:Ljava/lang/Integer;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getMatchingBeaconTypeCode()Ljava/lang/Long;
    .locals 2

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCode:Ljava/lang/Long;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const-wide/16 v0, -0x1

    .line 6
    .line 7
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    :cond_0
    return-object p0
.end method

.method public getMatchingBeaconTypeCodeEndOffset()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, -0x1

    .line 6
    return p0

    .line 7
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public getMatchingBeaconTypeCodeStartOffset()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeStartOffset:Ljava/lang/Integer;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, -0x1

    .line 6
    return p0

    .line 7
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public getPowerCorrection()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mDBmCorrection:Ljava/lang/Integer;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getServiceUuid()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public getServiceUuid128Bit()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid128Bit:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public getServiceUuidEndOffset()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidEndOffset:Ljava/lang/Integer;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public hashCode()I
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCode:Ljava/lang/Long;

    .line 4
    .line 5
    iget-object v2, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    .line 6
    .line 7
    iget-object v3, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    .line 8
    .line 9
    iget-object v4, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierLittleEndianFlags:Ljava/util/List;

    .line 10
    .line 11
    iget-object v5, v0, Lorg/altbeacon/beacon/BeaconParser;->mDataStartOffsets:Ljava/util/List;

    .line 12
    .line 13
    iget-object v6, v0, Lorg/altbeacon/beacon/BeaconParser;->mDataEndOffsets:Ljava/util/List;

    .line 14
    .line 15
    iget-object v7, v0, Lorg/altbeacon/beacon/BeaconParser;->mDataLittleEndianFlags:Ljava/util/List;

    .line 16
    .line 17
    iget-object v8, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierVariableLengthFlags:Ljava/util/List;

    .line 18
    .line 19
    iget-object v9, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeStartOffset:Ljava/lang/Integer;

    .line 20
    .line 21
    iget-object v10, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;

    .line 22
    .line 23
    iget-object v11, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidStartOffset:Ljava/lang/Integer;

    .line 24
    .line 25
    iget-object v12, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidEndOffset:Ljava/lang/Integer;

    .line 26
    .line 27
    iget-object v13, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid:Ljava/lang/Long;

    .line 28
    .line 29
    iget-object v14, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid128Bit:[B

    .line 30
    .line 31
    iget-object v15, v0, Lorg/altbeacon/beacon/BeaconParser;->mExtraFrame:Ljava/lang/Boolean;

    .line 32
    .line 33
    move-object/from16 v16, v1

    .line 34
    .line 35
    iget-object v1, v0, Lorg/altbeacon/beacon/BeaconParser;->mPowerStartOffset:Ljava/lang/Integer;

    .line 36
    .line 37
    move-object/from16 v17, v1

    .line 38
    .line 39
    iget-object v1, v0, Lorg/altbeacon/beacon/BeaconParser;->mPowerEndOffset:Ljava/lang/Integer;

    .line 40
    .line 41
    move-object/from16 v18, v1

    .line 42
    .line 43
    iget-object v1, v0, Lorg/altbeacon/beacon/BeaconParser;->mDBmCorrection:Ljava/lang/Integer;

    .line 44
    .line 45
    move-object/from16 v19, v1

    .line 46
    .line 47
    iget-object v1, v0, Lorg/altbeacon/beacon/BeaconParser;->mLayoutSize:Ljava/lang/Integer;

    .line 48
    .line 49
    move-object/from16 v20, v1

    .line 50
    .line 51
    iget-object v1, v0, Lorg/altbeacon/beacon/BeaconParser;->mAllowPduOverflow:Ljava/lang/Boolean;

    .line 52
    .line 53
    move-object/from16 v21, v1

    .line 54
    .line 55
    iget-object v1, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifier:Ljava/lang/String;

    .line 56
    .line 57
    move-object/from16 v22, v1

    .line 58
    .line 59
    iget-object v1, v0, Lorg/altbeacon/beacon/BeaconParser;->mHardwareAssistManufacturers:[I

    .line 60
    .line 61
    iget-object v0, v0, Lorg/altbeacon/beacon/BeaconParser;->extraParsers:Ljava/util/List;

    .line 62
    .line 63
    move-object/from16 v23, v22

    .line 64
    .line 65
    move-object/from16 v22, v1

    .line 66
    .line 67
    move-object/from16 v1, v16

    .line 68
    .line 69
    move-object/from16 v16, v17

    .line 70
    .line 71
    move-object/from16 v17, v18

    .line 72
    .line 73
    move-object/from16 v18, v19

    .line 74
    .line 75
    move-object/from16 v19, v20

    .line 76
    .line 77
    move-object/from16 v20, v21

    .line 78
    .line 79
    move-object/from16 v21, v23

    .line 80
    .line 81
    move-object/from16 v23, v0

    .line 82
    .line 83
    filled-new-array/range {v1 .. v23}, [Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    invoke-static {v0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    return v0
.end method

.method public setAllowPduOverflow(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconParser;->mAllowPduOverflow:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-void
.end method

.method public setBeaconLayout(Ljava/lang/String;)Lorg/altbeacon/beacon/BeaconParser;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "API setBeaconLayout "

    .line 6
    .line 7
    invoke-static {v2, v1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    const/4 v3, 0x0

    .line 12
    new-array v4, v3, [Ljava/lang/Object;

    .line 13
    .line 14
    const-string v5, "BeaconParser"

    .line 15
    .line 16
    invoke-static {v5, v2, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    iput-object v1, v0, Lorg/altbeacon/beacon/BeaconParser;->mBeaconLayout:Ljava/lang/String;

    .line 20
    .line 21
    new-instance v2, Ljava/lang/StringBuilder;

    .line 22
    .line 23
    const-string v4, "Parsing beacon layout: "

    .line 24
    .line 25
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    invoke-static {v5, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 36
    .line 37
    .line 38
    const-string v2, ","

    .line 39
    .line 40
    invoke-virtual {v1, v2}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 45
    .line 46
    iput-object v2, v0, Lorg/altbeacon/beacon/BeaconParser;->mExtraFrame:Ljava/lang/Boolean;

    .line 47
    .line 48
    array-length v2, v1

    .line 49
    move v4, v3

    .line 50
    :goto_0
    if-ge v4, v2, :cond_e

    .line 51
    .line 52
    aget-object v6, v1, v4

    .line 53
    .line 54
    sget-object v7, Lorg/altbeacon/beacon/BeaconParser;->I_PATTERN:Ljava/util/regex/Pattern;

    .line 55
    .line 56
    invoke-virtual {v7, v6}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 57
    .line 58
    .line 59
    move-result-object v7

    .line 60
    move v8, v3

    .line 61
    :goto_1
    invoke-virtual {v7}, Ljava/util/regex/Matcher;->find()Z

    .line 62
    .line 63
    .line 64
    move-result v9

    .line 65
    const-string v10, "l"

    .line 66
    .line 67
    const-string v11, "Cannot parse integer byte offset in term: "

    .line 68
    .line 69
    const/4 v12, 0x3

    .line 70
    const/4 v13, 0x2

    .line 71
    const/4 v14, 0x1

    .line 72
    if-eqz v9, :cond_0

    .line 73
    .line 74
    :try_start_0
    invoke-virtual {v7, v14}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v8

    .line 78
    invoke-static {v8}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 79
    .line 80
    .line 81
    move-result v8

    .line 82
    invoke-virtual {v7, v13}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v9

    .line 86
    invoke-static {v9}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 87
    .line 88
    .line 89
    move-result v9

    .line 90
    invoke-virtual {v7, v12}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v13

    .line 94
    invoke-virtual {v13, v10}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 95
    .line 96
    .line 97
    move-result v10

    .line 98
    invoke-static {v10}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 99
    .line 100
    .line 101
    move-result-object v10

    .line 102
    iget-object v13, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierLittleEndianFlags:Ljava/util/List;

    .line 103
    .line 104
    invoke-interface {v13, v10}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    invoke-virtual {v7, v12}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v10

    .line 111
    const-string v12, "v"

    .line 112
    .line 113
    invoke-virtual {v10, v12}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 114
    .line 115
    .line 116
    move-result v10

    .line 117
    invoke-static {v10}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 118
    .line 119
    .line 120
    move-result-object v10

    .line 121
    iget-object v12, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierVariableLengthFlags:Ljava/util/List;

    .line 122
    .line 123
    invoke-interface {v12, v10}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    iget-object v10, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierStartOffsets:Ljava/util/List;

    .line 127
    .line 128
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 129
    .line 130
    .line 131
    move-result-object v8

    .line 132
    invoke-interface {v10, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    iget-object v8, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifierEndOffsets:Ljava/util/List;

    .line 136
    .line 137
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 138
    .line 139
    .line 140
    move-result-object v9

    .line 141
    invoke-interface {v8, v9}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 142
    .line 143
    .line 144
    move v8, v14

    .line 145
    goto :goto_1

    .line 146
    :catch_0
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;

    .line 147
    .line 148
    invoke-static {v11, v6}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    throw v0

    .line 156
    :cond_0
    sget-object v7, Lorg/altbeacon/beacon/BeaconParser;->D_PATTERN:Ljava/util/regex/Pattern;

    .line 157
    .line 158
    invoke-virtual {v7, v6}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 159
    .line 160
    .line 161
    move-result-object v7

    .line 162
    :goto_2
    invoke-virtual {v7}, Ljava/util/regex/Matcher;->find()Z

    .line 163
    .line 164
    .line 165
    move-result v9

    .line 166
    if-eqz v9, :cond_1

    .line 167
    .line 168
    :try_start_1
    invoke-virtual {v7, v14}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v8

    .line 172
    invoke-static {v8}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 173
    .line 174
    .line 175
    move-result v8

    .line 176
    invoke-virtual {v7, v13}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v9

    .line 180
    invoke-static {v9}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 181
    .line 182
    .line 183
    move-result v9

    .line 184
    invoke-virtual {v7, v12}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v15

    .line 188
    invoke-virtual {v15, v10}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 189
    .line 190
    .line 191
    move-result v15

    .line 192
    invoke-static {v15}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 193
    .line 194
    .line 195
    move-result-object v15

    .line 196
    iget-object v3, v0, Lorg/altbeacon/beacon/BeaconParser;->mDataLittleEndianFlags:Ljava/util/List;

    .line 197
    .line 198
    invoke-interface {v3, v15}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    iget-object v3, v0, Lorg/altbeacon/beacon/BeaconParser;->mDataStartOffsets:Ljava/util/List;

    .line 202
    .line 203
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 204
    .line 205
    .line 206
    move-result-object v8

    .line 207
    invoke-interface {v3, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    iget-object v3, v0, Lorg/altbeacon/beacon/BeaconParser;->mDataEndOffsets:Ljava/util/List;

    .line 211
    .line 212
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 213
    .line 214
    .line 215
    move-result-object v8

    .line 216
    invoke-interface {v3, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_1

    .line 217
    .line 218
    .line 219
    move v8, v14

    .line 220
    const/4 v3, 0x0

    .line 221
    goto :goto_2

    .line 222
    :catch_1
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;

    .line 223
    .line 224
    invoke-static {v11, v6}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object v1

    .line 228
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;-><init>(Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    throw v0

    .line 232
    :cond_1
    sget-object v3, Lorg/altbeacon/beacon/BeaconParser;->P_PATTERN:Ljava/util/regex/Pattern;

    .line 233
    .line 234
    invoke-virtual {v3, v6}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 235
    .line 236
    .line 237
    move-result-object v3

    .line 238
    :goto_3
    invoke-virtual {v3}, Ljava/util/regex/Matcher;->find()Z

    .line 239
    .line 240
    .line 241
    move-result v7

    .line 242
    if-eqz v7, :cond_4

    .line 243
    .line 244
    const-string v7, "none"

    .line 245
    .line 246
    :try_start_2
    invoke-virtual {v3, v14}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 247
    .line 248
    .line 249
    move-result-object v8

    .line 250
    if-eqz v8, :cond_2

    .line 251
    .line 252
    invoke-virtual {v3, v13}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object v8

    .line 256
    if-eqz v8, :cond_2

    .line 257
    .line 258
    invoke-virtual {v3, v14}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 259
    .line 260
    .line 261
    move-result-object v8

    .line 262
    invoke-static {v8}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 263
    .line 264
    .line 265
    move-result v8

    .line 266
    invoke-virtual {v3, v13}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v9

    .line 270
    invoke-static {v9}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 271
    .line 272
    .line 273
    move-result v9

    .line 274
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 275
    .line 276
    .line 277
    move-result-object v8

    .line 278
    iput-object v8, v0, Lorg/altbeacon/beacon/BeaconParser;->mPowerStartOffset:Ljava/lang/Integer;

    .line 279
    .line 280
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 281
    .line 282
    .line 283
    move-result-object v8

    .line 284
    iput-object v8, v0, Lorg/altbeacon/beacon/BeaconParser;->mPowerEndOffset:Ljava/lang/Integer;

    .line 285
    .line 286
    :cond_2
    invoke-virtual {v3, v12}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 287
    .line 288
    .line 289
    move-result-object v8

    .line 290
    if-eqz v8, :cond_3

    .line 291
    .line 292
    invoke-virtual {v3, v12}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 293
    .line 294
    .line 295
    move-result-object v7

    .line 296
    invoke-static {v7}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 297
    .line 298
    .line 299
    move-result v8

    .line 300
    goto :goto_4

    .line 301
    :cond_3
    const/4 v8, 0x0

    .line 302
    :goto_4
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 303
    .line 304
    .line 305
    move-result-object v8

    .line 306
    iput-object v8, v0, Lorg/altbeacon/beacon/BeaconParser;->mDBmCorrection:Ljava/lang/Integer;
    :try_end_2
    .catch Ljava/lang/NumberFormatException; {:try_start_2 .. :try_end_2} :catch_2

    .line 307
    .line 308
    move v8, v14

    .line 309
    goto :goto_3

    .line 310
    :catch_2
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;

    .line 311
    .line 312
    const-string v1, "Cannot parse integer power byte offset ("

    .line 313
    .line 314
    const-string v2, ") in term: "

    .line 315
    .line 316
    invoke-static {v1, v7, v2, v6}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 317
    .line 318
    .line 319
    move-result-object v1

    .line 320
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;-><init>(Ljava/lang/String;)V

    .line 321
    .line 322
    .line 323
    throw v0

    .line 324
    :cond_4
    sget-object v3, Lorg/altbeacon/beacon/BeaconParser;->M_PATTERN:Ljava/util/regex/Pattern;

    .line 325
    .line 326
    invoke-virtual {v3, v6}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 327
    .line 328
    .line 329
    move-result-object v3

    .line 330
    :goto_5
    invoke-virtual {v3}, Ljava/util/regex/Matcher;->find()Z

    .line 331
    .line 332
    .line 333
    move-result v7

    .line 334
    const-string v9, "0x"

    .line 335
    .line 336
    const-string v10, " in term: "

    .line 337
    .line 338
    if-eqz v7, :cond_5

    .line 339
    .line 340
    :try_start_3
    invoke-virtual {v3, v14}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v7

    .line 344
    invoke-static {v7}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 345
    .line 346
    .line 347
    move-result v7

    .line 348
    invoke-virtual {v3, v13}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 349
    .line 350
    .line 351
    move-result-object v8

    .line 352
    invoke-static {v8}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 353
    .line 354
    .line 355
    move-result v8

    .line 356
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 357
    .line 358
    .line 359
    move-result-object v7

    .line 360
    iput-object v7, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeStartOffset:Ljava/lang/Integer;

    .line 361
    .line 362
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 363
    .line 364
    .line 365
    move-result-object v7

    .line 366
    iput-object v7, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCodeEndOffset:Ljava/lang/Integer;
    :try_end_3
    .catch Ljava/lang/NumberFormatException; {:try_start_3 .. :try_end_3} :catch_4

    .line 367
    .line 368
    invoke-virtual {v3, v12}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 369
    .line 370
    .line 371
    move-result-object v7

    .line 372
    :try_start_4
    new-instance v8, Ljava/lang/StringBuilder;

    .line 373
    .line 374
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 375
    .line 376
    .line 377
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 378
    .line 379
    .line 380
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 381
    .line 382
    .line 383
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 384
    .line 385
    .line 386
    move-result-object v8

    .line 387
    invoke-static {v8}, Ljava/lang/Long;->decode(Ljava/lang/String;)Ljava/lang/Long;

    .line 388
    .line 389
    .line 390
    move-result-object v8

    .line 391
    iput-object v8, v0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCode:Ljava/lang/Long;
    :try_end_4
    .catch Ljava/lang/NumberFormatException; {:try_start_4 .. :try_end_4} :catch_3

    .line 392
    .line 393
    move v8, v14

    .line 394
    goto :goto_5

    .line 395
    :catch_3
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;

    .line 396
    .line 397
    const-string v1, "Cannot parse beacon type code: "

    .line 398
    .line 399
    invoke-static {v1, v7, v10, v6}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 400
    .line 401
    .line 402
    move-result-object v1

    .line 403
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;-><init>(Ljava/lang/String;)V

    .line 404
    .line 405
    .line 406
    throw v0

    .line 407
    :catch_4
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;

    .line 408
    .line 409
    invoke-static {v11, v6}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 410
    .line 411
    .line 412
    move-result-object v1

    .line 413
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;-><init>(Ljava/lang/String;)V

    .line 414
    .line 415
    .line 416
    throw v0

    .line 417
    :cond_5
    sget-object v3, Lorg/altbeacon/beacon/BeaconParser;->S_PATTERN:Ljava/util/regex/Pattern;

    .line 418
    .line 419
    invoke-virtual {v3, v6}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 420
    .line 421
    .line 422
    move-result-object v3

    .line 423
    :goto_6
    invoke-virtual {v3}, Ljava/util/regex/Matcher;->find()Z

    .line 424
    .line 425
    .line 426
    move-result v7

    .line 427
    if-eqz v7, :cond_b

    .line 428
    .line 429
    :try_start_5
    invoke-virtual {v3, v14}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 430
    .line 431
    .line 432
    move-result-object v7

    .line 433
    invoke-static {v7}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 434
    .line 435
    .line 436
    move-result v7

    .line 437
    invoke-virtual {v3, v13}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 438
    .line 439
    .line 440
    move-result-object v8

    .line 441
    invoke-static {v8}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 442
    .line 443
    .line 444
    move-result v8

    .line 445
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 446
    .line 447
    .line 448
    move-result-object v7

    .line 449
    iput-object v7, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidStartOffset:Ljava/lang/Integer;

    .line 450
    .line 451
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 452
    .line 453
    .line 454
    move-result-object v7

    .line 455
    iput-object v7, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidEndOffset:Ljava/lang/Integer;
    :try_end_5
    .catch Ljava/lang/NumberFormatException; {:try_start_5 .. :try_end_5} :catch_7

    .line 456
    .line 457
    invoke-virtual {v3, v12}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 458
    .line 459
    .line 460
    move-result-object v7

    .line 461
    iget-object v8, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidEndOffset:Ljava/lang/Integer;

    .line 462
    .line 463
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 464
    .line 465
    .line 466
    move-result v8

    .line 467
    iget-object v15, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuidStartOffset:Ljava/lang/Integer;

    .line 468
    .line 469
    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    .line 470
    .line 471
    .line 472
    move-result v15

    .line 473
    sub-int/2addr v8, v15

    .line 474
    add-int/2addr v8, v14

    .line 475
    if-ne v8, v13, :cond_7

    .line 476
    .line 477
    :try_start_6
    new-instance v8, Ljava/lang/StringBuilder;

    .line 478
    .line 479
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 480
    .line 481
    .line 482
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 483
    .line 484
    .line 485
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 486
    .line 487
    .line 488
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 489
    .line 490
    .line 491
    move-result-object v8

    .line 492
    invoke-static {v8}, Ljava/lang/Long;->decode(Ljava/lang/String;)Ljava/lang/Long;

    .line 493
    .line 494
    .line 495
    move-result-object v8

    .line 496
    iput-object v8, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid:Ljava/lang/Long;
    :try_end_6
    .catch Ljava/lang/NumberFormatException; {:try_start_6 .. :try_end_6} :catch_5

    .line 497
    .line 498
    move/from16 v16, v13

    .line 499
    .line 500
    :cond_6
    move-object/from16 v19, v1

    .line 501
    .line 502
    move/from16 v17, v14

    .line 503
    .line 504
    goto :goto_9

    .line 505
    :catch_5
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;

    .line 506
    .line 507
    const-string v1, "Cannot parse serviceUuid: "

    .line 508
    .line 509
    invoke-static {v1, v7, v10, v6}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 510
    .line 511
    .line 512
    move-result-object v1

    .line 513
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;-><init>(Ljava/lang/String;)V

    .line 514
    .line 515
    .line 516
    throw v0

    .line 517
    :cond_7
    const/16 v15, 0x10

    .line 518
    .line 519
    if-eq v8, v15, :cond_9

    .line 520
    .line 521
    const/4 v12, 0x4

    .line 522
    if-ne v8, v12, :cond_8

    .line 523
    .line 524
    goto :goto_7

    .line 525
    :cond_8
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;

    .line 526
    .line 527
    const-string v1, "Cannot parse serviceUuid -- it must be 2, 4 or 16 bytes long: "

    .line 528
    .line 529
    invoke-static {v1, v7, v10, v6}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 530
    .line 531
    .line 532
    move-result-object v1

    .line 533
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;-><init>(Ljava/lang/String;)V

    .line 534
    .line 535
    .line 536
    throw v0

    .line 537
    :cond_9
    :goto_7
    const-string v12, "-"

    .line 538
    .line 539
    move/from16 v16, v13

    .line 540
    .line 541
    const-string v13, ""

    .line 542
    .line 543
    invoke-virtual {v7, v12, v13}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 544
    .line 545
    .line 546
    move-result-object v12

    .line 547
    invoke-virtual {v12}, Ljava/lang/String;->length()I

    .line 548
    .line 549
    .line 550
    move-result v13

    .line 551
    div-int/lit8 v13, v13, 0x2

    .line 552
    .line 553
    if-ne v13, v8, :cond_a

    .line 554
    .line 555
    new-array v7, v8, [B

    .line 556
    .line 557
    iput-object v7, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid128Bit:[B

    .line 558
    .line 559
    const/4 v7, 0x0

    .line 560
    :goto_8
    if-ge v7, v8, :cond_6

    .line 561
    .line 562
    mul-int/lit8 v13, v7, 0x2

    .line 563
    .line 564
    move/from16 v17, v14

    .line 565
    .line 566
    add-int/lit8 v14, v13, 0x2

    .line 567
    .line 568
    invoke-virtual {v12, v13, v14}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 569
    .line 570
    .line 571
    move-result-object v13

    .line 572
    :try_start_7
    iget-object v14, v0, Lorg/altbeacon/beacon/BeaconParser;->mServiceUuid128Bit:[B

    .line 573
    .line 574
    sub-int v18, v8, v7

    .line 575
    .line 576
    add-int/lit8 v18, v18, -0x1

    .line 577
    .line 578
    move-object/from16 v19, v1

    .line 579
    .line 580
    invoke-static {v13, v15}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;I)I

    .line 581
    .line 582
    .line 583
    move-result v1

    .line 584
    int-to-byte v1, v1

    .line 585
    aput-byte v1, v14, v18
    :try_end_7
    .catch Ljava/lang/NumberFormatException; {:try_start_7 .. :try_end_7} :catch_6

    .line 586
    .line 587
    add-int/lit8 v7, v7, 0x1

    .line 588
    .line 589
    move/from16 v14, v17

    .line 590
    .line 591
    move-object/from16 v1, v19

    .line 592
    .line 593
    goto :goto_8

    .line 594
    :catch_6
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;

    .line 595
    .line 596
    const-string v1, "Cannot parse serviceUuid byte "

    .line 597
    .line 598
    invoke-static {v1, v13, v10, v6}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 599
    .line 600
    .line 601
    move-result-object v1

    .line 602
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;-><init>(Ljava/lang/String;)V

    .line 603
    .line 604
    .line 605
    throw v0

    .line 606
    :goto_9
    move/from16 v13, v16

    .line 607
    .line 608
    move/from16 v8, v17

    .line 609
    .line 610
    move v14, v8

    .line 611
    move-object/from16 v1, v19

    .line 612
    .line 613
    const/4 v12, 0x3

    .line 614
    goto/16 :goto_6

    .line 615
    .line 616
    :cond_a
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;

    .line 617
    .line 618
    const-string v1, " must be "

    .line 619
    .line 620
    const-string v2, " bytes long but is "

    .line 621
    .line 622
    const-string v3, "ServiceUuid specified: "

    .line 623
    .line 624
    invoke-static {v3, v8, v7, v1, v2}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 625
    .line 626
    .line 627
    move-result-object v1

    .line 628
    invoke-virtual {v12}, Ljava/lang/String;->length()I

    .line 629
    .line 630
    .line 631
    move-result v2

    .line 632
    div-int/lit8 v2, v2, 0x2

    .line 633
    .line 634
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 635
    .line 636
    .line 637
    const-string v2, " bytes long in term: "

    .line 638
    .line 639
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 640
    .line 641
    .line 642
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 643
    .line 644
    .line 645
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 646
    .line 647
    .line 648
    move-result-object v1

    .line 649
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;-><init>(Ljava/lang/String;)V

    .line 650
    .line 651
    .line 652
    throw v0

    .line 653
    :catch_7
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;

    .line 654
    .line 655
    invoke-static {v11, v6}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 656
    .line 657
    .line 658
    move-result-object v1

    .line 659
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;-><init>(Ljava/lang/String;)V

    .line 660
    .line 661
    .line 662
    throw v0

    .line 663
    :cond_b
    move-object/from16 v19, v1

    .line 664
    .line 665
    move/from16 v17, v14

    .line 666
    .line 667
    sget-object v1, Lorg/altbeacon/beacon/BeaconParser;->X_PATTERN:Ljava/util/regex/Pattern;

    .line 668
    .line 669
    invoke-virtual {v1, v6}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 670
    .line 671
    .line 672
    move-result-object v1

    .line 673
    :goto_a
    invoke-virtual {v1}, Ljava/util/regex/Matcher;->find()Z

    .line 674
    .line 675
    .line 676
    move-result v3

    .line 677
    if-eqz v3, :cond_c

    .line 678
    .line 679
    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 680
    .line 681
    iput-object v3, v0, Lorg/altbeacon/beacon/BeaconParser;->mExtraFrame:Ljava/lang/Boolean;

    .line 682
    .line 683
    move/from16 v8, v17

    .line 684
    .line 685
    goto :goto_a

    .line 686
    :cond_c
    if-eqz v8, :cond_d

    .line 687
    .line 688
    add-int/lit8 v4, v4, 0x1

    .line 689
    .line 690
    move-object/from16 v1, v19

    .line 691
    .line 692
    const/4 v3, 0x0

    .line 693
    goto/16 :goto_0

    .line 694
    .line 695
    :cond_d
    const-string v0, "cannot parse term %s"

    .line 696
    .line 697
    filled-new-array {v6}, [Ljava/lang/Object;

    .line 698
    .line 699
    .line 700
    move-result-object v1

    .line 701
    invoke-static {v5, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 702
    .line 703
    .line 704
    new-instance v0, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;

    .line 705
    .line 706
    const-string v1, "Cannot parse beacon layout term: "

    .line 707
    .line 708
    invoke-static {v1, v6}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 709
    .line 710
    .line 711
    move-result-object v1

    .line 712
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/BeaconParser$BeaconLayoutException;-><init>(Ljava/lang/String;)V

    .line 713
    .line 714
    .line 715
    throw v0

    .line 716
    :cond_e
    invoke-direct {v0}, Lorg/altbeacon/beacon/BeaconParser;->calculateLayoutSize()I

    .line 717
    .line 718
    .line 719
    move-result v1

    .line 720
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 721
    .line 722
    .line 723
    move-result-object v1

    .line 724
    iput-object v1, v0, Lorg/altbeacon/beacon/BeaconParser;->mLayoutSize:Ljava/lang/Integer;

    .line 725
    .line 726
    return-object v0
.end method

.method public setHardwareAssistManufacturerCodes([I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconParser;->mHardwareAssistManufacturers:[I

    .line 2
    .line 3
    return-void
.end method

.method public setMatchingBeaconTypeCode(Ljava/lang/Long;)Lorg/altbeacon/beacon/BeaconParser;
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconParser;->mMatchingBeaconTypeCode:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifier:Ljava/lang/String;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mBeaconLayout:Ljava/lang/String;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifier:Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const-string v1, "~"

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconParser;->mBeaconLayout:Ljava/lang/String;

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
