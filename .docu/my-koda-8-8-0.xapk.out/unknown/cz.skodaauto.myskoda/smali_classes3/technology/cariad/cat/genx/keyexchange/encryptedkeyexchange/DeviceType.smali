.class public final enum Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u0012\n\u0002\u0008\u0007\u0008\u0086\u0081\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001B\u0011\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R\u0014\u0010\u0002\u001a\u00020\u0003X\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007j\u0002\u0008\u0008j\u0002\u0008\t\u00a8\u0006\n"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;",
        "",
        "uuid",
        "",
        "<init>",
        "(Ljava/lang/String;I[B)V",
        "getUuid$genx_release",
        "()[B",
        "SCON3",
        "RSE",
        "genx_release"
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
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

.field public static final enum RSE:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

.field public static final enum SCON3:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;


# instance fields
.field private final uuid:[B


# direct methods
.method private static final synthetic $values()[Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;
    .locals 2

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;->SCON3:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;->RSE:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 15

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 2
    .line 3
    const-string v1, "ac8d11de-7fbf-4abe-b08b-7417d116d384"

    .line 4
    .line 5
    invoke-static {v1}, Ljp/wc;->c(Ljava/lang/String;)Loy0/b;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const/16 v2, 0x10

    .line 10
    .line 11
    new-array v3, v2, [B

    .line 12
    .line 13
    iget-wide v4, v1, Loy0/b;->d:J

    .line 14
    .line 15
    const/4 v6, 0x0

    .line 16
    const/4 v7, 0x7

    .line 17
    move v9, v6

    .line 18
    move v8, v7

    .line 19
    :goto_0
    const/4 v10, -0x1

    .line 20
    if-ge v10, v8, :cond_0

    .line 21
    .line 22
    shl-int/lit8 v10, v8, 0x3

    .line 23
    .line 24
    add-int/lit8 v11, v9, 0x1

    .line 25
    .line 26
    shr-long v12, v4, v10

    .line 27
    .line 28
    long-to-int v10, v12

    .line 29
    int-to-byte v10, v10

    .line 30
    aput-byte v10, v3, v9

    .line 31
    .line 32
    add-int/lit8 v8, v8, -0x1

    .line 33
    .line 34
    move v9, v11

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    iget-wide v4, v1, Loy0/b;->e:J

    .line 37
    .line 38
    const/16 v1, 0x8

    .line 39
    .line 40
    move v9, v1

    .line 41
    move v8, v7

    .line 42
    :goto_1
    if-ge v10, v8, :cond_1

    .line 43
    .line 44
    shl-int/lit8 v11, v8, 0x3

    .line 45
    .line 46
    add-int/lit8 v12, v9, 0x1

    .line 47
    .line 48
    shr-long v13, v4, v11

    .line 49
    .line 50
    long-to-int v11, v13

    .line 51
    int-to-byte v11, v11

    .line 52
    aput-byte v11, v3, v9

    .line 53
    .line 54
    add-int/lit8 v8, v8, -0x1

    .line 55
    .line 56
    move v9, v12

    .line 57
    goto :goto_1

    .line 58
    :cond_1
    const-string v4, "SCON3"

    .line 59
    .line 60
    invoke-direct {v0, v4, v6, v3}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;-><init>(Ljava/lang/String;I[B)V

    .line 61
    .line 62
    .line 63
    sput-object v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;->SCON3:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 64
    .line 65
    new-instance v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 66
    .line 67
    const-string v3, "9d7dbdf6-e0e5-4789-bed4-f4b0bc48b7a5"

    .line 68
    .line 69
    invoke-static {v3}, Ljp/wc;->c(Ljava/lang/String;)Loy0/b;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    new-array v2, v2, [B

    .line 74
    .line 75
    iget-wide v4, v3, Loy0/b;->d:J

    .line 76
    .line 77
    move v8, v7

    .line 78
    :goto_2
    if-ge v10, v8, :cond_2

    .line 79
    .line 80
    shl-int/lit8 v9, v8, 0x3

    .line 81
    .line 82
    add-int/lit8 v11, v6, 0x1

    .line 83
    .line 84
    shr-long v12, v4, v9

    .line 85
    .line 86
    long-to-int v9, v12

    .line 87
    int-to-byte v9, v9

    .line 88
    aput-byte v9, v2, v6

    .line 89
    .line 90
    add-int/lit8 v8, v8, -0x1

    .line 91
    .line 92
    move v6, v11

    .line 93
    goto :goto_2

    .line 94
    :cond_2
    iget-wide v3, v3, Loy0/b;->e:J

    .line 95
    .line 96
    :goto_3
    if-ge v10, v7, :cond_3

    .line 97
    .line 98
    shl-int/lit8 v5, v7, 0x3

    .line 99
    .line 100
    add-int/lit8 v6, v1, 0x1

    .line 101
    .line 102
    shr-long v8, v3, v5

    .line 103
    .line 104
    long-to-int v5, v8

    .line 105
    int-to-byte v5, v5

    .line 106
    aput-byte v5, v2, v1

    .line 107
    .line 108
    add-int/lit8 v7, v7, -0x1

    .line 109
    .line 110
    move v1, v6

    .line 111
    goto :goto_3

    .line 112
    :cond_3
    const-string v1, "RSE"

    .line 113
    .line 114
    const/4 v3, 0x1

    .line 115
    invoke-direct {v0, v1, v3, v2}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;-><init>(Ljava/lang/String;I[B)V

    .line 116
    .line 117
    .line 118
    sput-object v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;->RSE:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 119
    .line 120
    invoke-static {}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;->$values()[Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    sput-object v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;->$VALUES:[Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 125
    .line 126
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    sput-object v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;->$ENTRIES:Lsx0/a;

    .line 131
    .line 132
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I[B)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([B)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;->uuid:[B

    .line 5
    .line 6
    return-void
.end method

.method public static getEntries()Lsx0/a;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lsx0/a;"
        }
    .end annotation

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;
    .locals 1

    .line 1
    const-class v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;->$VALUES:[Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getUuid$genx_release()[B
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;->uuid:[B

    .line 2
    .line 3
    return-object p0
.end method
