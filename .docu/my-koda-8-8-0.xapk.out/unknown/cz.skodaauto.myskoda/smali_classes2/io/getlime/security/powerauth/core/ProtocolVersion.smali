.class public final enum Lio/getlime/security/powerauth/core/ProtocolVersion;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/getlime/security/powerauth/core/ProtocolVersion;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/getlime/security/powerauth/core/ProtocolVersion;

.field public static final enum NA:Lio/getlime/security/powerauth/core/ProtocolVersion;

.field public static final enum V2:Lio/getlime/security/powerauth/core/ProtocolVersion;

.field public static final enum V3:Lio/getlime/security/powerauth/core/ProtocolVersion;


# instance fields
.field public final numericValue:I


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 2
    .line 3
    const-string v1, "NA"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lio/getlime/security/powerauth/core/ProtocolVersion;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/getlime/security/powerauth/core/ProtocolVersion;->NA:Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 10
    .line 11
    new-instance v1, Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 12
    .line 13
    const-string v2, "V2"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    const/4 v4, 0x2

    .line 17
    invoke-direct {v1, v2, v3, v4}, Lio/getlime/security/powerauth/core/ProtocolVersion;-><init>(Ljava/lang/String;II)V

    .line 18
    .line 19
    .line 20
    sput-object v1, Lio/getlime/security/powerauth/core/ProtocolVersion;->V2:Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 21
    .line 22
    new-instance v2, Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 23
    .line 24
    const-string v3, "V3"

    .line 25
    .line 26
    const/4 v5, 0x3

    .line 27
    invoke-direct {v2, v3, v4, v5}, Lio/getlime/security/powerauth/core/ProtocolVersion;-><init>(Ljava/lang/String;II)V

    .line 28
    .line 29
    .line 30
    sput-object v2, Lio/getlime/security/powerauth/core/ProtocolVersion;->V3:Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 31
    .line 32
    filled-new-array {v0, v1, v2}, [Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    sput-object v0, Lio/getlime/security/powerauth/core/ProtocolVersion;->$VALUES:[Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 37
    .line 38
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;II)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lio/getlime/security/powerauth/core/ProtocolVersion;->numericValue:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lio/getlime/security/powerauth/core/ProtocolVersion;
    .locals 1

    .line 1
    const-class v0, Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/getlime/security/powerauth/core/ProtocolVersion;
    .locals 1

    .line 1
    sget-object v0, Lio/getlime/security/powerauth/core/ProtocolVersion;->$VALUES:[Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/getlime/security/powerauth/core/ProtocolVersion;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 8
    .line 9
    return-object v0
.end method
