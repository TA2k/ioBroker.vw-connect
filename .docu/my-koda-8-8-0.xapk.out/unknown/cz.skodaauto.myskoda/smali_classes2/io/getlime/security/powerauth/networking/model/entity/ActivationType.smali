.class public final enum Lio/getlime/security/powerauth/networking/model/entity/ActivationType;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/getlime/security/powerauth/networking/model/entity/ActivationType;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

.field public static final enum CODE:Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

.field public static final enum CUSTOM:Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

.field public static final enum DIRECT:Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

.field public static final enum RECOVERY:Lio/getlime/security/powerauth/networking/model/entity/ActivationType;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 2
    .line 3
    const-string v1, "CODE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/getlime/security/powerauth/networking/model/entity/ActivationType;->CODE:Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 10
    .line 11
    new-instance v1, Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 12
    .line 13
    const-string v2, "DIRECT"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lio/getlime/security/powerauth/networking/model/entity/ActivationType;->DIRECT:Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 20
    .line 21
    new-instance v2, Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 22
    .line 23
    const-string v3, "CUSTOM"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lio/getlime/security/powerauth/networking/model/entity/ActivationType;->CUSTOM:Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 30
    .line 31
    new-instance v3, Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 32
    .line 33
    const-string v4, "RECOVERY"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Lio/getlime/security/powerauth/networking/model/entity/ActivationType;->RECOVERY:Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 40
    .line 41
    filled-new-array {v0, v1, v2, v3}, [Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lio/getlime/security/powerauth/networking/model/entity/ActivationType;->$VALUES:[Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 46
    .line 47
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lio/getlime/security/powerauth/networking/model/entity/ActivationType;
    .locals 1

    .line 1
    const-class v0, Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/getlime/security/powerauth/networking/model/entity/ActivationType;
    .locals 1

    .line 1
    sget-object v0, Lio/getlime/security/powerauth/networking/model/entity/ActivationType;->$VALUES:[Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/getlime/security/powerauth/networking/model/entity/ActivationType;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/getlime/security/powerauth/networking/model/entity/ActivationType;

    .line 8
    .line 9
    return-object v0
.end method
