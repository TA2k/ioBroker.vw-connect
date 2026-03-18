.class public Lio/getlime/security/powerauth/core/ActivationStatus;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/getlime/security/powerauth/core/ActivationStatus$ActivationState;
    }
.end annotation


# static fields
.field public static final State_Active:I = 0x3

.field public static final State_Blocked:I = 0x4

.field public static final State_Created:I = 0x1

.field public static final State_Deadlock:I = 0x80

.field public static final State_Pending_Commit:I = 0x2

.field public static final State_Removed:I = 0x5


# instance fields
.field public final currentVersion:Lio/getlime/security/powerauth/core/ProtocolVersion;

.field private final customObject:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end field

.field public final errorCode:I

.field public final failCount:I

.field public final isSignatureCalculationRecommended:Z

.field public final isUpgradeAvailable:Z

.field public final maxFailCount:I

.field public final needsSerializeSessionState:Z

.field public final state:I

.field public final upgradeVersion:Lio/getlime/security/powerauth/core/ProtocolVersion;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lio/getlime/security/powerauth/core/ActivationStatus;->errorCode:I

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    iput v1, p0, Lio/getlime/security/powerauth/core/ActivationStatus;->state:I

    .line 9
    .line 10
    iput v0, p0, Lio/getlime/security/powerauth/core/ActivationStatus;->failCount:I

    .line 11
    .line 12
    iput v0, p0, Lio/getlime/security/powerauth/core/ActivationStatus;->maxFailCount:I

    .line 13
    .line 14
    sget-object v1, Lio/getlime/security/powerauth/core/ProtocolVersion;->NA:Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 15
    .line 16
    iput-object v1, p0, Lio/getlime/security/powerauth/core/ActivationStatus;->currentVersion:Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 17
    .line 18
    iput-object v1, p0, Lio/getlime/security/powerauth/core/ActivationStatus;->upgradeVersion:Lio/getlime/security/powerauth/core/ProtocolVersion;

    .line 19
    .line 20
    iput-boolean v0, p0, Lio/getlime/security/powerauth/core/ActivationStatus;->isUpgradeAvailable:Z

    .line 21
    .line 22
    iput-boolean v0, p0, Lio/getlime/security/powerauth/core/ActivationStatus;->isSignatureCalculationRecommended:Z

    .line 23
    .line 24
    iput-boolean v0, p0, Lio/getlime/security/powerauth/core/ActivationStatus;->needsSerializeSessionState:Z

    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    iput-object v0, p0, Lio/getlime/security/powerauth/core/ActivationStatus;->customObject:Ljava/util/Map;

    .line 28
    .line 29
    return-void
.end method
