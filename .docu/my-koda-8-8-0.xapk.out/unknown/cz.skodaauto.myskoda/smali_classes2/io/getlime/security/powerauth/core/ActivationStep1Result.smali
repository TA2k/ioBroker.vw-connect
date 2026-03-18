.class public Lio/getlime/security/powerauth/core/ActivationStep1Result;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final devicePublicKey:Ljava/lang/String;

.field public final errorCode:I


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lio/getlime/security/powerauth/core/ActivationStep1Result;->errorCode:I

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    iput-object v0, p0, Lio/getlime/security/powerauth/core/ActivationStep1Result;->devicePublicKey:Ljava/lang/String;

    .line 9
    .line 10
    return-void
.end method
