.class public Lio/getlime/security/powerauth/networking/model/response/GetTemporaryKeyResponse;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private activationId:Ljava/lang/String;

.field private applicationKey:Ljava/lang/String;

.field private challenge:Ljava/lang/String;

.field private expiration:J
    .annotation runtime Lmu/b;
        value = "exp_ms"
    .end annotation
.end field

.field private keyId:Ljava/lang/String;
    .annotation runtime Lmu/b;
        value = "sub"
    .end annotation
.end field

.field private publicKey:Ljava/lang/String;

.field private serverTime:J
    .annotation runtime Lmu/b;
        value = "iat_ms"
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
