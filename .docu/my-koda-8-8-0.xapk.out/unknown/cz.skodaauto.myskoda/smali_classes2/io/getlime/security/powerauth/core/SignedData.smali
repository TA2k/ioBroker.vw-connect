.class public Lio/getlime/security/powerauth/core/SignedData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final data:[B

.field public final signature:[B

.field public final signatureFormat:I

.field public final signingKey:I


# direct methods
.method public constructor <init>([B[BII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/getlime/security/powerauth/core/SignedData;->data:[B

    .line 5
    .line 6
    iput-object p2, p0, Lio/getlime/security/powerauth/core/SignedData;->signature:[B

    .line 7
    .line 8
    iput p3, p0, Lio/getlime/security/powerauth/core/SignedData;->signingKey:I

    .line 9
    .line 10
    iput p4, p0, Lio/getlime/security/powerauth/core/SignedData;->signatureFormat:I

    .line 11
    .line 12
    return-void
.end method
