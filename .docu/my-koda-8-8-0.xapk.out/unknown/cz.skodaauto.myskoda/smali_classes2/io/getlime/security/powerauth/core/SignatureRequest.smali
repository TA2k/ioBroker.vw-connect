.class public Lio/getlime/security/powerauth/core/SignatureRequest;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final body:[B

.field public final method:Ljava/lang/String;

.field public final offlineNonce:Ljava/lang/String;

.field public final offlineSignatureLength:I

.field public final uriIdentifier:Ljava/lang/String;


# direct methods
.method public constructor <init>([BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/getlime/security/powerauth/core/SignatureRequest;->body:[B

    .line 5
    .line 6
    iput-object p2, p0, Lio/getlime/security/powerauth/core/SignatureRequest;->method:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lio/getlime/security/powerauth/core/SignatureRequest;->uriIdentifier:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lio/getlime/security/powerauth/core/SignatureRequest;->offlineNonce:Ljava/lang/String;

    .line 11
    .line 12
    iput p5, p0, Lio/getlime/security/powerauth/core/SignatureRequest;->offlineSignatureLength:I

    .line 13
    .line 14
    return-void
.end method
