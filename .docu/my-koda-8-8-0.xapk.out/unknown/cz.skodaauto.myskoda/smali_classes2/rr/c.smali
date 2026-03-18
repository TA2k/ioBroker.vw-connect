.class public final Lrr/c;
.super Ljava/lang/ThreadLocal;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lio/o;


# direct methods
.method public constructor <init>(Lio/o;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lrr/c;->a:Lio/o;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final initialValue()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lrr/c;->a:Lio/o;

    .line 2
    .line 3
    :try_start_0
    sget-object v0, Lrr/a;->f:Lrr/a;

    .line 4
    .line 5
    iget-object v1, p0, Lio/o;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/lang/String;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Lrr/a;->a(Ljava/lang/String;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Ljavax/crypto/Mac;

    .line 14
    .line 15
    iget-object p0, p0, Lio/o;->g:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Ljavax/crypto/spec/SecretKeySpec;

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljavax/crypto/Mac;->init(Ljava/security/Key;)V
    :try_end_0
    .catch Ljava/security/GeneralSecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    .line 21
    .line 22
    return-object v0

    .line 23
    :catch_0
    move-exception p0

    .line 24
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    throw v0
.end method
