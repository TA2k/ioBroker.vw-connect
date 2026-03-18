.class public final synthetic Ltechnology/cariad/cat/genx/crypto/SessionCredentials$$serializer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/crypto/SessionCredentials;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1019
    name = "$serializer"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Luz0/c0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000:\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u00c7\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0003\u0010\u0004J\u001d\u0010\t\u001a\u00020\u00082\u0006\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0007\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0015\u0010\r\u001a\u00020\u00022\u0006\u0010\u000c\u001a\u00020\u000b\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u0017\u0010\u0011\u001a\u000c\u0012\u0008\u0012\u0006\u0012\u0002\u0008\u00030\u00100\u000f\u00a2\u0006\u0004\u0008\u0011\u0010\u0012R\u0017\u0010\u0014\u001a\u00020\u00138\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0014\u0010\u0015\u001a\u0004\u0008\u0016\u0010\u0017\u00a8\u0006\u0018"
    }
    d2 = {
        "technology/cariad/cat/genx/crypto/SessionCredentials.$serializer",
        "Luz0/c0;",
        "Ltechnology/cariad/cat/genx/crypto/SessionCredentials;",
        "<init>",
        "()V",
        "Ltz0/d;",
        "encoder",
        "value",
        "Llx0/b0;",
        "serialize",
        "(Ltz0/d;Ltechnology/cariad/cat/genx/crypto/SessionCredentials;)V",
        "Ltz0/c;",
        "decoder",
        "deserialize",
        "(Ltz0/c;)Ltechnology/cariad/cat/genx/crypto/SessionCredentials;",
        "",
        "Lqz0/a;",
        "childSerializers",
        "()[Lqz0/a;",
        "Lsz0/g;",
        "descriptor",
        "Lsz0/g;",
        "getDescriptor",
        "()Lsz0/g;",
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

.annotation runtime Llx0/c;
.end annotation


# static fields
.field public static final INSTANCE:Ltechnology/cariad/cat/genx/crypto/SessionCredentials$$serializer;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/crypto/SessionCredentials$$serializer;

    .line 2
    .line 3
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/crypto/SessionCredentials$$serializer;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/genx/crypto/SessionCredentials$$serializer;->INSTANCE:Ltechnology/cariad/cat/genx/crypto/SessionCredentials$$serializer;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.cat.genx.crypto.SessionCredentials"

    .line 11
    .line 12
    const/4 v3, 0x5

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "localIdentifier"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "remoteIdentifier"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "sharedSessionKey"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "localNonce"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "remoteNonce"

    .line 38
    .line 39
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    sput-object v1, Ltechnology/cariad/cat/genx/crypto/SessionCredentials$$serializer;->descriptor:Lsz0/g;

    .line 43
    .line 44
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()[",
            "Lqz0/a;"
        }
    .end annotation

    .line 1
    const/4 p0, 0x5

    .line 2
    new-array p0, p0, [Lqz0/a;

    .line 3
    .line 4
    sget-object v0, Luz0/i;->c:Luz0/i;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    aput-object v0, p0, v1

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    aput-object v0, p0, v1

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    aput-object v0, p0, v1

    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    aput-object v0, p0, v1

    .line 17
    .line 18
    const/4 v1, 0x4

    .line 19
    aput-object v0, p0, v1

    .line 20
    .line 21
    return-object p0
.end method

.method public bridge synthetic deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/crypto/SessionCredentials$$serializer;->deserialize(Ltz0/c;)Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    move-result-object p0

    return-object p0
.end method

.method public final deserialize(Ltz0/c;)Ltechnology/cariad/cat/genx/crypto/SessionCredentials;
    .locals 11

    const-string p0, "decoder"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    sget-object p0, Ltechnology/cariad/cat/genx/crypto/SessionCredentials$$serializer;->descriptor:Lsz0/g;

    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    move-result-object p1

    const/4 v0, 0x1

    const/4 v1, 0x0

    const/4 v2, 0x0

    move v4, v1

    move-object v5, v2

    move-object v6, v5

    move-object v7, v6

    move-object v8, v7

    move-object v9, v8

    move v2, v0

    :goto_0
    if-eqz v2, :cond_6

    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    move-result v3

    const/4 v10, -0x1

    if-eq v3, v10, :cond_5

    if-eqz v3, :cond_4

    if-eq v3, v0, :cond_3

    const/4 v10, 0x2

    if-eq v3, v10, :cond_2

    const/4 v10, 0x3

    if-eq v3, v10, :cond_1

    const/4 v10, 0x4

    if-ne v3, v10, :cond_0

    sget-object v3, Luz0/i;->c:Luz0/i;

    invoke-interface {p1, p0, v10, v3, v9}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    move-object v9, v3

    check-cast v9, [B

    or-int/lit8 v4, v4, 0x10

    goto :goto_0

    :cond_0
    new-instance p0, Lqz0/k;

    invoke-direct {p0, v3}, Lqz0/k;-><init>(I)V

    throw p0

    :cond_1
    sget-object v3, Luz0/i;->c:Luz0/i;

    invoke-interface {p1, p0, v10, v3, v8}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    move-object v8, v3

    check-cast v8, [B

    or-int/lit8 v4, v4, 0x8

    goto :goto_0

    :cond_2
    sget-object v3, Luz0/i;->c:Luz0/i;

    invoke-interface {p1, p0, v10, v3, v7}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    move-object v7, v3

    check-cast v7, [B

    or-int/lit8 v4, v4, 0x4

    goto :goto_0

    :cond_3
    sget-object v3, Luz0/i;->c:Luz0/i;

    invoke-interface {p1, p0, v0, v3, v6}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    move-object v6, v3

    check-cast v6, [B

    or-int/lit8 v4, v4, 0x2

    goto :goto_0

    :cond_4
    sget-object v3, Luz0/i;->c:Luz0/i;

    invoke-interface {p1, p0, v1, v3, v5}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    move-object v5, v3

    check-cast v5, [B

    or-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_5
    move v2, v1

    goto :goto_0

    :cond_6
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    new-instance v3, Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    const/4 v10, 0x0

    invoke-direct/range {v3 .. v10}, Ltechnology/cariad/cat/genx/crypto/SessionCredentials;-><init>(I[B[B[B[B[BLuz0/l1;)V

    return-object v3
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/crypto/SessionCredentials$$serializer;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public bridge synthetic serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/crypto/SessionCredentials$$serializer;->serialize(Ltz0/d;Ltechnology/cariad/cat/genx/crypto/SessionCredentials;)V

    return-void
.end method

.method public final serialize(Ltz0/d;Ltechnology/cariad/cat/genx/crypto/SessionCredentials;)V
    .locals 0

    const-string p0, "encoder"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "value"

    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    sget-object p0, Ltechnology/cariad/cat/genx/crypto/SessionCredentials$$serializer;->descriptor:Lsz0/g;

    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    move-result-object p1

    invoke-static {p2, p1, p0}, Ltechnology/cariad/cat/genx/crypto/SessionCredentials;->write$Self$genx_release(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;Ltz0/b;Lsz0/g;)V

    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    return-void
.end method

.method public bridge typeParametersSerializers()[Lqz0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()[",
            "Lqz0/a;"
        }
    .end annotation

    .line 1
    sget-object p0, Luz0/b1;->b:[Lqz0/a;

    .line 2
    .line 3
    return-object p0
.end method
