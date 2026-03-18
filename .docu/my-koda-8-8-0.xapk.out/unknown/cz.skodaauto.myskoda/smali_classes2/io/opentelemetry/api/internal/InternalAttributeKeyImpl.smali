.class public final Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/common/AttributeKey;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/api/common/AttributeKey<",
        "TT;>;"
    }
.end annotation


# instance fields
.field private final hashCode:I

.field private final key:Ljava/lang/String;

.field private keyUtf8:[B
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final type:Lio/opentelemetry/api/common/AttributeType;


# direct methods
.method private constructor <init>(Lio/opentelemetry/api/common/AttributeType;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_1

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->type:Lio/opentelemetry/api/common/AttributeType;

    .line 7
    .line 8
    if-eqz p2, :cond_0

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->key:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {p1, p2}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->buildHashCode(Lio/opentelemetry/api/common/AttributeType;Ljava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    iput p1, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->hashCode:I

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 20
    .line 21
    const-string p1, "Null key"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 28
    .line 29
    const-string p1, "Null type"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method

.method private buildHashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->type:Lio/opentelemetry/api/common/AttributeType;

    iget-object p0, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->key:Ljava/lang/String;

    invoke-static {v0, p0}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->buildHashCode(Lio/opentelemetry/api/common/AttributeType;Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method private static buildHashCode(Lio/opentelemetry/api/common/AttributeType;Ljava/lang/String;)I
    .locals 1

    .line 2
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    move-result p0

    const v0, 0xf4243

    xor-int/2addr p0, v0

    mul-int/2addr p0, v0

    .line 3
    invoke-virtual {p1}, Ljava/lang/String;->hashCode()I

    move-result p1

    xor-int/2addr p0, p1

    return p0
.end method

.method public static create(Ljava/lang/String;Lio/opentelemetry/api/common/AttributeType;)Lio/opentelemetry/api/common/AttributeKey;
    .locals 1
    .param p0    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/AttributeType;",
            ")",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const-string p0, ""

    .line 7
    .line 8
    :goto_0
    invoke-direct {v0, p1, p0}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;-><init>(Lio/opentelemetry/api/common/AttributeType;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 4
    .param p1    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->type:Lio/opentelemetry/api/common/AttributeType;

    .line 13
    .line 14
    invoke-virtual {p1}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->getType()Lio/opentelemetry/api/common/AttributeType;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    iget-object p0, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->key:Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {p1}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->getKey()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_1

    .line 35
    .line 36
    return v0

    .line 37
    :cond_1
    return v2
.end method

.method public getKey()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->key:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getKeyUtf8()[B
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->keyUtf8:[B

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->key:Ljava/lang/String;

    .line 6
    .line 7
    sget-object v1, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iput-object v0, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->keyUtf8:[B

    .line 14
    .line 15
    :cond_0
    return-object v0
.end method

.method public getType()Lio/opentelemetry/api/common/AttributeType;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->type:Lio/opentelemetry/api/common/AttributeType;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->hashCode:I

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->key:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
