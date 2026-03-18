.class public final Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
        "TT;>;"
    }
.end annotation


# instance fields
.field private attributeKey:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final hashCode:I

.field private final key:Ljava/lang/String;

.field private keyUtf8:[B
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final type:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;


# direct methods
.method private constructor <init>(Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_1

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->type:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 7
    .line 8
    if-eqz p2, :cond_0

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->key:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {p1, p2}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->buildHashCode(Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;Ljava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    iput p1, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->hashCode:I

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
    iget-object v0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->type:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    iget-object p0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->key:Ljava/lang/String;

    invoke-static {v0, p0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->buildHashCode(Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method private static buildHashCode(Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;Ljava/lang/String;)I
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

.method public static create(Ljava/lang/String;Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
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
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;",
            ")",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;

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
    invoke-direct {v0, p1, p0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;-><init>(Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public static toAttributeKey(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Lio/opentelemetry/api/common/AttributeKey;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;)",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$incubator$common$ExtendedAttributeType:[I

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getType()Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    aget v0, v0, v1

    .line 12
    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    new-instance v1, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v2, "Unrecognized extendedAttributeKey type: "

    .line 21
    .line 22
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getType()Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw v0

    .line 40
    :pswitch_0
    const/4 p0, 0x0

    .line 41
    return-object p0

    .line 42
    :pswitch_1
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    sget-object v0, Lio/opentelemetry/api/common/AttributeType;->DOUBLE_ARRAY:Lio/opentelemetry/api/common/AttributeType;

    .line 47
    .line 48
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/common/AttributeType;)Lio/opentelemetry/api/common/AttributeKey;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :pswitch_2
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    sget-object v0, Lio/opentelemetry/api/common/AttributeType;->LONG_ARRAY:Lio/opentelemetry/api/common/AttributeType;

    .line 58
    .line 59
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/common/AttributeType;)Lio/opentelemetry/api/common/AttributeKey;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    :pswitch_3
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    sget-object v0, Lio/opentelemetry/api/common/AttributeType;->BOOLEAN_ARRAY:Lio/opentelemetry/api/common/AttributeType;

    .line 69
    .line 70
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/common/AttributeType;)Lio/opentelemetry/api/common/AttributeKey;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    sget-object v0, Lio/opentelemetry/api/common/AttributeType;->STRING_ARRAY:Lio/opentelemetry/api/common/AttributeType;

    .line 80
    .line 81
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/common/AttributeType;)Lio/opentelemetry/api/common/AttributeKey;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0

    .line 86
    :pswitch_5
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    sget-object v0, Lio/opentelemetry/api/common/AttributeType;->DOUBLE:Lio/opentelemetry/api/common/AttributeType;

    .line 91
    .line 92
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/common/AttributeType;)Lio/opentelemetry/api/common/AttributeKey;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0

    .line 97
    :pswitch_6
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    sget-object v0, Lio/opentelemetry/api/common/AttributeType;->LONG:Lio/opentelemetry/api/common/AttributeType;

    .line 102
    .line 103
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/common/AttributeType;)Lio/opentelemetry/api/common/AttributeKey;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0

    .line 108
    :pswitch_7
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    sget-object v0, Lio/opentelemetry/api/common/AttributeType;->BOOLEAN:Lio/opentelemetry/api/common/AttributeType;

    .line 113
    .line 114
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/common/AttributeType;)Lio/opentelemetry/api/common/AttributeKey;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0

    .line 119
    :pswitch_8
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    sget-object v0, Lio/opentelemetry/api/common/AttributeType;->STRING:Lio/opentelemetry/api/common/AttributeType;

    .line 124
    .line 125
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/InternalAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/common/AttributeType;)Lio/opentelemetry/api/common/AttributeKey;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0

    .line 130
    nop

    .line 131
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static toExtendedAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;)",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$common$AttributeType:[I

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getType()Lio/opentelemetry/api/common/AttributeType;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    aget v0, v0, v1

    .line 12
    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    new-instance v1, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v2, "Unrecognized attributeKey type: "

    .line 21
    .line 22
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getType()Lio/opentelemetry/api/common/AttributeType;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw v0

    .line 40
    :pswitch_0
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    sget-object v0, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->DOUBLE_ARRAY:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 45
    .line 46
    invoke-static {p0, v0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :pswitch_1
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    sget-object v0, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->LONG_ARRAY:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 56
    .line 57
    invoke-static {p0, v0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_2
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    sget-object v0, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->BOOLEAN_ARRAY:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 67
    .line 68
    invoke-static {p0, v0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0

    .line 73
    :pswitch_3
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    sget-object v0, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->STRING_ARRAY:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 78
    .line 79
    invoke-static {p0, v0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0

    .line 84
    :pswitch_4
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    sget-object v0, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->DOUBLE:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 89
    .line 90
    invoke-static {p0, v0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    return-object p0

    .line 95
    :pswitch_5
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    sget-object v0, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->LONG:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 100
    .line 101
    invoke-static {p0, v0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    return-object p0

    .line 106
    :pswitch_6
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    sget-object v0, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->BOOLEAN:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 111
    .line 112
    invoke-static {p0, v0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    return-object p0

    .line 117
    :pswitch_7
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    sget-object v0, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->STRING:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 122
    .line 123
    invoke-static {p0, v0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    return-object p0

    .line 128
    nop

    .line 129
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public asAttributeKey()Lio/opentelemetry/api/common/AttributeKey;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->attributeKey:Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->toAttributeKey(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Lio/opentelemetry/api/common/AttributeKey;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iput-object v0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->attributeKey:Lio/opentelemetry/api/common/AttributeKey;

    .line 10
    .line 11
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->attributeKey:Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    return-object p0
.end method

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
    instance-of v1, p1, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->type:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 13
    .line 14
    invoke-virtual {p1}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->getType()Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

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
    iget-object p0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->key:Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {p1}, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->getKey()Ljava/lang/String;

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
    iget-object p0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->key:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getKeyUtf8()[B
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->keyUtf8:[B

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->key:Ljava/lang/String;

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
    iput-object v0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->keyUtf8:[B

    .line 14
    .line 15
    :cond_0
    return-object v0
.end method

.method public getType()Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->type:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->hashCode:I

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;->key:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
