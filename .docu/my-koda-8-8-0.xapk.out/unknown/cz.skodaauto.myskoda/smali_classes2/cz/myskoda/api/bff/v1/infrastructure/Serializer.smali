.class public final Lcz/myskoda/api/bff/v1/infrastructure/Serializer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0008\u00c6\u0002\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R \u0010\u0005\u001a\u00020\u00048\u0006X\u0087\u0004\u00a2\u0006\u0012\n\u0004\u0008\u0005\u0010\u0006\u0012\u0004\u0008\t\u0010\u0003\u001a\u0004\u0008\u0007\u0010\u0008R!\u0010\u0010\u001a\u00020\n8FX\u0087\u0084\u0002\u00a2\u0006\u0012\n\u0004\u0008\u000b\u0010\u000c\u0012\u0004\u0008\u000f\u0010\u0003\u001a\u0004\u0008\r\u0010\u000e\u00a8\u0006\u0011"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/infrastructure/Serializer;",
        "",
        "<init>",
        "()V",
        "Lcom/squareup/moshi/Moshi$Builder;",
        "moshiBuilder",
        "Lcom/squareup/moshi/Moshi$Builder;",
        "getMoshiBuilder",
        "()Lcom/squareup/moshi/Moshi$Builder;",
        "getMoshiBuilder$annotations",
        "Lcom/squareup/moshi/Moshi;",
        "moshi$delegate",
        "Llx0/i;",
        "getMoshi",
        "()Lcom/squareup/moshi/Moshi;",
        "getMoshi$annotations",
        "moshi",
        "bff-api_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final INSTANCE:Lcz/myskoda/api/bff/v1/infrastructure/Serializer;

.field private static final moshi$delegate:Llx0/i;

.field private static final moshiBuilder:Lcom/squareup/moshi/Moshi$Builder;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcz/myskoda/api/bff/v1/infrastructure/Serializer;

    .line 2
    .line 3
    invoke-direct {v0}, Lcz/myskoda/api/bff/v1/infrastructure/Serializer;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcz/myskoda/api/bff/v1/infrastructure/Serializer;->INSTANCE:Lcz/myskoda/api/bff/v1/infrastructure/Serializer;

    .line 7
    .line 8
    new-instance v0, Lcom/squareup/moshi/Moshi$Builder;

    .line 9
    .line 10
    invoke-direct {v0}, Lcom/squareup/moshi/Moshi$Builder;-><init>()V

    .line 11
    .line 12
    .line 13
    new-instance v1, Lcz/myskoda/api/bff/v1/infrastructure/OffsetDateTimeAdapter;

    .line 14
    .line 15
    invoke-direct {v1}, Lcz/myskoda/api/bff/v1/infrastructure/OffsetDateTimeAdapter;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    new-instance v1, Lcz/myskoda/api/bff/v1/infrastructure/LocalDateTimeAdapter;

    .line 22
    .line 23
    invoke-direct {v1}, Lcz/myskoda/api/bff/v1/infrastructure/LocalDateTimeAdapter;-><init>()V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    new-instance v1, Lcz/myskoda/api/bff/v1/infrastructure/LocalDateAdapter;

    .line 30
    .line 31
    invoke-direct {v1}, Lcz/myskoda/api/bff/v1/infrastructure/LocalDateAdapter;-><init>()V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    new-instance v1, Lcz/myskoda/api/bff/v1/infrastructure/UUIDAdapter;

    .line 38
    .line 39
    invoke-direct {v1}, Lcz/myskoda/api/bff/v1/infrastructure/UUIDAdapter;-><init>()V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    new-instance v1, Lcz/myskoda/api/bff/v1/infrastructure/ByteArrayAdapter;

    .line 46
    .line 47
    invoke-direct {v1}, Lcz/myskoda/api/bff/v1/infrastructure/ByteArrayAdapter;-><init>()V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance v1, Lcz/myskoda/api/bff/v1/infrastructure/URIAdapter;

    .line 54
    .line 55
    invoke-direct {v1}, Lcz/myskoda/api/bff/v1/infrastructure/URIAdapter;-><init>()V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    new-instance v1, Lbx/d;

    .line 62
    .line 63
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/Moshi$Builder;->a(Lcom/squareup/moshi/JsonAdapter$Factory;)V

    .line 67
    .line 68
    .line 69
    new-instance v1, Lcz/myskoda/api/bff/v1/infrastructure/BigDecimalAdapter;

    .line 70
    .line 71
    invoke-direct {v1}, Lcz/myskoda/api/bff/v1/infrastructure/BigDecimalAdapter;-><init>()V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    new-instance v1, Lcz/myskoda/api/bff/v1/infrastructure/BigIntegerAdapter;

    .line 78
    .line 79
    invoke-direct {v1}, Lcz/myskoda/api/bff/v1/infrastructure/BigIntegerAdapter;-><init>()V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v0, v1}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    sput-object v0, Lcz/myskoda/api/bff/v1/infrastructure/Serializer;->moshiBuilder:Lcom/squareup/moshi/Moshi$Builder;

    .line 86
    .line 87
    new-instance v0, Ll31/b;

    .line 88
    .line 89
    const/16 v1, 0xf

    .line 90
    .line 91
    invoke-direct {v0, v1}, Ll31/b;-><init>(I)V

    .line 92
    .line 93
    .line 94
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    sput-object v0, Lcz/myskoda/api/bff/v1/infrastructure/Serializer;->moshi$delegate:Llx0/i;

    .line 99
    .line 100
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

.method public static synthetic a()Lcom/squareup/moshi/Moshi;
    .locals 1

    .line 1
    invoke-static {}, Lcz/myskoda/api/bff/v1/infrastructure/Serializer;->moshi_delegate$lambda$0()Lcom/squareup/moshi/Moshi;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static final getMoshi()Lcom/squareup/moshi/Moshi;
    .locals 2

    .line 1
    sget-object v0, Lcz/myskoda/api/bff/v1/infrastructure/Serializer;->moshi$delegate:Llx0/i;

    .line 2
    .line 3
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "getValue(...)"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    check-cast v0, Lcom/squareup/moshi/Moshi;

    .line 13
    .line 14
    return-object v0
.end method

.method public static synthetic getMoshi$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static final getMoshiBuilder()Lcom/squareup/moshi/Moshi$Builder;
    .locals 1

    .line 1
    sget-object v0, Lcz/myskoda/api/bff/v1/infrastructure/Serializer;->moshiBuilder:Lcom/squareup/moshi/Moshi$Builder;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic getMoshiBuilder$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method private static final moshi_delegate$lambda$0()Lcom/squareup/moshi/Moshi;
    .locals 1

    .line 1
    sget-object v0, Lcz/myskoda/api/bff/v1/infrastructure/Serializer;->moshiBuilder:Lcom/squareup/moshi/Moshi$Builder;

    .line 2
    .line 3
    invoke-static {v0, v0}, Lkx/a;->c(Lcom/squareup/moshi/Moshi$Builder;Lcom/squareup/moshi/Moshi$Builder;)Lcom/squareup/moshi/Moshi;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method
