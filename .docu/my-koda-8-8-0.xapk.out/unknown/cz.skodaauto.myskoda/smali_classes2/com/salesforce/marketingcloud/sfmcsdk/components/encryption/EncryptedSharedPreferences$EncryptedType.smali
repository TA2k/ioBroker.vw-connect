.class final enum Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "EncryptedType"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType$Companion;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u000b\u0008\u0082\u0081\u0002\u0018\u0000 \r2\u0008\u0012\u0004\u0012\u00020\u00000\u0001:\u0001\rB\u000f\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0004R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0005\u0010\u0006j\u0002\u0008\u0007j\u0002\u0008\u0008j\u0002\u0008\tj\u0002\u0008\nj\u0002\u0008\u000bj\u0002\u0008\u000c\u00a8\u0006\u000e"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;",
        "",
        "id",
        "",
        "(Ljava/lang/String;II)V",
        "getId",
        "()I",
        "STRING",
        "STRING_SET",
        "INT",
        "LONG",
        "FLOAT",
        "BOOLEAN",
        "Companion",
        "sfmcsdk_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

.field public static final enum BOOLEAN:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType$Companion;

.field public static final enum FLOAT:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

.field public static final enum INT:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

.field public static final enum LONG:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

.field public static final enum STRING:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

.field public static final enum STRING_SET:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;


# instance fields
.field private final id:I


# direct methods
.method private static final synthetic $values()[Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;
    .locals 6

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->STRING:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->STRING_SET:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 4
    .line 5
    sget-object v2, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->INT:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 6
    .line 7
    sget-object v3, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->LONG:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 8
    .line 9
    sget-object v4, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->FLOAT:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 10
    .line 11
    sget-object v5, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->BOOLEAN:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 12
    .line 13
    filled-new-array/range {v0 .. v5}, [Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 2
    .line 3
    const-string v1, "STRING"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->STRING:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 10
    .line 11
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 12
    .line 13
    const-string v1, "STRING_SET"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->STRING_SET:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 20
    .line 21
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 22
    .line 23
    const-string v1, "INT"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;-><init>(Ljava/lang/String;II)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->INT:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 30
    .line 31
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 32
    .line 33
    const-string v1, "LONG"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;-><init>(Ljava/lang/String;II)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->LONG:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 40
    .line 41
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 42
    .line 43
    const-string v1, "FLOAT"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;-><init>(Ljava/lang/String;II)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->FLOAT:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 50
    .line 51
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 52
    .line 53
    const-string v1, "BOOLEAN"

    .line 54
    .line 55
    const/4 v2, 0x5

    .line 56
    invoke-direct {v0, v1, v2, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;-><init>(Ljava/lang/String;II)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->BOOLEAN:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 60
    .line 61
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->$values()[Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->$VALUES:[Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 66
    .line 67
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->$ENTRIES:Lsx0/a;

    .line 72
    .line 73
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType$Companion;

    .line 74
    .line 75
    const/4 v1, 0x0

    .line 76
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 77
    .line 78
    .line 79
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType$Companion;

    .line 80
    .line 81
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;II)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->id:I

    .line 5
    .line 6
    return-void
.end method

.method public static getEntries()Lsx0/a;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lsx0/a;"
        }
    .end annotation

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->$VALUES:[Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getId()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptedSharedPreferences$EncryptedType;->id:I

    .line 2
    .line 3
    return p0
.end method
