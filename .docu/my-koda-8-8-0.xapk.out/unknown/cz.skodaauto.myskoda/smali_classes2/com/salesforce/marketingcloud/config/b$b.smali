.class public final enum Lcom/salesforce/marketingcloud/config/b$b;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/config/b;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "b"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/config/b$b;",
        ">;"
    }
.end annotation


# static fields
.field public static final enum b:Lcom/salesforce/marketingcloud/config/b$b;

.field private static final synthetic c:[Lcom/salesforce/marketingcloud/config/b$b;

.field private static final synthetic d:Lsx0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/config/b$b;

    .line 2
    .line 3
    const-string v1, "EVENTS"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/config/b$b;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/salesforce/marketingcloud/config/b$b;->b:Lcom/salesforce/marketingcloud/config/b$b;

    .line 10
    .line 11
    invoke-static {}, Lcom/salesforce/marketingcloud/config/b$b;->a()[Lcom/salesforce/marketingcloud/config/b$b;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lcom/salesforce/marketingcloud/config/b$b;->c:[Lcom/salesforce/marketingcloud/config/b$b;

    .line 16
    .line 17
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lcom/salesforce/marketingcloud/config/b$b;->d:Lsx0/a;

    .line 22
    .line 23
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static final synthetic a()[Lcom/salesforce/marketingcloud/config/b$b;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/b$b;->b:Lcom/salesforce/marketingcloud/config/b$b;

    .line 2
    .line 3
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/config/b$b;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method

.method public static b()Lsx0/a;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lsx0/a;"
        }
    .end annotation

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/b$b;->d:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/config/b$b;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/config/b$b;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/config/b$b;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/config/b$b;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/b$b;->c:[Lcom/salesforce/marketingcloud/config/b$b;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/config/b$b;

    .line 8
    .line 9
    return-object v0
.end method
