.class public final Lcom/salesforce/marketingcloud/config/a$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/config/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/config/a$a;-><init>()V

    return-void
.end method

.method public static synthetic b()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final a()Lcom/salesforce/marketingcloud/config/a;
    .locals 0

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->a()Lcom/salesforce/marketingcloud/config/a;

    move-result-object p0

    return-object p0
.end method

.method public final a(Lcom/salesforce/marketingcloud/config/a;)V
    .locals 0

    .line 2
    invoke-static {p1}, Lcom/salesforce/marketingcloud/config/a;->a(Lcom/salesforce/marketingcloud/config/a;)V

    return-void
.end method

.method public final c()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->b()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final d()Ljava/util/EnumSet;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/EnumSet<",
            "Lcom/salesforce/marketingcloud/k$e;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/config/a;->c()Ljava/util/EnumSet;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
