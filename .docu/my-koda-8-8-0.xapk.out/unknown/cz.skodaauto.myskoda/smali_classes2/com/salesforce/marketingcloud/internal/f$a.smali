.class public final Lcom/salesforce/marketingcloud/internal/f$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/internal/f;
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
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/internal/f$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/g;->b()I

    move-result p0

    return p0
.end method

.method public final a(I)V
    .locals 0

    .line 3
    sget-object p0, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/g;->a(I)V

    return-void
.end method

.method public final a(Lcom/salesforce/marketingcloud/MCLogListener;)V
    .locals 0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/g;->a(Lcom/salesforce/marketingcloud/MCLogListener;)V

    return-void
.end method

.method public final a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 4
    invoke-static {p1, p2, p3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method
