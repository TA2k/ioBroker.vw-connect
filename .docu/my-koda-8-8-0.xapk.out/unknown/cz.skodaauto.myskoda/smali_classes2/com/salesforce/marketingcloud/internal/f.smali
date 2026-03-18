.class public final Lcom/salesforce/marketingcloud/internal/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/internal/f$a;
    }
.end annotation


# static fields
.field public static final a:Lcom/salesforce/marketingcloud/internal/f$a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/internal/f$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/internal/f$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/internal/f;->a:Lcom/salesforce/marketingcloud/internal/f$a;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final a()I
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/internal/f;->a:Lcom/salesforce/marketingcloud/internal/f$a;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/f$a;->a()I

    move-result v0

    return v0
.end method

.method public static final a(I)V
    .locals 1

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/internal/f;->a:Lcom/salesforce/marketingcloud/internal/f$a;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/internal/f$a;->a(I)V

    return-void
.end method

.method public static final a(Lcom/salesforce/marketingcloud/MCLogListener;)V
    .locals 1

    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/internal/f;->a:Lcom/salesforce/marketingcloud/internal/f$a;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/internal/f$a;->a(Lcom/salesforce/marketingcloud/MCLogListener;)V

    return-void
.end method

.method public static final a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 4
    sget-object v0, Lcom/salesforce/marketingcloud/internal/f;->a:Lcom/salesforce/marketingcloud/internal/f$a;

    invoke-virtual {v0, p0, p1, p2}, Lcom/salesforce/marketingcloud/internal/f$a;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method
