.class public interface abstract Lcom/salesforce/marketingcloud/push/style/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/style/a$a;,
        Lcom/salesforce/marketingcloud/push/style/a$b;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# static fields
.field public static final a:Lcom/salesforce/marketingcloud/push/style/a$a;

.field public static final b:F = 3.0f

.field public static final c:Ljava/lang/String; = "#333333"


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/push/style/a$a;->a:Lcom/salesforce/marketingcloud/push/style/a$a;

    .line 2
    .line 3
    sput-object v0, Lcom/salesforce/marketingcloud/push/style/a;->a:Lcom/salesforce/marketingcloud/push/style/a$a;

    .line 4
    .line 5
    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/push/style/a;Ljava/lang/Object;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    if-nez p4, :cond_1

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    .line 1
    sget-object p2, Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;->R:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    :cond_0
    invoke-interface {p0, p1, p2}, Lcom/salesforce/marketingcloud/push/style/a;->a(Ljava/lang/Object;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;)Ljava/lang/Object;

    move-result-object p0

    return-object p0

    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    const-string p1, "Super calls with default arguments not supported in this target, function: apply"

    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p0
.end method


# virtual methods
.method public abstract a(Ljava/lang/Object;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;",
            "Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;",
            ")TT;"
        }
    .end annotation
.end method
