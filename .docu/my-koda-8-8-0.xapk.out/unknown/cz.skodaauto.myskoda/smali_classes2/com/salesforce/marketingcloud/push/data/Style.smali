.class public interface abstract Lcom/salesforce/marketingcloud/push/data/Style;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/data/Style$Alignment;,
        Lcom/salesforce/marketingcloud/push/data/Style$a;,
        Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;,
        Lcom/salesforce/marketingcloud/push/data/Style$Size;,
        Lcom/salesforce/marketingcloud/push/data/Style$b;
    }
.end annotation


# static fields
.field public static final a:Lcom/salesforce/marketingcloud/push/data/Style$a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/Style$a;->a:Lcom/salesforce/marketingcloud/push/data/Style$a;

    .line 2
    .line 3
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Style;->a:Lcom/salesforce/marketingcloud/push/data/Style$a;

    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public abstract b()Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;
.end method

.method public abstract c()Lcom/salesforce/marketingcloud/push/data/Style$Size;
.end method

.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public abstract e()Lcom/salesforce/marketingcloud/push/data/Style$Alignment;
.end method

.method public abstract g()Ljava/lang/String;
.end method

.method public abstract i()Ljava/lang/String;
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 1

    .line 1
    const-string p2, "parcel"

    .line 2
    .line 3
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/push/data/Style;->g()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p2

    .line 10
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/push/data/Style;->i()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/push/data/Style;->c()Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    const/4 v0, 0x0

    .line 25
    if-eqz p2, :cond_0

    .line 26
    .line 27
    invoke-virtual {p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    move-object p2, v0

    .line 33
    :goto_0
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/push/data/Style;->e()Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    if-eqz p2, :cond_1

    .line 41
    .line 42
    invoke-virtual {p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    move-object p2, v0

    .line 48
    :goto_1
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/push/data/Style;->b()Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    if-eqz p0, :cond_2

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    :cond_2
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    return-void
.end method
