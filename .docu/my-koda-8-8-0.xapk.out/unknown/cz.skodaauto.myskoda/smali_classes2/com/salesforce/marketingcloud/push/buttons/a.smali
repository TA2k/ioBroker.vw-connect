.class public final Lcom/salesforce/marketingcloud/push/buttons/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/push/data/Template;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/buttons/a$a;,
        Lcom/salesforce/marketingcloud/push/buttons/a$c;
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/push/buttons/a;",
            ">;"
        }
    .end annotation
.end field

.field public static final f:Lcom/salesforce/marketingcloud/push/buttons/a$a;


# instance fields
.field private final b:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/buttons/a$c;",
            ">;"
        }
    .end annotation
.end field

.field private final c:Lcom/salesforce/marketingcloud/push/data/Style;

.field private final d:Lcom/salesforce/marketingcloud/push/data/Template$Type;

.field private final e:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/buttons/a$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/push/buttons/a$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/push/buttons/a;->f:Lcom/salesforce/marketingcloud/push/buttons/a$a;

    .line 8
    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/push/buttons/a$b;

    .line 10
    .line 11
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/buttons/a$b;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/push/buttons/a;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>(Ljava/util/List;Lcom/salesforce/marketingcloud/push/data/Style;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/buttons/a$c;",
            ">;",
            "Lcom/salesforce/marketingcloud/push/data/Style;",
            ")V"
        }
    .end annotation

    const-string v0, "items"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->b:Ljava/util/List;

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->c:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 4
    sget-object p1, Lcom/salesforce/marketingcloud/push/data/Template$Type;->RichButtons:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->d:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Lcom/salesforce/marketingcloud/push/data/Style;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 5
    :cond_0
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/push/buttons/a;-><init>(Ljava/util/List;Lcom/salesforce/marketingcloud/push/data/Style;)V

    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/push/buttons/a;Ljava/util/List;Lcom/salesforce/marketingcloud/push/data/Style;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/buttons/a;
    .locals 0

    and-int/lit8 p4, p3, 0x1

    if-eqz p4, :cond_0

    .line 2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->b:Ljava/util/List;

    :cond_0
    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_1

    iget-object p2, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->c:Lcom/salesforce/marketingcloud/push/data/Style;

    :cond_1
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/push/buttons/a;->a(Ljava/util/List;Lcom/salesforce/marketingcloud/push/data/Style;)Lcom/salesforce/marketingcloud/push/buttons/a;

    move-result-object p0

    return-object p0
.end method

.method public static final a(Lcom/salesforce/marketingcloud/push/buttons/a;)Z
    .locals 1

    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/push/buttons/a;->f:Lcom/salesforce/marketingcloud/push/buttons/a$a;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/push/buttons/a$a;->a(Lcom/salesforce/marketingcloud/push/buttons/a;)Z

    move-result p0

    return p0
.end method


# virtual methods
.method public final a(Ljava/util/List;Lcom/salesforce/marketingcloud/push/data/Style;)Lcom/salesforce/marketingcloud/push/buttons/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/buttons/a$c;",
            ">;",
            "Lcom/salesforce/marketingcloud/push/data/Style;",
            ")",
            "Lcom/salesforce/marketingcloud/push/buttons/a;"
        }
    .end annotation

    .line 1
    const-string p0, "items"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p0, Lcom/salesforce/marketingcloud/push/buttons/a;

    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/push/buttons/a;-><init>(Ljava/util/List;Lcom/salesforce/marketingcloud/push/data/Style;)V

    return-object p0
.end method

.method public a()Lcom/salesforce/marketingcloud/push/data/Style;
    .locals 0

    .line 4
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->c:Lcom/salesforce/marketingcloud/push/data/Style;

    return-object p0
.end method

.method public d()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->e:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->b:Ljava/util/List;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/buttons/a;->b:Ljava/util/List;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->c:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 25
    .line 26
    iget-object p1, p1, Lcom/salesforce/marketingcloud/push/buttons/a;->c:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 27
    .line 28
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-nez p0, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    return v0
.end method

.method public f()Lcom/salesforce/marketingcloud/push/data/Template$Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->d:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/buttons/a$c;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->b:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->b:Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->c:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 10
    .line 11
    if-nez p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    :goto_0
    add-int/2addr v0, p0

    .line 20
    return v0
.end method

.method public final j()Lcom/salesforce/marketingcloud/push/data/Style;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->c:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/buttons/a$c;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->b:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->b:Ljava/util/List;

    .line 2
    .line 3
    const-string v0, "RichButtonTemplate(items="

    .line 4
    .line 5
    const-string v1, ")"

    .line 6
    .line 7
    invoke-static {v0, v1, p0}, Lp3/m;->l(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    const-string v0, "out"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->b:Ljava/util/List;

    .line 7
    .line 8
    invoke-static {v0, p1}, Lvj/b;->p(Ljava/util/List;Landroid/os/Parcel;)Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    check-cast v1, Lcom/salesforce/marketingcloud/push/buttons/a$c;

    .line 23
    .line 24
    invoke-virtual {v1, p1, p2}, Lcom/salesforce/marketingcloud/push/buttons/a$c;->writeToParcel(Landroid/os/Parcel;I)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/buttons/a;->c:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 29
    .line 30
    invoke-virtual {p1, p0, p2}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 31
    .line 32
    .line 33
    return-void
.end method
