.class public final Lcom/salesforce/marketingcloud/push/carousel/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/push/data/Template;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/carousel/a$a;,
        Lcom/salesforce/marketingcloud/push/carousel/a$b;
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/push/carousel/a;",
            ">;"
        }
    .end annotation
.end field

.field public static final g:Lcom/salesforce/marketingcloud/push/carousel/a$b;

.field public static final h:I


# instance fields
.field private final b:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/carousel/a$a;",
            ">;"
        }
    .end annotation
.end field

.field private final c:I

.field private final d:Lcom/salesforce/marketingcloud/push/data/Style;

.field private final e:Lcom/salesforce/marketingcloud/push/data/Template$Type;

.field private final f:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/carousel/a$b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/push/carousel/a$b;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/push/carousel/a;->g:Lcom/salesforce/marketingcloud/push/carousel/a$b;

    .line 8
    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/push/carousel/a$c;

    .line 10
    .line 11
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/carousel/a$c;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/push/carousel/a;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>(Ljava/util/List;ILcom/salesforce/marketingcloud/push/data/Style;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/carousel/a$a;",
            ">;I",
            "Lcom/salesforce/marketingcloud/push/data/Style;",
            ")V"
        }
    .end annotation

    const-string v0, "items"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->b:Ljava/util/List;

    .line 3
    iput p2, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->c:I

    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 5
    sget-object p1, Lcom/salesforce/marketingcloud/push/data/Template$Type;->CarouselFull:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->e:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;ILcom/salesforce/marketingcloud/push/data/Style;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p5, p4, 0x2

    if-eqz p5, :cond_0

    const/4 p2, 0x0

    :cond_0
    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_1

    const/4 p3, 0x0

    .line 6
    :cond_1
    invoke-direct {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/push/carousel/a;-><init>(Ljava/util/List;ILcom/salesforce/marketingcloud/push/data/Style;)V

    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/push/carousel/a;Ljava/util/List;ILcom/salesforce/marketingcloud/push/data/Style;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/carousel/a;
    .locals 0

    and-int/lit8 p5, p4, 0x1

    if-eqz p5, :cond_0

    .line 2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->b:Ljava/util/List;

    :cond_0
    and-int/lit8 p5, p4, 0x2

    if-eqz p5, :cond_1

    iget p2, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->c:I

    :cond_1
    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_2

    iget-object p3, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/push/carousel/a;->a(Ljava/util/List;ILcom/salesforce/marketingcloud/push/data/Style;)Lcom/salesforce/marketingcloud/push/carousel/a;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final a(Ljava/util/List;ILcom/salesforce/marketingcloud/push/data/Style;)Lcom/salesforce/marketingcloud/push/carousel/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/carousel/a$a;",
            ">;I",
            "Lcom/salesforce/marketingcloud/push/data/Style;",
            ")",
            "Lcom/salesforce/marketingcloud/push/carousel/a;"
        }
    .end annotation

    .line 1
    const-string p0, "items"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p0, Lcom/salesforce/marketingcloud/push/carousel/a;

    invoke-direct {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/push/carousel/a;-><init>(Ljava/util/List;ILcom/salesforce/marketingcloud/push/data/Style;)V

    return-object p0
.end method

.method public a()Lcom/salesforce/marketingcloud/push/data/Style;
    .locals 0

    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    return-object p0
.end method

.method public d()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->f:Ljava/lang/String;

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
    instance-of v1, p1, Lcom/salesforce/marketingcloud/push/carousel/a;

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
    check-cast p1, Lcom/salesforce/marketingcloud/push/carousel/a;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->b:Ljava/util/List;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/carousel/a;->b:Ljava/util/List;

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
    iget v1, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->c:I

    .line 25
    .line 26
    iget v3, p1, Lcom/salesforce/marketingcloud/push/carousel/a;->c:I

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 32
    .line 33
    iget-object p1, p1, Lcom/salesforce/marketingcloud/push/carousel/a;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 34
    .line 35
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    if-nez p0, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    return v0
.end method

.method public f()Lcom/salesforce/marketingcloud/push/data/Template$Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->e:Lcom/salesforce/marketingcloud/push/data/Template$Type;

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
            "Lcom/salesforce/marketingcloud/push/carousel/a$a;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->b:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->b:Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget v2, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->c:I

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 17
    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    :goto_0
    add-int/2addr v0, p0

    .line 27
    return v0
.end method

.method public final j()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->c:I

    .line 2
    .line 3
    return p0
.end method

.method public final k()Lcom/salesforce/marketingcloud/push/data/Style;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/carousel/a$a;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->b:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->c:I

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->b:Ljava/util/List;

    .line 2
    .line 3
    iget p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->c:I

    .line 4
    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "CarouselFullTemplate(items="

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v0, ", selectedIndex="

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ")"

    .line 24
    .line 25
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
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
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->b:Ljava/util/List;

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
    check-cast v1, Lcom/salesforce/marketingcloud/push/carousel/a$a;

    .line 23
    .line 24
    invoke-virtual {v1, p1, p2}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->writeToParcel(Landroid/os/Parcel;I)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    iget v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->c:I

    .line 29
    .line 30
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 34
    .line 35
    invoke-virtual {p1, p0, p2}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 36
    .line 37
    .line 38
    return-void
.end method
