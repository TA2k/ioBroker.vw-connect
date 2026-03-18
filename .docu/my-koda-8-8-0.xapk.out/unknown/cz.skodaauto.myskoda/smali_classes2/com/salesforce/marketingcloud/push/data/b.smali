.class public final Lcom/salesforce/marketingcloud/push/data/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/push/data/d;
.implements Landroid/os/Parcelable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/data/b$a;
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/push/data/b;",
            ">;"
        }
    .end annotation
.end field

.field public static final f:Lcom/salesforce/marketingcloud/push/data/b$a;


# instance fields
.field private final b:Ljava/lang/String;

.field private final c:Lcom/salesforce/marketingcloud/push/data/c;

.field private final d:Lcom/salesforce/marketingcloud/push/data/Style;

.field private final e:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/data/a;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/b$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/push/data/b$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/b;->f:Lcom/salesforce/marketingcloud/push/data/b$a;

    .line 8
    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/b$b;

    .line 10
    .line 11
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/data/b$b;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/b;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/push/data/c;",
            "Lcom/salesforce/marketingcloud/push/data/Style;",
            "Ljava/util/List<",
            "+",
            "Lcom/salesforce/marketingcloud/push/data/a;",
            ">;)V"
        }
    .end annotation

    const-string v0, "url"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/data/b;->b:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/push/data/b;->c:Lcom/salesforce/marketingcloud/push/data/c;

    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/push/data/b;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/push/data/b;->e:Ljava/util/List;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p6, p5, 0x2

    const/4 v0, 0x0

    if-eqz p6, :cond_0

    move-object p2, v0

    :cond_0
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_1

    move-object p3, v0

    :cond_1
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_2

    .line 6
    sget-object p4, Lmx0/s;->d:Lmx0/s;

    .line 7
    :cond_2
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/push/data/b;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;)V

    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/push/data/b;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/data/b;
    .locals 0

    and-int/lit8 p6, p5, 0x1

    if-eqz p6, :cond_0

    .line 2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/push/data/b;->b:Ljava/lang/String;

    :cond_0
    and-int/lit8 p6, p5, 0x2

    if-eqz p6, :cond_1

    iget-object p2, p0, Lcom/salesforce/marketingcloud/push/data/b;->c:Lcom/salesforce/marketingcloud/push/data/c;

    :cond_1
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_2

    iget-object p3, p0, Lcom/salesforce/marketingcloud/push/data/b;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    :cond_2
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_3

    iget-object p4, p0, Lcom/salesforce/marketingcloud/push/data/b;->e:Ljava/util/List;

    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/push/data/b;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;)Lcom/salesforce/marketingcloud/push/data/b;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public a()Lcom/salesforce/marketingcloud/push/data/Style;
    .locals 0

    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/b;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    return-object p0
.end method

.method public final a(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;)Lcom/salesforce/marketingcloud/push/data/b;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/push/data/c;",
            "Lcom/salesforce/marketingcloud/push/data/Style;",
            "Ljava/util/List<",
            "+",
            "Lcom/salesforce/marketingcloud/push/data/a;",
            ">;)",
            "Lcom/salesforce/marketingcloud/push/data/b;"
        }
    .end annotation

    .line 1
    const-string p0, "url"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p0, Lcom/salesforce/marketingcloud/push/data/b;

    invoke-direct {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/push/data/b;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;)V

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
    instance-of v1, p1, Lcom/salesforce/marketingcloud/push/data/b;

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
    check-cast p1, Lcom/salesforce/marketingcloud/push/data/b;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/b;->b:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/data/b;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/b;->c:Lcom/salesforce/marketingcloud/push/data/c;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/data/b;->c:Lcom/salesforce/marketingcloud/push/data/c;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/b;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 36
    .line 37
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/data/b;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/b;->e:Ljava/util/List;

    .line 47
    .line 48
    iget-object p1, p1, Lcom/salesforce/marketingcloud/push/data/b;->e:Ljava/util/List;

    .line 49
    .line 50
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-nez p0, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    return v0
.end method

.method public h()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/data/a;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/b;->e:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/data/b;->b:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/b;->c:Lcom/salesforce/marketingcloud/push/data/c;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    move v1, v2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/c;->hashCode()I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    :goto_0
    add-int/2addr v0, v1

    .line 21
    mul-int/lit8 v0, v0, 0x1f

    .line 22
    .line 23
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/b;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 24
    .line 25
    if-nez v1, :cond_1

    .line 26
    .line 27
    move v1, v2

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    :goto_1
    add-int/2addr v0, v1

    .line 34
    mul-int/lit8 v0, v0, 0x1f

    .line 35
    .line 36
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/b;->e:Ljava/util/List;

    .line 37
    .line 38
    if-nez p0, :cond_2

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    :goto_2
    add-int/2addr v0, v2

    .line 46
    return v0
.end method

.method public final j()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/b;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k()Lcom/salesforce/marketingcloud/push/data/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/b;->c:Lcom/salesforce/marketingcloud/push/data/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l()Lcom/salesforce/marketingcloud/push/data/Style;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/b;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/data/a;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/b;->e:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final n()Lcom/salesforce/marketingcloud/push/data/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/b;->c:Lcom/salesforce/marketingcloud/push/data/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final o()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/b;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/data/b;->b:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/b;->c:Lcom/salesforce/marketingcloud/push/data/c;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/b;->a()Lcom/salesforce/marketingcloud/push/data/Style;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/data/b;->h()Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    new-instance v3, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v4, "Media(url="

    .line 16
    .line 17
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v0, ", altText="

    .line 24
    .line 25
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v0, ", style="

    .line 32
    .line 33
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v0, ", action="

    .line 40
    .line 41
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string p0, ")"

    .line 48
    .line 49
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 3

    .line 1
    const-string v0, "out"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/data/b;->b:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/data/b;->c:Lcom/salesforce/marketingcloud/push/data/c;

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    const/4 v2, 0x0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/push/data/c;->writeToParcel(Landroid/os/Parcel;I)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/data/b;->d:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 28
    .line 29
    invoke-virtual {p1, v0, p2}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/b;->e:Ljava/util/List;

    .line 33
    .line 34
    if-nez p0, :cond_1

    .line 35
    .line 36
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :cond_1
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 41
    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 48
    .line 49
    .line 50
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-eqz v0, :cond_2

    .line 59
    .line 60
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    check-cast v0, Landroid/os/Parcelable;

    .line 65
    .line 66
    invoke-virtual {p1, v0, p2}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
    return-void
.end method
