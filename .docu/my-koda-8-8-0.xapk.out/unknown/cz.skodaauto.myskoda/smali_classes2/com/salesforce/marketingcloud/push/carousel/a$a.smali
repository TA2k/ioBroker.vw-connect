.class public final Lcom/salesforce/marketingcloud/push/carousel/a$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;
.implements Lcom/salesforce/marketingcloud/push/data/d;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/carousel/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/push/carousel/a$a;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final b:Ljava/lang/String;

.field private final c:Lcom/salesforce/marketingcloud/push/data/b;

.field private final d:Lcom/salesforce/marketingcloud/push/data/c;

.field private final e:Lcom/salesforce/marketingcloud/push/data/c;

.field private final f:Lcom/salesforce/marketingcloud/push/data/Style;

.field private final g:Ljava/util/List;
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
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/carousel/a$a$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/carousel/a$a$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/b;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/push/data/b;",
            "Lcom/salesforce/marketingcloud/push/data/c;",
            "Lcom/salesforce/marketingcloud/push/data/c;",
            "Lcom/salesforce/marketingcloud/push/data/Style;",
            "Ljava/util/List<",
            "+",
            "Lcom/salesforce/marketingcloud/push/data/a;",
            ">;)V"
        }
    .end annotation

    const-string v0, "identifier"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "media"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->b:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->c:Lcom/salesforce/marketingcloud/push/data/b;

    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->d:Lcom/salesforce/marketingcloud/push/data/c;

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->e:Lcom/salesforce/marketingcloud/push/data/c;

    .line 6
    iput-object p5, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->f:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 7
    iput-object p6, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->g:Ljava/util/List;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/b;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p8, p7, 0x4

    const/4 v0, 0x0

    if-eqz p8, :cond_0

    move-object p3, v0

    :cond_0
    and-int/lit8 p8, p7, 0x8

    if-eqz p8, :cond_1

    move-object p4, v0

    :cond_1
    and-int/lit8 p8, p7, 0x10

    if-eqz p8, :cond_2

    move-object p5, v0

    :cond_2
    and-int/lit8 p7, p7, 0x20

    if-eqz p7, :cond_3

    .line 8
    sget-object p6, Lcom/salesforce/marketingcloud/push/data/a$e;->d:Lcom/salesforce/marketingcloud/push/data/a$e;

    invoke-static {p6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p6

    .line 9
    :cond_3
    invoke-direct/range {p0 .. p6}, Lcom/salesforce/marketingcloud/push/carousel/a$a;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/b;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;)V

    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/push/carousel/a$a;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/b;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/carousel/a$a;
    .locals 0

    and-int/lit8 p8, p7, 0x1

    if-eqz p8, :cond_0

    .line 2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->b:Ljava/lang/String;

    :cond_0
    and-int/lit8 p8, p7, 0x2

    if-eqz p8, :cond_1

    iget-object p2, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->c:Lcom/salesforce/marketingcloud/push/data/b;

    :cond_1
    and-int/lit8 p8, p7, 0x4

    if-eqz p8, :cond_2

    iget-object p3, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->d:Lcom/salesforce/marketingcloud/push/data/c;

    :cond_2
    and-int/lit8 p8, p7, 0x8

    if-eqz p8, :cond_3

    iget-object p4, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->e:Lcom/salesforce/marketingcloud/push/data/c;

    :cond_3
    and-int/lit8 p8, p7, 0x10

    if-eqz p8, :cond_4

    iget-object p5, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->f:Lcom/salesforce/marketingcloud/push/data/Style;

    :cond_4
    and-int/lit8 p7, p7, 0x20

    if-eqz p7, :cond_5

    iget-object p6, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->g:Ljava/util/List;

    :cond_5
    move-object p7, p5

    move-object p8, p6

    move-object p5, p3

    move-object p6, p4

    move-object p3, p1

    move-object p4, p2

    move-object p2, p0

    invoke-virtual/range {p2 .. p8}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/b;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;)Lcom/salesforce/marketingcloud/push/carousel/a$a;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/b;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;)Lcom/salesforce/marketingcloud/push/carousel/a$a;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/push/data/b;",
            "Lcom/salesforce/marketingcloud/push/data/c;",
            "Lcom/salesforce/marketingcloud/push/data/c;",
            "Lcom/salesforce/marketingcloud/push/data/Style;",
            "Ljava/util/List<",
            "+",
            "Lcom/salesforce/marketingcloud/push/data/a;",
            ">;)",
            "Lcom/salesforce/marketingcloud/push/carousel/a$a;"
        }
    .end annotation

    .line 1
    const-string p0, "identifier"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "media"

    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Lcom/salesforce/marketingcloud/push/carousel/a$a;

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    move-object v5, p5

    move-object v6, p6

    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/push/carousel/a$a;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/b;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;)V

    return-object v0
.end method

.method public a()Lcom/salesforce/marketingcloud/push/data/Style;
    .locals 0

    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->f:Lcom/salesforce/marketingcloud/push/data/Style;

    return-object p0
.end method

.method public final d()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->b:Ljava/lang/String;

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
    instance-of v1, p1, Lcom/salesforce/marketingcloud/push/carousel/a$a;

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
    check-cast p1, Lcom/salesforce/marketingcloud/push/carousel/a$a;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->b:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/carousel/a$a;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->c:Lcom/salesforce/marketingcloud/push/data/b;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/carousel/a$a;->c:Lcom/salesforce/marketingcloud/push/data/b;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->d:Lcom/salesforce/marketingcloud/push/data/c;

    .line 36
    .line 37
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/carousel/a$a;->d:Lcom/salesforce/marketingcloud/push/data/c;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->e:Lcom/salesforce/marketingcloud/push/data/c;

    .line 47
    .line 48
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/carousel/a$a;->e:Lcom/salesforce/marketingcloud/push/data/c;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->f:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 58
    .line 59
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/carousel/a$a;->f:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->g:Ljava/util/List;

    .line 69
    .line 70
    iget-object p1, p1, Lcom/salesforce/marketingcloud/push/carousel/a$a;->g:Ljava/util/List;

    .line 71
    .line 72
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    if-nez p0, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
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
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->g:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->c:Lcom/salesforce/marketingcloud/push/data/b;

    .line 10
    .line 11
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/data/b;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->d:Lcom/salesforce/marketingcloud/push/data/c;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    move v0, v2

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/push/data/c;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    :goto_0
    add-int/2addr v1, v0

    .line 30
    mul-int/lit8 v1, v1, 0x1f

    .line 31
    .line 32
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->e:Lcom/salesforce/marketingcloud/push/data/c;

    .line 33
    .line 34
    if-nez v0, :cond_1

    .line 35
    .line 36
    move v0, v2

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/push/data/c;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    :goto_1
    add-int/2addr v1, v0

    .line 43
    mul-int/lit8 v1, v1, 0x1f

    .line 44
    .line 45
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->f:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 46
    .line 47
    if-nez v0, :cond_2

    .line 48
    .line 49
    move v0, v2

    .line 50
    goto :goto_2

    .line 51
    :cond_2
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    :goto_2
    add-int/2addr v1, v0

    .line 56
    mul-int/lit8 v1, v1, 0x1f

    .line 57
    .line 58
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->g:Ljava/util/List;

    .line 59
    .line 60
    if-nez p0, :cond_3

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    :goto_3
    add-int/2addr v1, v2

    .line 68
    return v1
.end method

.method public final j()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k()Lcom/salesforce/marketingcloud/push/data/b;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->c:Lcom/salesforce/marketingcloud/push/data/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l()Lcom/salesforce/marketingcloud/push/data/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->d:Lcom/salesforce/marketingcloud/push/data/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()Lcom/salesforce/marketingcloud/push/data/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->e:Lcom/salesforce/marketingcloud/push/data/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final n()Lcom/salesforce/marketingcloud/push/data/Style;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->f:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 2
    .line 3
    return-object p0
.end method

.method public final o()Ljava/util/List;
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
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->g:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final p()Lcom/salesforce/marketingcloud/push/data/b;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->c:Lcom/salesforce/marketingcloud/push/data/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final q()Lcom/salesforce/marketingcloud/push/data/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->e:Lcom/salesforce/marketingcloud/push/data/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final r()Lcom/salesforce/marketingcloud/push/data/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->d:Lcom/salesforce/marketingcloud/push/data/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final s()Lorg/json/JSONObject;
    .locals 3

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->b:Ljava/lang/String;

    .line 7
    .line 8
    const-string v2, "id"

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    sget-object v1, Lcom/salesforce/marketingcloud/push/data/b;->f:Lcom/salesforce/marketingcloud/push/data/b$a;

    .line 14
    .line 15
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->c:Lcom/salesforce/marketingcloud/push/data/b;

    .line 16
    .line 17
    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/push/data/b$a;->a(Lcom/salesforce/marketingcloud/push/data/b;)Lorg/json/JSONObject;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-string v2, "md"

    .line 22
    .line 23
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->d:Lcom/salesforce/marketingcloud/push/data/c;

    .line 27
    .line 28
    if-eqz v1, :cond_0

    .line 29
    .line 30
    sget-object v2, Lcom/salesforce/marketingcloud/push/data/c;->e:Lcom/salesforce/marketingcloud/push/data/c$a;

    .line 31
    .line 32
    invoke-virtual {v2, v1}, Lcom/salesforce/marketingcloud/push/data/c$a;->a(Lcom/salesforce/marketingcloud/push/data/c;)Lorg/json/JSONObject;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    const-string v2, "ti"

    .line 37
    .line 38
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 39
    .line 40
    .line 41
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->e:Lcom/salesforce/marketingcloud/push/data/c;

    .line 42
    .line 43
    if-eqz v1, :cond_1

    .line 44
    .line 45
    sget-object v2, Lcom/salesforce/marketingcloud/push/data/c;->e:Lcom/salesforce/marketingcloud/push/data/c$a;

    .line 46
    .line 47
    invoke-virtual {v2, v1}, Lcom/salesforce/marketingcloud/push/data/c$a;->a(Lcom/salesforce/marketingcloud/push/data/c;)Lorg/json/JSONObject;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    const-string v2, "sti"

    .line 52
    .line 53
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 54
    .line 55
    .line 56
    :cond_1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->a()Lcom/salesforce/marketingcloud/push/data/Style;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    if-eqz v1, :cond_2

    .line 61
    .line 62
    sget-object v2, Lcom/salesforce/marketingcloud/push/data/Style;->a:Lcom/salesforce/marketingcloud/push/data/Style$a;

    .line 63
    .line 64
    invoke-virtual {v2, v1}, Lcom/salesforce/marketingcloud/push/data/Style$a;->a(Lcom/salesforce/marketingcloud/push/data/Style;)Lorg/json/JSONObject;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    const-string v2, "s"

    .line 69
    .line 70
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 71
    .line 72
    .line 73
    :cond_2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->h()Ljava/util/List;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    if-eqz v1, :cond_4

    .line 78
    .line 79
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->h()Ljava/util/List;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    new-instance v1, Ljava/util/ArrayList;

    .line 84
    .line 85
    const/16 v2, 0xa

    .line 86
    .line 87
    invoke-static {p0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 88
    .line 89
    .line 90
    move-result v2

    .line 91
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 92
    .line 93
    .line 94
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    if-eqz v2, :cond_3

    .line 103
    .line 104
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    check-cast v2, Lcom/salesforce/marketingcloud/push/data/a;

    .line 109
    .line 110
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/push/data/a;->j()Lorg/json/JSONObject;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    goto :goto_0

    .line 118
    :cond_3
    new-instance p0, Lorg/json/JSONArray;

    .line 119
    .line 120
    invoke-direct {p0, v1}, Lorg/json/JSONArray;-><init>(Ljava/util/Collection;)V

    .line 121
    .line 122
    .line 123
    const-string v1, "ac"

    .line 124
    .line 125
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 126
    .line 127
    .line 128
    :cond_4
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 7

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->b:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->d:Lcom/salesforce/marketingcloud/push/data/c;

    .line 4
    .line 5
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->e:Lcom/salesforce/marketingcloud/push/data/c;

    .line 6
    .line 7
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->c:Lcom/salesforce/marketingcloud/push/data/b;

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->a()Lcom/salesforce/marketingcloud/push/data/Style;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->h()Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    new-instance v5, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    const-string v6, "CarouselItem(identifier="

    .line 20
    .line 21
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, ", title="

    .line 28
    .line 29
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", subTitle="

    .line 36
    .line 37
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v0, ", media="

    .line 44
    .line 45
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v0, ", style="

    .line 52
    .line 53
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v0, ", action="

    .line 60
    .line 61
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const-string p0, ")"

    .line 68
    .line 69
    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
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
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->b:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->c:Lcom/salesforce/marketingcloud/push/data/b;

    .line 12
    .line 13
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/push/data/b;->writeToParcel(Landroid/os/Parcel;I)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->d:Lcom/salesforce/marketingcloud/push/data/c;

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    const/4 v2, 0x0

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/push/data/c;->writeToParcel(Landroid/os/Parcel;I)V

    .line 30
    .line 31
    .line 32
    :goto_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->e:Lcom/salesforce/marketingcloud/push/data/c;

    .line 33
    .line 34
    if-nez v0, :cond_1

    .line 35
    .line 36
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/push/data/c;->writeToParcel(Landroid/os/Parcel;I)V

    .line 44
    .line 45
    .line 46
    :goto_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->f:Lcom/salesforce/marketingcloud/push/data/Style;

    .line 47
    .line 48
    invoke-virtual {p1, v0, p2}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/carousel/a$a;->g:Ljava/util/List;

    .line 52
    .line 53
    if-nez p0, :cond_2

    .line 54
    .line 55
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_2
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 60
    .line 61
    .line 62
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 67
    .line 68
    .line 69
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    if-eqz v0, :cond_3

    .line 78
    .line 79
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    check-cast v0, Landroid/os/Parcelable;

    .line 84
    .line 85
    invoke-virtual {p1, v0, p2}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 86
    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_3
    return-void
.end method
