.class public final Lcom/salesforce/marketingcloud/push/data/Style$b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/push/data/Style;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/data/Style;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "b"
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/push/data/Style$b;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final b:Ljava/lang/String;

.field private final c:Ljava/lang/String;

.field private final d:Lcom/salesforce/marketingcloud/push/data/Style$Size;

.field private final e:Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

.field private final f:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

.field private g:Landroid/text/Spanned;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/Style$b$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/data/Style$b$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Style$b;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 9

    const/16 v7, 0x3f

    const/4 v8, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v0, p0

    .line 1
    invoke-direct/range {v0 .. v8}, Lcom/salesforce/marketingcloud/push/data/Style$b;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style$Size;Lcom/salesforce/marketingcloud/push/data/Style$Alignment;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;Landroid/text/Spanned;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style$Size;Lcom/salesforce/marketingcloud/push/data/Style$Alignment;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;Landroid/text/Spanned;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->b:Ljava/lang/String;

    .line 4
    iput-object p2, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->c:Ljava/lang/String;

    .line 5
    iput-object p3, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->d:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 6
    iput-object p4, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->e:Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    .line 7
    iput-object p5, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->f:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    .line 8
    iput-object p6, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->g:Landroid/text/Spanned;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style$Size;Lcom/salesforce/marketingcloud/push/data/Style$Alignment;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;Landroid/text/Spanned;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p8, p7, 0x1

    const/4 v0, 0x0

    if-eqz p8, :cond_0

    move-object p1, v0

    :cond_0
    and-int/lit8 p8, p7, 0x2

    if-eqz p8, :cond_1

    move-object p2, v0

    :cond_1
    and-int/lit8 p8, p7, 0x4

    if-eqz p8, :cond_2

    move-object p3, v0

    :cond_2
    and-int/lit8 p8, p7, 0x8

    if-eqz p8, :cond_3

    move-object p4, v0

    :cond_3
    and-int/lit8 p8, p7, 0x10

    if-eqz p8, :cond_4

    move-object p5, v0

    :cond_4
    and-int/lit8 p7, p7, 0x20

    if-eqz p7, :cond_5

    move-object p6, v0

    .line 9
    :cond_5
    invoke-direct/range {p0 .. p6}, Lcom/salesforce/marketingcloud/push/data/Style$b;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style$Size;Lcom/salesforce/marketingcloud/push/data/Style$Alignment;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;Landroid/text/Spanned;)V

    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/push/data/Style$b;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style$Size;Lcom/salesforce/marketingcloud/push/data/Style$Alignment;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;Landroid/text/Spanned;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/data/Style$b;
    .locals 0

    and-int/lit8 p8, p7, 0x1

    if-eqz p8, :cond_0

    .line 2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->b:Ljava/lang/String;

    :cond_0
    and-int/lit8 p8, p7, 0x2

    if-eqz p8, :cond_1

    iget-object p2, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->c:Ljava/lang/String;

    :cond_1
    and-int/lit8 p8, p7, 0x4

    if-eqz p8, :cond_2

    iget-object p3, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->d:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    :cond_2
    and-int/lit8 p8, p7, 0x8

    if-eqz p8, :cond_3

    iget-object p4, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->e:Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    :cond_3
    and-int/lit8 p8, p7, 0x10

    if-eqz p8, :cond_4

    iget-object p5, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->f:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    :cond_4
    and-int/lit8 p7, p7, 0x20

    if-eqz p7, :cond_5

    iget-object p6, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->g:Landroid/text/Spanned;

    :cond_5
    move-object p7, p5

    move-object p8, p6

    move-object p5, p3

    move-object p6, p4

    move-object p3, p1

    move-object p4, p2

    move-object p2, p0

    invoke-virtual/range {p2 .. p8}, Lcom/salesforce/marketingcloud/push/data/Style$b;->a(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style$Size;Lcom/salesforce/marketingcloud/push/data/Style$Alignment;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;Landroid/text/Spanned;)Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic p()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style$Size;Lcom/salesforce/marketingcloud/push/data/Style$Alignment;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;Landroid/text/Spanned;)Lcom/salesforce/marketingcloud/push/data/Style$b;
    .locals 0

    .line 1
    new-instance p0, Lcom/salesforce/marketingcloud/push/data/Style$b;

    invoke-direct/range {p0 .. p6}, Lcom/salesforce/marketingcloud/push/data/Style$b;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style$Size;Lcom/salesforce/marketingcloud/push/data/Style$Alignment;Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;Landroid/text/Spanned;)V

    return-object p0
.end method

.method public final a(Landroid/text/Spanned;)V
    .locals 0

    .line 3
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->g:Landroid/text/Spanned;

    return-void
.end method

.method public b()Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->f:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    .line 2
    .line 3
    return-object p0
.end method

.method public c()Lcom/salesforce/marketingcloud/push/data/Style$Size;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->d:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 2
    .line 3
    return-object p0
.end method

.method public e()Lcom/salesforce/marketingcloud/push/data/Style$Alignment;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->e:Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    .line 2
    .line 3
    return-object p0
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
    instance-of v1, p1, Lcom/salesforce/marketingcloud/push/data/Style$b;

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
    check-cast p1, Lcom/salesforce/marketingcloud/push/data/Style$b;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->b:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/data/Style$b;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->c:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/data/Style$b;->c:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->d:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 36
    .line 37
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/data/Style$b;->d:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->e:Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    .line 43
    .line 44
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/data/Style$b;->e:Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    .line 45
    .line 46
    if-eq v1, v3, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->f:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    .line 50
    .line 51
    iget-object v3, p1, Lcom/salesforce/marketingcloud/push/data/Style$b;->f:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    .line 52
    .line 53
    if-eq v1, v3, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->g:Landroid/text/Spanned;

    .line 57
    .line 58
    iget-object p1, p1, Lcom/salesforce/marketingcloud/push/data/Style$b;->g:Landroid/text/Spanned;

    .line 59
    .line 60
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    if-nez p0, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    return v0
.end method

.method public g()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->b:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    :goto_0
    mul-int/lit8 v0, v0, 0x1f

    .line 13
    .line 14
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->c:Ljava/lang/String;

    .line 15
    .line 16
    if-nez v2, :cond_1

    .line 17
    .line 18
    move v2, v1

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    :goto_1
    add-int/2addr v0, v2

    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->d:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 28
    .line 29
    if-nez v2, :cond_2

    .line 30
    .line 31
    move v2, v1

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    :goto_2
    add-int/2addr v0, v2

    .line 38
    mul-int/lit8 v0, v0, 0x1f

    .line 39
    .line 40
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->e:Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    .line 41
    .line 42
    if-nez v2, :cond_3

    .line 43
    .line 44
    move v2, v1

    .line 45
    goto :goto_3

    .line 46
    :cond_3
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    :goto_3
    add-int/2addr v0, v2

    .line 51
    mul-int/lit8 v0, v0, 0x1f

    .line 52
    .line 53
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->f:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    .line 54
    .line 55
    if-nez v2, :cond_4

    .line 56
    .line 57
    move v2, v1

    .line 58
    goto :goto_4

    .line 59
    :cond_4
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    :goto_4
    add-int/2addr v0, v2

    .line 64
    mul-int/lit8 v0, v0, 0x1f

    .line 65
    .line 66
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->g:Landroid/text/Spanned;

    .line 67
    .line 68
    if-nez p0, :cond_5

    .line 69
    .line 70
    goto :goto_5

    .line 71
    :cond_5
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    :goto_5
    add-int/2addr v0, v1

    .line 76
    return v0
.end method

.method public i()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->c:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final j()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->c:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k()Lcom/salesforce/marketingcloud/push/data/Style$Size;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->d:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l()Lcom/salesforce/marketingcloud/push/data/Style$Alignment;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->e:Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->f:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    .line 2
    .line 3
    return-object p0
.end method

.method public final n()Landroid/text/Spanned;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->g:Landroid/text/Spanned;

    .line 2
    .line 3
    return-object p0
.end method

.method public final o()Landroid/text/Spanned;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->g:Landroid/text/Spanned;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 8

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->b:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->c:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->d:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 6
    .line 7
    iget-object v3, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->e:Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    .line 8
    .line 9
    iget-object v4, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->f:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    .line 10
    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->g:Landroid/text/Spanned;

    .line 12
    .line 13
    const-string v5, ", backgroundColor="

    .line 14
    .line 15
    const-string v6, ", fontSize="

    .line 16
    .line 17
    const-string v7, "StyleImpl(fontColor="

    .line 18
    .line 19
    invoke-static {v7, v0, v5, v1, v6}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    const-string v1, ", alignment="

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string v1, ", fontStyle="

    .line 35
    .line 36
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v1, ", span="

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string p0, ")"

    .line 51
    .line 52
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    const-string p2, "out"

    .line 2
    .line 3
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p2, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->b:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p2, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->c:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object p2, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->d:Lcom/salesforce/marketingcloud/push/data/Style$Size;

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    const/4 v1, 0x0

    .line 20
    if-nez p2, :cond_0

    .line 21
    .line 22
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    :goto_0
    iget-object p2, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->e:Lcom/salesforce/marketingcloud/push/data/Style$Alignment;

    .line 37
    .line 38
    if-nez p2, :cond_1

    .line 39
    .line 40
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p2

    .line 51
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :goto_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Style$b;->f:Lcom/salesforce/marketingcloud/push/data/Style$FontStyle;

    .line 55
    .line 56
    if-nez p0, :cond_2

    .line 57
    .line 58
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    :cond_2
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    return-void
.end method
