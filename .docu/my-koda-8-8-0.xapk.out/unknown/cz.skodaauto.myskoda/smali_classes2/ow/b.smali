.class public abstract Low/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkw/e;


# static fields
.field public static final f:Lfv/b;


# instance fields
.field public final a:Lqw/e;

.field public final b:Low/c;

.field public final c:La2/e;

.field public final d:F

.field public final e:Landroid/graphics/RectF;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfv/b;

    .line 2
    .line 3
    const/16 v1, 0xd

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Low/b;->f:Lfv/b;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lqw/e;Low/c;La2/e;F)V
    .locals 1

    .line 1
    sget-object v0, Low/a;->d:Low/a;

    .line 2
    .line 3
    const-string v0, "valueFormatter"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Low/b;->a:Lqw/e;

    .line 12
    .line 13
    iput-object p2, p0, Low/b;->b:Low/c;

    .line 14
    .line 15
    iput-object p3, p0, Low/b;->c:La2/e;

    .line 16
    .line 17
    iput p4, p0, Low/b;->d:F

    .line 18
    .line 19
    new-instance p1, Landroid/graphics/RectF;

    .line 20
    .line 21
    invoke-direct {p1}, Landroid/graphics/RectF;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Low/b;->e:Landroid/graphics/RectF;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final a(Lkw/g;Lkw/i;Ljava/lang/Object;Ld3/a;)V
    .locals 0

    .line 1
    check-cast p3, Lmw/a;

    .line 2
    .line 3
    const-string p0, "horizontalDimensions"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "model"

    .line 9
    .line 10
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string p0, "insets"

    .line 14
    .line 15
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    sget-object p0, Low/a;->d:Low/a;

    .line 19
    .line 20
    return-void
.end method

.method public final b(Lkw/g;FLjava/lang/Object;Ld3/a;)V
    .locals 0

    .line 1
    check-cast p3, Lmw/a;

    .line 2
    .line 3
    const-string p0, "model"

    .line 4
    .line 5
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "insets"

    .line 9
    .line 10
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Low/b;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p1, Low/b;

    .line 8
    .line 9
    iget-object v0, p1, Low/b;->a:Lqw/e;

    .line 10
    .line 11
    iget-object v1, p0, Low/b;->a:Lqw/e;

    .line 12
    .line 13
    invoke-virtual {v1, v0}, Lqw/e;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    iget-object v0, p0, Low/b;->b:Low/c;

    .line 20
    .line 21
    iget-object v1, p1, Low/b;->b:Low/c;

    .line 22
    .line 23
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    sget-object v0, Low/a;->d:Low/a;

    .line 30
    .line 31
    iget-object v0, p0, Low/b;->c:La2/e;

    .line 32
    .line 33
    iget-object v1, p1, Low/b;->c:La2/e;

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    iget p0, p0, Low/b;->d:F

    .line 42
    .line 43
    iget p1, p1, Low/b;->d:F

    .line 44
    .line 45
    cmpg-float p0, p0, p1

    .line 46
    .line 47
    if-nez p0, :cond_0

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    const/4 p0, 0x0

    .line 51
    return p0

    .line 52
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 53
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Low/b;->a:Lqw/e;

    .line 2
    .line 3
    invoke-virtual {v0}, Lqw/e;->hashCode()I

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
    iget-object v2, p0, Low/b;->b:Low/c;

    .line 11
    .line 12
    invoke-virtual {v2}, Low/c;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    sget-object v0, Low/a;->d:Low/a;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v2

    .line 25
    mul-int/2addr v0, v1

    .line 26
    iget-object v2, p0, Low/b;->c:La2/e;

    .line 27
    .line 28
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    add-int/2addr v2, v0

    .line 33
    mul-int/2addr v2, v1

    .line 34
    iget p0, p0, Low/b;->d:F

    .line 35
    .line 36
    invoke-static {p0, v2, v1}, La7/g0;->c(FII)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0
.end method
