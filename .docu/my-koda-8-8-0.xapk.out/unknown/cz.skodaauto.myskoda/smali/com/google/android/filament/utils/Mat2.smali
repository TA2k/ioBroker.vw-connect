.class public final Lcom/google/android/filament/utils/Mat2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/Mat2$Companion;,
        Lcom/google/android/filament/utils/Mat2$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000F\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0010\u0008\n\u0002\u0008\u0004\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u000f\n\u0002\u0010\u000b\n\u0002\u0008\u0006\n\u0002\u0010\u0014\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0013\u0008\u0086\u0008\u0018\u0000 A2\u00020\u0001:\u0001AB\u001b\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0005\u0010\u0006B\u0011\u0008\u0016\u0012\u0006\u0010\u0007\u001a\u00020\u0000\u00a2\u0006\u0004\u0008\u0005\u0010\u0008J\u0018\u0010\u000b\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\tH\u0086\u0002\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ \u0010\u000b\u001a\u00020\u000e2\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\r\u001a\u00020\tH\u0086\u0002\u00a2\u0006\u0004\u0008\u000b\u0010\u000fJ\u0018\u0010\u000b\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\u0010H\u0086\u0002\u00a2\u0006\u0004\u0008\u000b\u0010\u0011J \u0010\u000b\u001a\u00020\u000e2\u0006\u0010\n\u001a\u00020\u00102\u0006\u0010\r\u001a\u00020\tH\u0086\u0002\u00a2\u0006\u0004\u0008\u000b\u0010\u0012J \u0010\u0013\u001a\u00020\u000e2\u0006\u0010\r\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\tH\u0086\u0002\u00a2\u0006\u0004\u0008\u0013\u0010\u000fJ(\u0010\u0013\u001a\u00020\u00152\u0006\u0010\r\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\u0014\u001a\u00020\u000eH\u0086\u0002\u00a2\u0006\u0004\u0008\u0013\u0010\u0016J \u0010\u0017\u001a\u00020\u00152\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\u0014\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J(\u0010\u0017\u001a\u00020\u00152\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\r\u001a\u00020\t2\u0006\u0010\u0014\u001a\u00020\u000eH\u0086\u0002\u00a2\u0006\u0004\u0008\u0017\u0010\u0016J\u0010\u0010\u0019\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008\u0019\u0010\u001aJ\u0010\u0010\u001b\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008\u001b\u0010\u001aJ\u0010\u0010\u001c\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008\u001c\u0010\u001aJ\u0018\u0010\u001d\u001a\u00020\u00002\u0006\u0010\u0014\u001a\u00020\u000eH\u0086\u0002\u00a2\u0006\u0004\u0008\u001d\u0010\u001eJ\u0018\u0010\u001f\u001a\u00020\u00002\u0006\u0010\u0014\u001a\u00020\u000eH\u0086\u0002\u00a2\u0006\u0004\u0008\u001f\u0010\u001eJ\u0018\u0010 \u001a\u00020\u00002\u0006\u0010\u0014\u001a\u00020\u000eH\u0086\u0002\u00a2\u0006\u0004\u0008 \u0010\u001eJ\u0018\u0010!\u001a\u00020\u00002\u0006\u0010\u0014\u001a\u00020\u000eH\u0086\u0002\u00a2\u0006\u0004\u0008!\u0010\u001eJ\"\u0010#\u001a\u00020\u00002\u0006\u0010\u0014\u001a\u00020\u000e2\u0008\u0008\u0002\u0010\"\u001a\u00020\u000eH\u0086\u0008\u00a2\u0006\u0004\u0008#\u0010$J\"\u0010&\u001a\u00020%2\u0006\u0010\u0014\u001a\u00020\u000e2\u0008\u0008\u0002\u0010\"\u001a\u00020\u000eH\u0086\u0008\u00a2\u0006\u0004\u0008&\u0010\'J\u0018\u0010 \u001a\u00020\u00002\u0006\u0010\u0007\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008 \u0010(J\"\u0010#\u001a\u00020\u00002\u0006\u0010\u0007\u001a\u00020\u00002\u0008\u0008\u0002\u0010\"\u001a\u00020\u000eH\u0086\u0008\u00a2\u0006\u0004\u0008#\u0010)J\"\u0010&\u001a\u00020%2\u0006\u0010\u0007\u001a\u00020\u00002\u0008\u0008\u0002\u0010\"\u001a\u00020\u000eH\u0086\u0008\u00a2\u0006\u0004\u0008&\u0010*J\u0018\u0010 \u001a\u00020\u00022\u0006\u0010\u0014\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008 \u0010+J\r\u0010-\u001a\u00020,\u00a2\u0006\u0004\u0008-\u0010.J\u000f\u00100\u001a\u00020/H\u0016\u00a2\u0006\u0004\u00080\u00101J\u0010\u00102\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u00082\u00103J\u0010\u00104\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u00084\u00103J$\u00105\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0002H\u00c6\u0001\u00a2\u0006\u0004\u00085\u00106J\u0010\u00107\u001a\u00020\tH\u00d6\u0001\u00a2\u0006\u0004\u00087\u00108J\u001a\u0010&\u001a\u00020%2\u0008\u00109\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003\u00a2\u0006\u0004\u0008&\u0010:R\"\u0010\u0003\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0003\u0010;\u001a\u0004\u0008<\u00103\"\u0004\u0008=\u0010>R\"\u0010\u0004\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0004\u0010;\u001a\u0004\u0008?\u00103\"\u0004\u0008@\u0010>\u00a8\u0006B"
    }
    d2 = {
        "Lcom/google/android/filament/utils/Mat2;",
        "",
        "Lcom/google/android/filament/utils/Float2;",
        "x",
        "y",
        "<init>",
        "(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V",
        "m",
        "(Lcom/google/android/filament/utils/Mat2;)V",
        "",
        "column",
        "get",
        "(I)Lcom/google/android/filament/utils/Float2;",
        "row",
        "",
        "(II)F",
        "Lcom/google/android/filament/utils/MatrixColumn;",
        "(Lcom/google/android/filament/utils/MatrixColumn;)Lcom/google/android/filament/utils/Float2;",
        "(Lcom/google/android/filament/utils/MatrixColumn;I)F",
        "invoke",
        "v",
        "Llx0/b0;",
        "(IIF)V",
        "set",
        "(ILcom/google/android/filament/utils/Float2;)V",
        "unaryMinus",
        "()Lcom/google/android/filament/utils/Mat2;",
        "inc",
        "dec",
        "plus",
        "(F)Lcom/google/android/filament/utils/Mat2;",
        "minus",
        "times",
        "div",
        "delta",
        "compareTo",
        "(FF)Lcom/google/android/filament/utils/Mat2;",
        "",
        "equals",
        "(FF)Z",
        "(Lcom/google/android/filament/utils/Mat2;)Lcom/google/android/filament/utils/Mat2;",
        "(Lcom/google/android/filament/utils/Mat2;F)Lcom/google/android/filament/utils/Mat2;",
        "(Lcom/google/android/filament/utils/Mat2;F)Z",
        "(Lcom/google/android/filament/utils/Float2;)Lcom/google/android/filament/utils/Float2;",
        "",
        "toFloatArray",
        "()[F",
        "",
        "toString",
        "()Ljava/lang/String;",
        "component1",
        "()Lcom/google/android/filament/utils/Float2;",
        "component2",
        "copy",
        "(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)Lcom/google/android/filament/utils/Mat2;",
        "hashCode",
        "()I",
        "other",
        "(Ljava/lang/Object;)Z",
        "Lcom/google/android/filament/utils/Float2;",
        "getX",
        "setX",
        "(Lcom/google/android/filament/utils/Float2;)V",
        "getY",
        "setY",
        "Companion",
        "filament-utils-android_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final Companion:Lcom/google/android/filament/utils/Mat2$Companion;


# instance fields
.field private x:Lcom/google/android/filament/utils/Float2;

.field private y:Lcom/google/android/filament/utils/Float2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat2$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/google/android/filament/utils/Mat2$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/android/filament/utils/Mat2;->Companion:Lcom/google/android/filament/utils/Mat2$Companion;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    const/4 v1, 0x3

    invoke-direct {p0, v0, v0, v1, v0}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V
    .locals 1

    const-string v0, "x"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "y"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 4
    iput-object p2, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    return-void
.end method

.method public synthetic constructor <init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;ILkotlin/jvm/internal/g;)V
    .locals 4

    and-int/lit8 p4, p3, 0x1

    const/4 v0, 0x0

    const/4 v1, 0x2

    const/4 v2, 0x0

    const/high16 v3, 0x3f800000    # 1.0f

    if-eqz p4, :cond_0

    .line 5
    new-instance p1, Lcom/google/android/filament/utils/Float2;

    invoke-direct {p1, v3, v2, v1, v0}, Lcom/google/android/filament/utils/Float2;-><init>(FFILkotlin/jvm/internal/g;)V

    :cond_0
    and-int/2addr p3, v1

    if-eqz p3, :cond_1

    .line 6
    new-instance p2, Lcom/google/android/filament/utils/Float2;

    const/4 p3, 0x1

    invoke-direct {p2, v2, v3, p3, v0}, Lcom/google/android/filament/utils/Float2;-><init>(FFILkotlin/jvm/internal/g;)V

    .line 7
    :cond_1
    invoke-direct {p0, p1, p2}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/utils/Mat2;)V
    .locals 4

    const-string v0, "m"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    iget-object v0, p1, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    const/4 v1, 0x0

    const/4 v2, 0x3

    const/4 v3, 0x0

    invoke-static {v0, v1, v1, v2, v3}, Lcom/google/android/filament/utils/Float2;->copy$default(Lcom/google/android/filament/utils/Float2;FFILjava/lang/Object;)Lcom/google/android/filament/utils/Float2;

    move-result-object v0

    iget-object p1, p1, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    invoke-static {p1, v1, v1, v2, v3}, Lcom/google/android/filament/utils/Float2;->copy$default(Lcom/google/android/filament/utils/Float2;FFILjava/lang/Object;)Lcom/google/android/filament/utils/Float2;

    move-result-object p1

    invoke-direct {p0, v0, p1}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    return-void
.end method

.method public static synthetic compareTo$default(Lcom/google/android/filament/utils/Mat2;FFILjava/lang/Object;)Lcom/google/android/filament/utils/Mat2;
    .locals 4

    and-int/lit8 p3, p3, 0x2

    const/4 p4, 0x0

    if-eqz p3, :cond_0

    move p2, p4

    .line 1
    :cond_0
    new-instance p3, Lcom/google/android/filament/utils/Mat2;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getX()Lcom/google/android/filament/utils/Float2;

    move-result-object v0

    .line 3
    new-instance v1, Lcom/google/android/filament/utils/Float2;

    .line 4
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v2

    sub-float v3, v2, p1

    .line 5
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float v3, v3, p2

    if-gez v3, :cond_1

    move v2, p4

    goto :goto_0

    .line 6
    :cond_1
    invoke-static {v2, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v2

    int-to-float v2, v2

    .line 7
    :goto_0
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v0

    sub-float v3, v0, p1

    .line 8
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float v3, v3, p2

    if-gez v3, :cond_2

    move v0, p4

    goto :goto_1

    .line 9
    :cond_2
    invoke-static {v0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 10
    :goto_1
    invoke-direct {v1, v2, v0}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getY()Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    .line 12
    new-instance v0, Lcom/google/android/filament/utils/Float2;

    .line 13
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v2

    sub-float v3, v2, p1

    .line 14
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float v3, v3, p2

    if-gez v3, :cond_3

    move v2, p4

    goto :goto_2

    .line 15
    :cond_3
    invoke-static {v2, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v2

    int-to-float v2, v2

    .line 16
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p0

    sub-float v3, p0, p1

    .line 17
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float p2, v3, p2

    if-gez p2, :cond_4

    goto :goto_3

    .line 18
    :cond_4
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float p4, p0

    .line 19
    :goto_3
    invoke-direct {v0, v2, p4}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 20
    invoke-direct {p3, v1, v0}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    return-object p3
.end method

.method public static synthetic compareTo$default(Lcom/google/android/filament/utils/Mat2;Lcom/google/android/filament/utils/Mat2;FILjava/lang/Object;)Lcom/google/android/filament/utils/Mat2;
    .locals 6

    and-int/lit8 p3, p3, 0x2

    const/4 p4, 0x0

    if-eqz p3, :cond_0

    move p2, p4

    .line 21
    :cond_0
    const-string p3, "m"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p3, Lcom/google/android/filament/utils/Mat2;

    .line 22
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getX()Lcom/google/android/filament/utils/Float2;

    move-result-object v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat2;->getX()Lcom/google/android/filament/utils/Float2;

    move-result-object v1

    .line 23
    new-instance v2, Lcom/google/android/filament/utils/Float2;

    .line 24
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v3

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v4

    sub-float v5, v3, v4

    .line 25
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_1

    move v3, p4

    goto :goto_0

    .line 26
    :cond_1
    invoke-static {v3, v4}, Ljava/lang/Float;->compare(FF)I

    move-result v3

    int-to-float v3, v3

    .line 27
    :goto_0
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v0

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v1

    sub-float v4, v0, v1

    .line 28
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_2

    move v0, p4

    goto :goto_1

    .line 29
    :cond_2
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 30
    :goto_1
    invoke-direct {v2, v3, v0}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 31
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getY()Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat2;->getY()Lcom/google/android/filament/utils/Float2;

    move-result-object p1

    .line 32
    new-instance v0, Lcom/google/android/filament/utils/Float2;

    .line 33
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v3

    sub-float v4, v1, v3

    .line 34
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_3

    move v1, p4

    goto :goto_2

    .line 35
    :cond_3
    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 36
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p1

    sub-float v3, p0, p1

    .line 37
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float p2, v3, p2

    if-gez p2, :cond_4

    goto :goto_3

    .line 38
    :cond_4
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float p4, p0

    .line 39
    :goto_3
    invoke-direct {v0, v1, p4}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 40
    invoke-direct {p3, v2, v0}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    return-object p3
.end method

.method public static synthetic copy$default(Lcom/google/android/filament/utils/Mat2;Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;ILjava/lang/Object;)Lcom/google/android/filament/utils/Mat2;
    .locals 0

    .line 1
    and-int/lit8 p4, p3, 0x1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2}, Lcom/google/android/filament/utils/Mat2;->copy(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)Lcom/google/android/filament/utils/Mat2;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static synthetic equals$default(Lcom/google/android/filament/utils/Mat2;FFILjava/lang/Object;)Z
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 1
    :cond_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getX()Lcom/google/android/filament/utils/Float2;

    move-result-object p3

    .line 2
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result p4

    sub-float/2addr p4, p1

    .line 3
    invoke-static {p4}, Ljava/lang/Math;->abs(F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 4
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p3

    sub-float/2addr p3, p1

    .line 5
    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getY()Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result p3

    sub-float/2addr p3, p1

    .line 8
    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 9
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p0

    sub-float/2addr p0, p1

    .line 10
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_1

    const/4 p0, 0x1

    return p0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method

.method public static synthetic equals$default(Lcom/google/android/filament/utils/Mat2;Lcom/google/android/filament/utils/Mat2;FILjava/lang/Object;)Z
    .locals 2

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 11
    :cond_0
    const-string p3, "m"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getX()Lcom/google/android/filament/utils/Float2;

    move-result-object p3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat2;->getX()Lcom/google/android/filament/utils/Float2;

    move-result-object p4

    .line 12
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v0

    invoke-virtual {p4}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v1

    sub-float/2addr v0, v1

    .line 13
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 14
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p3

    invoke-virtual {p4}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p4

    sub-float/2addr p3, p4

    .line 15
    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 16
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getY()Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat2;->getY()Lcom/google/android/filament/utils/Float2;

    move-result-object p1

    .line 17
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result p3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result p4

    sub-float/2addr p3, p4

    .line 18
    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 19
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p1

    sub-float/2addr p0, p1

    .line 20
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_1

    const/4 p0, 0x1

    return p0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method


# virtual methods
.method public final compareTo(FF)Lcom/google/android/filament/utils/Mat2;
    .locals 6

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat2;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getX()Lcom/google/android/filament/utils/Float2;

    move-result-object v1

    .line 3
    new-instance v2, Lcom/google/android/filament/utils/Float2;

    .line 4
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v3

    sub-float v4, v3, p1

    .line 5
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    const/4 v5, 0x0

    if-gez v4, :cond_0

    move v3, v5

    goto :goto_0

    .line 6
    :cond_0
    invoke-static {v3, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v3

    int-to-float v3, v3

    .line 7
    :goto_0
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v1

    sub-float v4, v1, p1

    .line 8
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_1

    move v1, v5

    goto :goto_1

    .line 9
    :cond_1
    invoke-static {v1, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 10
    :goto_1
    invoke-direct {v2, v3, v1}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getY()Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    .line 12
    new-instance v1, Lcom/google/android/filament/utils/Float2;

    .line 13
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v3

    sub-float v4, v3, p1

    .line 14
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_2

    move v3, v5

    goto :goto_2

    .line 15
    :cond_2
    invoke-static {v3, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v3

    int-to-float v3, v3

    .line 16
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p0

    sub-float v4, p0, p1

    .line 17
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float p2, v4, p2

    if-gez p2, :cond_3

    goto :goto_3

    .line 18
    :cond_3
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float v5, p0

    .line 19
    :goto_3
    invoke-direct {v1, v3, v5}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 20
    invoke-direct {v0, v2, v1}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    return-object v0
.end method

.method public final compareTo(Lcom/google/android/filament/utils/Mat2;F)Lcom/google/android/filament/utils/Mat2;
    .locals 8

    const-string v0, "m"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    new-instance v0, Lcom/google/android/filament/utils/Mat2;

    .line 22
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getX()Lcom/google/android/filament/utils/Float2;

    move-result-object v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat2;->getX()Lcom/google/android/filament/utils/Float2;

    move-result-object v2

    .line 23
    new-instance v3, Lcom/google/android/filament/utils/Float2;

    .line 24
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v4

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v5

    sub-float v6, v4, v5

    .line 25
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    const/4 v7, 0x0

    if-gez v6, :cond_0

    move v4, v7

    goto :goto_0

    .line 26
    :cond_0
    invoke-static {v4, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 27
    :goto_0
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v1

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v2

    sub-float v5, v1, v2

    .line 28
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_1

    move v1, v7

    goto :goto_1

    .line 29
    :cond_1
    invoke-static {v1, v2}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 30
    :goto_1
    invoke-direct {v3, v4, v1}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 31
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getY()Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat2;->getY()Lcom/google/android/filament/utils/Float2;

    move-result-object p1

    .line 32
    new-instance v1, Lcom/google/android/filament/utils/Float2;

    .line 33
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v2

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v4

    sub-float v5, v2, v4

    .line 34
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_2

    move v2, v7

    goto :goto_2

    .line 35
    :cond_2
    invoke-static {v2, v4}, Ljava/lang/Float;->compare(FF)I

    move-result v2

    int-to-float v2, v2

    .line 36
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p1

    sub-float v4, p0, p1

    .line 37
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float p2, v4, p2

    if-gez p2, :cond_3

    goto :goto_3

    .line 38
    :cond_3
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float v7, p0

    .line 39
    :goto_3
    invoke-direct {v1, v2, v7}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 40
    invoke-direct {v0, v3, v1}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    return-object v0
.end method

.method public final component1()Lcom/google/android/filament/utils/Float2;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Lcom/google/android/filament/utils/Float2;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)Lcom/google/android/filament/utils/Mat2;
    .locals 0

    .line 1
    const-string p0, "x"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "y"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lcom/google/android/filament/utils/Mat2;

    .line 12
    .line 13
    invoke-direct {p0, p1, p2}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    .line 14
    .line 15
    .line 16
    return-object p0
.end method

.method public final dec()Lcom/google/android/filament/utils/Mat2;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat2;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->dec()Lcom/google/android/filament/utils/Float2;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iput-object v2, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 10
    .line 11
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 12
    .line 13
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float2;->dec()Lcom/google/android/filament/utils/Float2;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    iput-object v3, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 18
    .line 19
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public final div(F)Lcom/google/android/filament/utils/Mat2;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat2;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 4
    .line 5
    new-instance v2, Lcom/google/android/filament/utils/Float2;

    .line 6
    .line 7
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    div-float/2addr v3, p1

    .line 12
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    div-float/2addr v1, p1

    .line 17
    invoke-direct {v2, v3, v1}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 21
    .line 22
    new-instance v1, Lcom/google/android/filament/utils/Float2;

    .line 23
    .line 24
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    div-float/2addr v3, p1

    .line 29
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    div-float/2addr p0, p1

    .line 34
    invoke-direct {v1, v3, p0}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 35
    .line 36
    .line 37
    invoke-direct {v0, v2, v1}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    .line 38
    .line 39
    .line 40
    return-object v0
.end method

.method public final equals(FF)Z
    .locals 2

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getX()Lcom/google/android/filament/utils/Float2;

    move-result-object v0

    .line 3
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v1

    sub-float/2addr v1, p1

    .line 4
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 5
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v0

    sub-float/2addr v0, p1

    .line 6
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getY()Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    .line 8
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v0

    sub-float/2addr v0, p1

    .line 9
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 10
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p0

    sub-float/2addr p0, p1

    .line 11
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public final equals(Lcom/google/android/filament/utils/Mat2;F)Z
    .locals 4

    const-string v0, "m"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getX()Lcom/google/android/filament/utils/Float2;

    move-result-object v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat2;->getX()Lcom/google/android/filament/utils/Float2;

    move-result-object v1

    .line 13
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v2

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v3

    sub-float/2addr v2, v3

    .line 14
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 15
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v0

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v1

    sub-float/2addr v0, v1

    .line 16
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 17
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat2;->getY()Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat2;->getY()Lcom/google/android/filament/utils/Float2;

    move-result-object p1

    .line 18
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v1

    sub-float/2addr v0, v1

    .line 19
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 20
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p1

    sub-float/2addr p0, p1

    .line 21
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Lcom/google/android/filament/utils/Mat2;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Lcom/google/android/filament/utils/Mat2;

    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    iget-object v3, p1, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2

    return v2

    :cond_2
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    iget-object p1, p1, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    if-nez p0, :cond_3

    return v2

    :cond_3
    return v0
.end method

.method public final get(II)F
    .locals 0

    .line 4
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat2;->get(I)Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Float2;->get(I)F

    move-result p0

    return p0
.end method

.method public final get(Lcom/google/android/filament/utils/MatrixColumn;I)F
    .locals 1

    const-string v0, "column"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat2;->get(Lcom/google/android/filament/utils/MatrixColumn;)Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Float2;->get(I)F

    move-result p0

    return p0
.end method

.method public final get(I)Lcom/google/android/filament/utils/Float2;
    .locals 1

    if-eqz p1, :cond_1

    const/4 v0, 0x1

    if-ne p1, v0, :cond_0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    return-object p0

    .line 2
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "column must be in 0..1"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 3
    :cond_1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    return-object p0
.end method

.method public final get(Lcom/google/android/filament/utils/MatrixColumn;)Lcom/google/android/filament/utils/Float2;
    .locals 1

    const-string v0, "column"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    sget-object v0, Lcom/google/android/filament/utils/Mat2$WhenMappings;->$EnumSwitchMapping$0:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p1, v0, p1

    const/4 v0, 0x1

    if-eq p1, v0, :cond_1

    const/4 v0, 0x2

    if-ne p1, v0, :cond_0

    .line 6
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    return-object p0

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "column must be X or Y"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 8
    :cond_1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    return-object p0
.end method

.method public final getX()Lcom/google/android/filament/utils/Float2;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getY()Lcom/google/android/filament/utils/Float2;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public final inc()Lcom/google/android/filament/utils/Mat2;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat2;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->inc()Lcom/google/android/filament/utils/Float2;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iput-object v2, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 10
    .line 11
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 12
    .line 13
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float2;->inc()Lcom/google/android/filament/utils/Float2;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    iput-object v3, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 18
    .line 19
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public final invoke(II)F
    .locals 0

    add-int/lit8 p2, p2, -0x1

    .line 1
    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Mat2;->get(I)Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    add-int/lit8 p1, p1, -0x1

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float2;->get(I)F

    move-result p0

    return p0
.end method

.method public final invoke(IIF)V
    .locals 0

    add-int/lit8 p2, p2, -0x1

    add-int/lit8 p1, p1, -0x1

    .line 2
    invoke-virtual {p0, p2, p1, p3}, Lcom/google/android/filament/utils/Mat2;->set(IIF)V

    return-void
.end method

.method public final minus(F)Lcom/google/android/filament/utils/Mat2;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat2;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 4
    .line 5
    new-instance v2, Lcom/google/android/filament/utils/Float2;

    .line 6
    .line 7
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    sub-float/2addr v3, p1

    .line 12
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    sub-float/2addr v1, p1

    .line 17
    invoke-direct {v2, v3, v1}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 21
    .line 22
    new-instance v1, Lcom/google/android/filament/utils/Float2;

    .line 23
    .line 24
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    sub-float/2addr v3, p1

    .line 29
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    sub-float/2addr p0, p1

    .line 34
    invoke-direct {v1, v3, p0}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 35
    .line 36
    .line 37
    invoke-direct {v0, v2, v1}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    .line 38
    .line 39
    .line 40
    return-object v0
.end method

.method public final plus(F)Lcom/google/android/filament/utils/Mat2;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat2;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 4
    .line 5
    new-instance v2, Lcom/google/android/filament/utils/Float2;

    .line 6
    .line 7
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    add-float/2addr v3, p1

    .line 12
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    add-float/2addr v1, p1

    .line 17
    invoke-direct {v2, v3, v1}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 21
    .line 22
    new-instance v1, Lcom/google/android/filament/utils/Float2;

    .line 23
    .line 24
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    add-float/2addr v3, p1

    .line 29
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    add-float/2addr p0, p1

    .line 34
    invoke-direct {v1, v3, p0}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 35
    .line 36
    .line 37
    invoke-direct {v0, v2, v1}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    .line 38
    .line 39
    .line 40
    return-object v0
.end method

.method public final set(IIF)V
    .locals 0

    .line 4
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat2;->get(I)Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    invoke-virtual {p0, p2, p3}, Lcom/google/android/filament/utils/Float2;->set(IF)V

    return-void
.end method

.method public final set(ILcom/google/android/filament/utils/Float2;)V
    .locals 1

    const-string v0, "v"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat2;->get(I)Lcom/google/android/filament/utils/Float2;

    move-result-object p0

    .line 2
    invoke-virtual {p2}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result p1

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float2;->setX(F)V

    .line 3
    invoke-virtual {p2}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p1

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float2;->setY(F)V

    return-void
.end method

.method public final setX(Lcom/google/android/filament/utils/Float2;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 7
    .line 8
    return-void
.end method

.method public final setY(Lcom/google/android/filament/utils/Float2;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 7
    .line 8
    return-void
.end method

.method public final times(Lcom/google/android/filament/utils/Float2;)Lcom/google/android/filament/utils/Float2;
    .locals 4

    const-string v0, "v"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    new-instance v0, Lcom/google/android/filament/utils/Float2;

    .line 17
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v2

    mul-float/2addr v2, v1

    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v3

    mul-float/2addr v3, v1

    add-float/2addr v3, v2

    .line 18
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v2

    mul-float/2addr v2, v1

    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p1

    mul-float/2addr p1, p0

    add-float/2addr p1, v2

    .line 19
    invoke-direct {v0, v3, p1}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    return-object v0
.end method

.method public final times(F)Lcom/google/android/filament/utils/Mat2;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat2;

    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 2
    new-instance v2, Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v3

    mul-float/2addr v3, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v1

    mul-float/2addr v1, p1

    invoke-direct {v2, v3, v1}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 3
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 4
    new-instance v1, Lcom/google/android/filament/utils/Float2;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v3

    mul-float/2addr v3, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p0

    mul-float/2addr p0, p1

    invoke-direct {v1, v3, p0}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 5
    invoke-direct {v0, v2, v1}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    return-object v0
.end method

.method public final times(Lcom/google/android/filament/utils/Mat2;)Lcom/google/android/filament/utils/Mat2;
    .locals 6

    const-string v0, "m"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    new-instance v0, Lcom/google/android/filament/utils/Mat2;

    .line 7
    new-instance v1, Lcom/google/android/filament/utils/Float2;

    .line 8
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v2

    iget-object v3, p1, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v3

    mul-float/2addr v3, v2

    iget-object v2, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v2

    iget-object v4, p1, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v4

    mul-float/2addr v4, v2

    add-float/2addr v4, v3

    .line 9
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v2

    iget-object v3, p1, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v3

    mul-float/2addr v3, v2

    iget-object v2, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v2

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v5

    mul-float/2addr v5, v2

    add-float/2addr v5, v3

    .line 10
    invoke-direct {v1, v4, v5}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 11
    new-instance v2, Lcom/google/android/filament/utils/Float2;

    .line 12
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v3

    iget-object v4, p1, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v4

    mul-float/2addr v4, v3

    iget-object v3, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v3

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v5

    mul-float/2addr v5, v3

    add-float/2addr v5, v4

    .line 13
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result v3

    iget-object v4, p1, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float2;->getX()F

    move-result v4

    mul-float/2addr v4, v3

    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p0

    iget-object p1, p1, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float2;->getY()F

    move-result p1

    mul-float/2addr p1, p0

    add-float/2addr p1, v4

    .line 14
    invoke-direct {v2, v5, p1}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 15
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    return-object v0
.end method

.method public final toFloatArray()[F
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 8
    .line 9
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 14
    .line 15
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 20
    .line 21
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    const/4 v3, 0x4

    .line 26
    new-array v3, v3, [F

    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    aput v0, v3, v4

    .line 30
    .line 31
    const/4 v0, 0x1

    .line 32
    aput v1, v3, v0

    .line 33
    .line 34
    const/4 v0, 0x2

    .line 35
    aput v2, v3, v0

    .line 36
    .line 37
    const/4 v0, 0x3

    .line 38
    aput p0, v3, v0

    .line 39
    .line 40
    return-object v3
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 8
    .line 9
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->getX()F

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 14
    .line 15
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 20
    .line 21
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->getY()F

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    new-instance v3, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string v4, "\n            |"

    .line 28
    .line 29
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, " "

    .line 36
    .line 37
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, "|\n            |"

    .line 44
    .line 45
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string p0, "|\n            "

    .line 58
    .line 59
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-static {p0}, Lly0/q;->g(Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0
.end method

.method public final unaryMinus()Lcom/google/android/filament/utils/Mat2;
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat2;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat2;->x:Lcom/google/android/filament/utils/Float2;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float2;->unaryMinus()Lcom/google/android/filament/utils/Float2;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat2;->y:Lcom/google/android/filament/utils/Float2;

    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float2;->unaryMinus()Lcom/google/android/filament/utils/Float2;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-direct {v0, v1, p0}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method
