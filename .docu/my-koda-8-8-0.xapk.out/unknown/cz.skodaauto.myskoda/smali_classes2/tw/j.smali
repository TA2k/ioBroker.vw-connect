.class public final Ltw/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltw/e;


# static fields
.field public static final a:Ltw/j;

.field public static final b:Landroid/graphics/RectF;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ltw/j;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltw/j;->a:Ltw/j;

    .line 7
    .line 8
    new-instance v0, Landroid/graphics/RectF;

    .line 9
    .line 10
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Ltw/j;->b:Landroid/graphics/RectF;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a(FFFFLtw/d;Landroid/graphics/Path;)V
    .locals 3

    .line 1
    const-string p0, "path"

    .line 2
    .line 3
    invoke-static {p6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p5}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/high16 p5, 0x42b40000    # 90.0f

    .line 11
    .line 12
    sget-object v0, Ltw/j;->b:Landroid/graphics/RectF;

    .line 13
    .line 14
    const/4 v1, 0x2

    .line 15
    if-eqz p0, :cond_3

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq p0, v2, :cond_2

    .line 19
    .line 20
    if-eq p0, v1, :cond_1

    .line 21
    .line 22
    const/4 v2, 0x3

    .line 23
    if-ne p0, v2, :cond_0

    .line 24
    .line 25
    int-to-float p0, v1

    .line 26
    mul-float/2addr p4, p0

    .line 27
    sub-float/2addr p4, p2

    .line 28
    mul-float/2addr p1, p0

    .line 29
    sub-float/2addr p1, p3

    .line 30
    invoke-virtual {v0, p3, p4, p1, p2}, Landroid/graphics/RectF;->set(FFFF)V

    .line 31
    .line 32
    .line 33
    move p0, p5

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    new-instance p0, La8/r0;

    .line 36
    .line 37
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :cond_1
    int-to-float p0, v1

    .line 42
    mul-float/2addr p3, p0

    .line 43
    sub-float/2addr p3, p1

    .line 44
    mul-float/2addr p2, p0

    .line 45
    sub-float/2addr p2, p4

    .line 46
    invoke-virtual {v0, p3, p2, p1, p4}, Landroid/graphics/RectF;->set(FFFF)V

    .line 47
    .line 48
    .line 49
    const/4 p0, 0x0

    .line 50
    goto :goto_0

    .line 51
    :cond_2
    int-to-float p0, v1

    .line 52
    mul-float/2addr p1, p0

    .line 53
    sub-float/2addr p1, p3

    .line 54
    mul-float/2addr p4, p0

    .line 55
    sub-float/2addr p4, p2

    .line 56
    invoke-virtual {v0, p1, p2, p3, p4}, Landroid/graphics/RectF;->set(FFFF)V

    .line 57
    .line 58
    .line 59
    const/high16 p0, 0x43870000    # 270.0f

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_3
    int-to-float p0, v1

    .line 63
    mul-float/2addr p3, p0

    .line 64
    sub-float/2addr p3, p1

    .line 65
    mul-float/2addr p2, p0

    .line 66
    sub-float/2addr p2, p4

    .line 67
    invoke-virtual {v0, p1, p4, p3, p2}, Landroid/graphics/RectF;->set(FFFF)V

    .line 68
    .line 69
    .line 70
    const/high16 p0, 0x43340000    # 180.0f

    .line 71
    .line 72
    :goto_0
    invoke-virtual {p6, v0, p0, p5}, Landroid/graphics/Path;->arcTo(Landroid/graphics/RectF;FF)V

    .line 73
    .line 74
    .line 75
    return-void
.end method
