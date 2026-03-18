.class public final Ltw/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltw/e;


# static fields
.field public static final a:Lt0/c;

.field public static final b:Ltw/k;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lt0/c;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-direct {v0, v1}, Lt0/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltw/k;->a:Lt0/c;

    .line 8
    .line 9
    new-instance v0, Ltw/k;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Ltw/k;->b:Ltw/k;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public a(FFFFLtw/d;Landroid/graphics/Path;)V
    .locals 0

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
    if-eqz p0, :cond_3

    .line 11
    .line 12
    const/4 p5, 0x1

    .line 13
    if-eq p0, p5, :cond_2

    .line 14
    .line 15
    const/4 p5, 0x2

    .line 16
    if-eq p0, p5, :cond_1

    .line 17
    .line 18
    const/4 p1, 0x3

    .line 19
    if-ne p0, p1, :cond_0

    .line 20
    .line 21
    invoke-virtual {p6, p3, p2}, Landroid/graphics/Path;->lineTo(FF)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    new-instance p0, La8/r0;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    invoke-virtual {p6, p1, p4}, Landroid/graphics/Path;->lineTo(FF)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_2
    invoke-virtual {p6, p3, p2}, Landroid/graphics/Path;->lineTo(FF)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_3
    invoke-virtual {p6, p1, p4}, Landroid/graphics/Path;->lineTo(FF)V

    .line 40
    .line 41
    .line 42
    return-void
.end method
