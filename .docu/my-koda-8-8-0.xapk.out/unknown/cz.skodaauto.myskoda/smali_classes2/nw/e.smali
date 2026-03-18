.class public final Lnw/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lnw/i;

.field public final b:Lnw/h;

.field public final c:Lnw/a;

.field public final d:Landroid/graphics/Paint;


# direct methods
.method public constructor <init>(Lnw/i;Lnw/h;Landroid/graphics/Paint$Cap;Lnw/a;Lmw/e;)V
    .locals 1

    .line 1
    sget-object v0, Lpw/i;->d:Lpw/i;

    .line 2
    .line 3
    const-string v0, "cap"

    .line 4
    .line 5
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "pointConnector"

    .line 9
    .line 10
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string v0, "dataLabelValueFormatter"

    .line 14
    .line 15
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lnw/e;->a:Lnw/i;

    .line 22
    .line 23
    iput-object p2, p0, Lnw/e;->b:Lnw/h;

    .line 24
    .line 25
    iput-object p4, p0, Lnw/e;->c:Lnw/a;

    .line 26
    .line 27
    new-instance p1, Landroid/graphics/Paint;

    .line 28
    .line 29
    const/4 p2, 0x1

    .line 30
    invoke-direct {p1, p2}, Landroid/graphics/Paint;-><init>(I)V

    .line 31
    .line 32
    .line 33
    sget-object p2, Landroid/graphics/Paint$Style;->STROKE:Landroid/graphics/Paint$Style;

    .line 34
    .line 35
    invoke-virtual {p1, p2}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p1, p3}, Landroid/graphics/Paint;->setStrokeCap(Landroid/graphics/Paint$Cap;)V

    .line 39
    .line 40
    .line 41
    iput-object p1, p0, Lnw/e;->d:Landroid/graphics/Paint;

    .line 42
    .line 43
    return-void
.end method
